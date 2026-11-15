# This file is Copyright 2026 Michael Külper and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
#
"""Finds QEMU (and other KVM) virtual machines in a Linux host memory image.

A QEMU guest's RAM is an anonymous or shared mapping of the QEMU process. The plugin finds it by the firmware tables
that every x86 PC guest has in low memory, so a renamed QEMU binary is found too. It rebuilds the guest-physical
address space from the machine's memory map and can write it as an ELF core whose PT_LOAD segments carry
guest-physical addresses. Volatility opens that file directly, so every plugin runs on the guest.
"""

import bisect
import datetime
import functools
import logging
from typing import Dict, Iterator, List, NamedTuple, Optional, Tuple

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import pslist
from volatility3.plugins import qemu_cmdline, qemu_common

vollog = logging.getLogger(__name__)

# The largest argument area (mm->arg_start .. arg_end) that is read as a command line.
MAX_ARGV_SIZE = 0x10000

COLUMNS = [
    ("PID", int),
    ("COMM", str),
    ("PPID", int),
    ("UID", int),
    ("Started", datetime.datetime),
    ("Executable", str),
    ("Accel", str),
    ("vCPUs", int),
] + qemu_common.VM_COLUMNS


def _flags_int(flags: interfaces.objects.ObjectInterface) -> int:
    """A page or folio flags word as an integer.

    From Linux 6.18 `page.flags` is a struct (`memdesc_flags_t`) whose member `f` holds the bits; before that it is an
    integer, which has no member `f`.
    """
    return int(getattr(flags, "f", flags))


def _page_index(page: interfaces.objects.ObjectInterface) -> int:
    """The offset of a page-cache `struct page` in its file, in pages.

    Linux 6.16 renamed `page.index` to `__folio_index`. The double underscore would be mangled inside a class, so the
    name is fetched with `getattr`.
    """
    name = "__folio_index" if page.has_member("__folio_index") else "index"
    return int(getattr(page, name))


# Linux x86-64 (4.19 and later) writes a swap entry into a non-present PTE: the swap area (the "type") in bits 59-63
# and the inverted offset below. The highest types are not swap areas but migration, hardware poison, device and PTE
# marker entries. MAX_SWAPFILES is 32 minus those, and at least 23 with all of them configured.
PTE_PROTNONE = 1 << 8  # _PAGE_PROTNONE: a PROT_NONE mapping
PTE_SWAP_TYPE_SHIFT = 59
MIN_MAX_SWAPFILES = 23

# Superblock magics of hugetlbfs and tmpfs, which backs memfd (include/uapi/linux/magic.h)
HUGETLBFS_MAGIC = 0x958458F6
TMPFS_MAGIC = 0x01021994
# Why a page of a file mapping that is neither in the page tables nor in the page cache may still exist
NOT_CACHED = "not in the page cache (may be swapped or on disk)"


def linux_pte_reason(entry: int, bits: int) -> Optional[str]:
    """Why a page is missing, from a Linux x86-64 page table entry of the host process.

    Args:
        entry: The page table entry
        bits: The address bits it covers (12 for a PTE)

    Returns:
        The reason, or None if the entry is nothing Linux-specific (see `RamBlock._reason`)
    """
    if (
        entry & PTE_PROTNONE and not entry & 1
    ):  # PROT_NONE: the walk treats it as present, but the frame is not in the image
        return "page table not in the image" if bits > 12 else qemu_common.FRAME_MISSING
    if entry and not entry & 1 and bits <= 12:
        if entry >> PTE_SWAP_TYPE_SHIFT < MIN_MAX_SWAPFILES:
            return "swapped out"
        return "not present (migration, poison or marker entry)"
    return None


class LinuxRamBlock(qemu_common.RamBlock):
    """A RAM block that is a mapping (VMA) of the QEMU process.

    Plain `-m` RAM is an anonymous mapping. With memory-backend-memfd or -file (libvirt, Proxmox, hugepages) it is a
    shared file mapping. A page missing from QEMU's page tables may then still be in the file's page cache, which is
    the fallback source. `file_backed` tells whether there is one.
    """

    def __init__(self, context, layer_name: str, vma, backing: str):
        start = int(vma.vm_start)
        self.file_backed = bool(vma.vm_file)
        super().__init__(
            context.layers[layer_name],
            start,
            int(vma.vm_end) - start,
            backing,
            self.cached_page if self.file_backed else None,
        )
        self.vma = vma
        self._context = context
        self._pgoff = 0
        # file page index -> offset of its `struct page`; filled by `load_page_cache` for ordinary pages
        self._cache: Optional[Dict[int, int]] = None
        # First file page index of a large folio -> (offset of its head `struct page`, pages in it). Only the head of
        # a large folio is in the page cache tree. `_large_starts` is the sorted list of those indexes.
        self._large: Dict[int, Tuple[int, int]] = {}
        self._large_starts: List[int] = []
        self._page_type = self._page_layer = ""
        # The bit of PG_head in `page.flags`, read once from the kernel's pageflags enumeration; -1: not read yet.
        self._head_bit: Optional[int] = -1

    def _reason(self, entry: int, bits: int) -> str:
        reason = linux_pte_reason(entry, bits) or super()._reason(entry, bits)
        if reason == "never present" and self.file_backed:
            return self.uncached_reason or reason
        return reason

    @functools.cached_property
    def uncached_reason(self) -> Optional[str]:
        """Why a page of the file behind the mapping that is neither in the page tables nor in the page cache may exist
        elsewhere (`NOT_CACHED`); None if it was never written, so that the guest's page is zeros.

        That holds for hugetlbfs (no swap) and for a tmpfs or memfd file whose `shmem_inode_info.swapped` is 0. A
        swapped-out shmem page leaves a value entry in the page cache that the walk skips, so with `swapped` above 0
        the page may be there. A page of any other file may be on disk only. A file system or a field that cannot be
        read counts as unknown, which is not zeros.
        """
        if not self.file_backed:
            return None
        try:
            inode = self.vma.vm_file.get_inode()
            magic = int(inode.i_sb.s_magic)
            if magic == HUGETLBFS_MAGIC:
                return None
            if magic == TMPFS_MAGIC:
                kernel = linux.LinuxUtilities.get_module_from_volobj_type(
                    self._context, inode
                )
                # the kernel's SHMEM_I(): the inode is the member `vfs_inode` of a `shmem_inode_info`
                info = linux.LinuxUtilities.container_of(
                    int(inode.vol.offset), "shmem_inode_info", "vfs_inode", kernel
                )
                if info is not None and int(info.swapped) == 0:
                    return None
        except (
            AttributeError,
            KeyError,
            ValueError,
            TypeError,
            exceptions.VolatilityException,
        ) as excp:
            vollog.debug(f"RAM block {self.start:#x}: file system unknown: {excp}")
        return NOT_CACHED

    @functools.cached_property
    def inode_address(self) -> Optional[int]:
        """The address of the inode behind the mapping, or None if anonymous. Mappings of the same file share it."""
        if not self.file_backed:
            return None
        try:
            inode = self.vma.vm_file.get_inode()
            return int(inode.vol.offset) if inode else None
        except (AttributeError, exceptions.InvalidAddressException):
            return None

    def _folio_order(self, page: interfaces.objects.ObjectInterface) -> int:
        """The order of the large folio whose head is the page-cache entry `page`; 0 for an ordinary page or an unknown
        layout.

        The order lives where the kernel version keeps it: `page[1].compound_order` before Linux 6.1,
        `folio->_folio_order` from 6.1, and the low byte of `folio->_flags_1` after that field was dropped (6.8 or 6.9).
        A page that is not a compound head has no order, and the first tail page's fields belong to another page, so the
        head flag is tested first.
        """
        try:
            if self._head_bit == -1:
                self._head_bit = getattr(page, "pageflags_enum", {}).get("PG_head")
            if (
                self._head_bit is None
                or not _flags_int(page.flags) >> self._head_bit & 1
            ):
                return 0
            context, vol = self._context, page.vol
            folio_type = vol.type_name.rpartition(constants.BANG)[0] + (
                constants.BANG + "folio"
            )
            if context.symbol_space.has_type(folio_type):
                folio = context.object(
                    folio_type, layer_name=vol.layer_name, offset=vol.offset
                )
                if folio.has_member("_folio_order"):
                    return int(folio._folio_order)
                if folio.has_member("_flags_1"):
                    return _flags_int(folio._flags_1) & 0xFF
            if page.has_member("compound_order"):
                tail = context.object(
                    vol.type_name,
                    layer_name=vol.layer_name,
                    offset=vol.offset
                    + context.symbol_space.get_type(vol.type_name).size,
                )
                return int(tail.compound_order)
        except (
            AttributeError,
            KeyError,
            TypeError,
            exceptions.VolatilityException,
        ) as excp:
            vollog.debug(f"folio order of the page at {page.vol.offset:#x}: {excp}")
            return 0
        vollog.debug(
            f"no folio order in this kernel's layout (page at {page.vol.offset:#x}): kept as one page"
        )
        return 0

    def _hugetlb_index_in_huge_pages(
        self, inode: interfaces.objects.ObjectInterface
    ) -> bool:
        """Whether the page cache index of this hugetlbfs inode counts huge pages instead of pages.

        Linux 6.7 changed the index to base pages and removed `hugetlb_basepage_index`. Before Linux 5.13 (v5.12
        still has `__basepage_index` in mm/hugetlb.c, v5.13 has `hugetlb_basepage_index`) the same function is named
        `__basepage_index`, so either symbol marks a kernel with huge-page indexes. The same rule is used in the fix
        proposed for `inode.get_contents` in volatility3.
        """
        try:
            # hugetlbfs superblock and a kernel that still has hugetlb_basepage_index (or __basepage_index before 5.13)
            if int(inode.i_sb.s_magic) != HUGETLBFS_MAGIC:
                return False
            kernel = linux.LinuxUtilities.get_module_from_volobj_type(
                self._context, inode
            )
            return any(
                kernel.has_symbol(name)
                for name in ("hugetlb_basepage_index", "__basepage_index")
            )
        except (AttributeError, ValueError, TypeError, exceptions.VolatilityException):
            return False

    def load_page_cache(self) -> None:
        """Reads which pages of the file behind the mapping are in its page cache; once, and nothing if anonymous.

        `inode.get_pages` finds the kernel by the module name "kernel", so this must run while that name is the kernel
        the mapping belongs to. A page cache that cannot be walked to its end, for example in a damaged image, is kept
        as far as it was read, with a warning.

        Only the head of a large folio (a transparent huge page of shmem, a hugetlbfs page) is in the page cache tree,
        so its pages are added from the head using its order. Before Linux 6.7 a hugetlbfs page is stored at its index
        counted in huge pages, not base pages; the indexes are then scaled (see `_hugetlb_index_in_huge_pages`).
        """
        if self._cache is not None or not self.file_backed:
            return
        self._pgoff = int(self.vma.vm_pgoff)
        cache: Dict[int, int] = {}
        large: Dict[int, Tuple[int, int]] = {}
        inode = None
        try:
            inode = self.vma.vm_file.get_inode()
            for page in inode.get_pages() if inode else ():
                if page.mapping != inode.i_mapping:
                    vollog.debug(
                        f"Cached page at {int(page.vol.offset):#x} belongs to another address space than its inode"
                    )
                    continue
                order = self._folio_order(page)
                if order:
                    large[_page_index(page)] = (int(page.vol.offset), 1 << order)
                else:
                    cache[_page_index(page)] = int(page.vol.offset)
                self._page_type, self._page_layer = (
                    page.vol.type_name,
                    page.vol.layer_name,
                )
        except (
            exceptions.LinuxPageCacheException,
            exceptions.InvalidAddressException,
        ) as excp:
            # The page cache is a generator, so the pages before the invalid one are kept.
            vollog.warning(
                f"RAM block {self.start:#x} ({self.backing}): the page cache of its file is incomplete "
                f"({len(cache) + len(large)} pages read): {excp}"
            )
        if large and self._hugetlb_index_in_huge_pages(inode):
            vollog.debug(f"RAM block {self.start:#x}: hugetlbfs index in huge pages")
            large = {
                index * pages: (address, pages)
                for index, (address, pages) in large.items()
            }
        self._large = large
        self._large_starts = sorted(large)
        self._cache = cache

    def _large_folio_page(self, index: int) -> Optional[int]:
        """The `struct page` offset for file page `index` if a large folio holds it, else None."""
        position = bisect.bisect_right(self._large_starts, index) - 1
        if position < 0:
            return None
        start = self._large_starts[position]
        address, pages = self._large[start]
        if index >= start + pages:
            return None
        size = self._context.symbol_space.get_type(self._page_type).size
        return address + (index - start) * size

    def cached_page(self, offset: int) -> Optional[interfaces.objects.ObjectInterface]:
        """The page-cache `struct page` of the file behind this mapping, or None.

        None if the mapping is anonymous or the page is not cached.

        Args:
            offset: The offset in the block (a multiple of the page size)
        """
        if not self.file_backed:
            return None
        self.load_page_cache()
        index = self._pgoff + offset // qemu_common.PAGE
        address = self._cache.get(index)
        if address is None and self._large_starts:
            address = self._large_folio_page(index)
        if address is None:
            return None
        return self._context.object(
            self._page_type, layer_name=self._page_layer, offset=address
        )


class _Vmm(NamedTuple):
    """What `VMs.find_vms` reads of one process."""

    files: List[str]  # names of its KVM files
    argv: List[str]
    vmas: List  # all mappings
    rw_vmas: List  # the read-write ones
    blocks: List[LinuxRamBlock]  # the read-write ones large enough to be guest RAM

    @property
    def has_kvm(self) -> bool:
        """Whether the process holds a VM file."""
        return "kvm-vm" in self.files


class _Found(NamedTuple):
    """A row of `VMs.find_vms` before processes that only share another one's guest RAM are dropped."""

    task: interfaces.objects.ObjectInterface
    guest: Optional[qemu_common.GuestVM]
    info: qemu_common.VmmInfo
    # how sure it is that the process is a VMM: 0 to 2 (QemuCommon.vmm_signal)
    signal: int


class VMs(interfaces.plugins.PluginInterface):
    """Lists QEMU/KVM virtual machines running inside the image and dumps their guest-physical memory."""

    _required_framework_version = (2, 13, 0)
    _version = (1, 6, 1)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel", architectures=["Intel64"]
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.VersionRequirement(
                name="linuxutils", component=linux.LinuxUtilities, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="qemu_common", component=qemu_common.QemuCommon, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="qemu_cmdline",
                component=qemu_cmdline.QemuCmdline,
                version=(1, 0, 0),
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Only look at these process IDs",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Write each guest's physical memory as an ELF core (vm.<pid>.<addr>.elf)",
                default=False,
                optional=True,
            ),
        ]

    @classmethod
    def kvm_files(
        cls,
        context: interfaces.context.ContextInterface,
        symbol_table: str,
        task: interfaces.objects.ObjectInterface,
    ) -> Iterator[Tuple[str, interfaces.objects.ObjectInterface]]:
        """The KVM files a process holds: anonymous inodes named kvm-vm and kvm-vcpu:N, and kvm-gmem for guest_memfd.

        guest_memfd (Linux 6.8+) holds the private memory of SEV-SNP and TDX guests, which the VMM does not map.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            symbol_table: The name of the kernel's symbol table
            task: The process
        """
        for _fd, filp, _path in linux.LinuxUtilities.files_descriptors_for_process(
            context, symbol_table, task
        ):
            try:
                name = filp.get_dentry().d_name.name_as_str()
            except exceptions.InvalidAddressException:
                continue
            if "kvm" in name:
                yield name, filp

    @classmethod
    def owner_values(
        cls,
        context: interfaces.context.ContextInterface,
        task: interfaces.objects.ObjectInterface,
    ) -> Dict[str, object]:
        """Who started the VMM, when and from which file: the PPID, UID, Started and Executable columns.

        The values are by column name, and N/A where the kernel does not say. The executable keeps the kernel's "
        (deleted)" suffix if the VMM binary was removed after the start.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            task: The VMM process
        """
        fields = pslist.PsList.get_task_fields(task)
        try:
            exe = task.mm.exe_file
            path = linux.LinuxUtilities.path_for_file(context, task, exe) if exe else ""
        except (AttributeError, exceptions.InvalidAddressException):
            path = ""
        values = {"PPID": int(fields.user_ppid)}
        if path:
            values["Executable"] = path
        if fields.uid is not None:
            values["UID"] = int(fields.uid)
        if fields.creation_time is not None:
            values["Started"] = fields.creation_time
        return values

    @classmethod
    def read_argv(
        cls,
        context: interfaces.context.ContextInterface,
        task: interfaces.objects.ObjectInterface,
        layer_name: str,
    ) -> List[str]:
        """The command line of a process from its argument area (mm->arg_start .. arg_end); empty if unreadable or too
        large.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            task: The process
            layer_name: The name of the process's layer
        """
        try:
            size = task.mm.arg_end - task.mm.arg_start
            if not 0 < size <= MAX_ARGV_SIZE:
                return []
            raw = context.layers[layer_name].read(task.mm.arg_start, size)
        except exceptions.InvalidAddressException:
            return []
        return [
            a.decode("utf-8", "replace") for a in raw.rstrip(b"\x00").split(b"\x00")
        ]

    @classmethod
    def confidential_label(
        cls, argv: List[str], file_names: List[str]
    ) -> Optional[str]:
        """What makes this a confidential guest, or None.

        That is the command line's 'SEV', 'SEV-ES', 'SEV-SNP' or 'TDX', else 'guest_memfd' if it holds guest_memfd
        files.

        Args:
            argv: The VMM's command line
            file_names: The names of the KVM files it holds (see `kvm_files`)
        """
        gmem = any("kvm-gmem" in name for name in file_names)
        return qemu_cmdline.QemuCmdline.confidential(argv) or (
            "guest_memfd" if gmem else None
        )

    @classmethod
    def _ram_blocks(
        cls, context, task, layer_name: str, rw_vmas: List
    ) -> List[LinuxRamBlock]:
        """The read-write mappings (anonymous or shared file) large enough to be guest RAM."""
        return [
            LinuxRamBlock(
                context,
                layer_name,
                vma,
                (vma.get_name(context, task) or "file").strip()
                if vma.vm_file
                else "anonymous",
            )
            for vma in rw_vmas
            if int(vma.vm_end) - int(vma.vm_start) >= qemu_common.MIN_RAM
        ]

    @classmethod
    def _mapped_files(cls, vmas: List) -> Iterator[str]:
        """The files that VMAs map, each once, as 'directory/name'.

        Reading only the last directory is cheaper than the whole path and enough to recognise a library. The libraries
        reveal a renamed QEMU.
        """
        seen = set()
        for vma in vmas:
            try:
                if not vma.vm_file or int(vma.vm_file) in seen:
                    continue
                seen.add(int(vma.vm_file))
                dentry = vma.vm_file.get_dentry()
                name = dentry.d_name.name_as_str()
                parent = dentry.d_parent.dereference().d_name.name_as_str()
            except exceptions.InvalidAddressException:
                continue
            yield f"{parent}/{name}"

    @classmethod
    def _heap_ranges(cls, rw_vmas: List) -> Iterator[Tuple[int, int]]:
        """The anonymous read-write mappings small enough to be a heap, where QEMU's RAMBlock records live."""
        for vma in rw_vmas:
            start, end = int(vma.vm_start), int(vma.vm_end)
            if not vma.vm_file and end - start <= qemu_common.HEAP_MAX:
                yield start, end

    @classmethod
    def _read_vmm(
        cls,
        context: interfaces.context.ContextInterface,
        symbol_table: str,
        task: interfaces.objects.ObjectInterface,
        layer_name: str,
    ) -> "_Vmm":
        """What `find_vms` reads of a process: its KVM files, command line, mappings and candidate RAM blocks."""
        files = [name for name, _filp in cls.kvm_files(context, symbol_table, task)]
        argv = cls.read_argv(context, task, layer_name)
        vmas = list(qemu_common.QemuCommon.vmas(task.mm))
        rw_vmas = [vma for vma in vmas if vma.get_protection()[:2] == "rw"]
        blocks = cls._ram_blocks(context, task, layer_name, rw_vmas)
        return _Vmm(files, argv, vmas, rw_vmas, blocks)

    @classmethod
    def _find_task_guests(
        cls, task: interfaces.objects.ObjectInterface, vmm: "_Vmm"
    ) -> Optional[Tuple[List[qemu_common.GuestVM], Optional[qemu_common.GuestVM], int]]:
        """(guests, unplaced guest, VMM signal) of a process, or None if it is neither a VMM nor a KVM user."""
        guests, unplaced, signal = qemu_common.QemuCommon.detect_guests(
            int(task.pid),
            vmm.blocks,
            vmm.argv,
            functools.partial(cls._mapped_files, vmm.vmas),
            functools.partial(cls._heap_ranges, vmm.rw_vmas),
            vmm.has_kvm,
        )
        if not guests and not vmm.has_kvm and signal < 2:
            return None
        return guests, unplaced, signal

    @classmethod
    def _vmm_info(cls, vmm: "_Vmm") -> qemu_common.VmmInfo:
        """The VMM columns: accelerator, vCPU count and command line."""
        # A set, because Firecracker holds two fds per vCPU.
        vcpus = {n for n in vmm.files if n.startswith("kvm-vcpu:")}
        return qemu_common.VmmInfo(
            # Without a KVM file, QEMU runs the guest in its own emulator (TCG).
            accel="KVM" if vmm.has_kvm else "TCG",
            vcpus=len(vcpus) if vmm.has_kvm else renderers.NotAvailableValue(),
            argv=vmm.argv,
        )

    @classmethod
    def _confidential_guest(
        cls, task: interfaces.objects.ObjectInterface, vmm: "_Vmm", label: str
    ) -> Optional[qemu_common.GuestVM]:
        """The RAM of a confidential guest, listed but never dumped (the key is in the CPU), or None if unknown."""
        block = qemu_common.QemuCommon.encrypted_block(vmm.blocks, vmm.argv)
        if not block:
            return None
        return qemu_common.GuestVM(
            int(task.pid),
            qemu_common.GuestRam([block]),
            [],
            qemu_cmdline.QemuCmdline.machine_type(vmm.argv),
            encrypted=label,
        )

    @classmethod
    def find_vms(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        pids: Optional[List[int]] = None,
    ) -> Iterator[
        Tuple[
            interfaces.objects.ObjectInterface,
            Optional[qemu_common.GuestVM],
            qemu_common.VmmInfo,
        ]
    ]:
        """Every process that holds a PC guest's RAM or a KVM VM file.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the host kernel module
            pids: Only these process IDs (all if None or empty)

        Yields:
            (task, guest, info). The guest is None for a KVM user without PC firmware tables (a microVM, see linux.kvm),
            for a VMM whose RSDP was not found, and for a confidential guest whose RAM block is unknown. A process that
            only shares another one's guest RAM (see `_without_shared_ram`) is not listed.
        """
        symbol_table = context.modules[kernel_module_name].symbol_table_name
        filter_func = pslist.PsList.create_pid_filter(pids)
        tasks = list(
            pslist.PsList.list_tasks(
                context, kernel_module_name, filter_func=filter_func
            )
        )
        if not tasks and not pids:
            # A VM host image holds the guests' kernels too. If their symbol tables are in the symbol path, automagic
            # can lock onto a guest kernel (by its VMCOREINFO or banner) instead of the host's.
            vollog.warning(
                "No processes found: the kernel was probably not identified correctly. If this image is a VM "
                "host, it also contains guest kernels; run with a symbol directory that holds only the host's "
                "symbol table (banners.Banners lists every kernel in the image)."
            )
        found_vms: List[_Found] = []
        for task in tasks:
            if not task.mm:
                continue
            layer_name = task.add_process_layer()
            if layer_name is None:
                continue
            vmm = cls._read_vmm(context, symbol_table, task, layer_name)
            found = cls._find_task_guests(task, vmm)
            if found is None:
                continue
            guests, unplaced, signal = found
            info = cls._vmm_info(vmm)
            label = cls.confidential_label(vmm.argv, vmm.files)
            if guests and label:
                vollog.warning(
                    f"PID {task.pid}: {label}, but the guest RAM is plaintext"
                )
            if not guests and label:
                found_vms.append(
                    _Found(
                        task,
                        cls._confidential_guest(task, vmm, label),
                        info._replace(encrypted=label),
                        signal,
                    )
                )
                continue
            # `unplaced` may be None: a KVM user without PC firmware tables, such as a microVM.
            for guest in guests or [unplaced]:
                found_vms.append(_Found(task, guest, info, signal))
        for found_vm in cls._without_shared_ram(found_vms):
            yield found_vm.task, found_vm.guest, found_vm.info

    @classmethod
    def _without_shared_ram(cls, found: List["_Found"]) -> List["_Found"]:
        """The rows without those of processes that only share the guest RAM of another VMM.

        virtiofsd and vhost-user backends (OVS-DPDK, DPDK vhost-user-blk) map the guest's memfd or hugetlbfs file to
        reach the virtqueues, so the firmware tables appear in their address space too. If the RAM blocks of two
        processes are the same file (same inode), the one with the weaker VMM signal (no KVM file, no QEMU command
        line) is not listed and a warning names both. Equal signals, such as two QEMU processes on one file, keep
        both rows.
        """
        by_inode: Dict[int, List[_Found]] = {}
        for row in found:
            for block in row.guest.ram.blocks if row.guest else ():
                inode = getattr(block, "inode_address", None)
                if inode is not None:
                    by_inode.setdefault(inode, []).append(row)
        dropped: Dict[int, _Found] = {}
        for rows in by_inode.values():
            strongest = max(rows, key=lambda row: row.signal)
            for row in rows:
                if row.signal < strongest.signal and id(row) not in dropped:
                    dropped[id(row)] = row
                    vollog.warning(
                        f"PID {row.task.pid} shares the guest RAM of PID {strongest.task.pid} "
                        "(vhost-user backend or virtiofsd?): not listed as a VMM of its own"
                    )
        return [row for row in found if id(row) not in dropped]

    def _generator(self):
        dump = self.config.get("dump")
        for task, vm, info in self.find_vms(
            self.context, self.config["kernel"], self.config.get("pid")
        ):
            process = {
                "PID": int(task.pid),
                "COMM": utility.array_to_string(task.comm),
            }
            yield from qemu_common.QemuCommon.vm_rows(
                COLUMNS,
                process,
                info,
                vm,
                self.open,
                dump,
                self.owner_values(self.context, task),
            )

    def run(self):
        return renderers.TreeGrid(COLUMNS, self._generator())
