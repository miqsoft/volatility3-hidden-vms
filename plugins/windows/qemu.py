# This file is Copyright 2026 Michael Külper and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
#
"""Finds QEMU virtual machines in a Windows host memory image.

QEMU for Windows allocates guest RAM with VirtualAlloc (private, PAGE_READWRITE). The plugin walks the VADs of every
process and finds the allocation with an x86 PC guest's low memory by its ACPI RSDP, so a renamed
qemu-system-x86_64.exe is found too. It joins NUMA blocks, applies the PC memory map and can write the
guest-physical memory as an ELF core that Volatility opens directly. The shared logic is in qemu_common, which
linux.qemu uses as well.
"""

import datetime
import functools
import logging
from typing import Dict, Iterator, List, Optional, Set, Tuple

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins import qemu_cmdline, qemu_common
from volatility3.plugins.windows import cmdline, pslist, vadinfo

vollog = logging.getLogger(__name__)

RW = ("PAGE_READWRITE", "PAGE_EXECUTE_READWRITE")
# Size of the kernel's paging file table (`MmPagingFile`, `_MI_VISIBLE_PARTITION.PagingFile`).
MAX_PAGING_FILES = 16
# Bits of a non-present PTE: a prototype PTE, and a transition page, which is on a list but still in memory.
PTE_PROTOTYPE = 1 << 10
PTE_TRANSITION = 1 << 11
# Flags of a software PTE on a kernel with SwizzleBit (Windows 10 and later): bits 1-4 are PageFileReserved,
# PageFileAllocated, ColdPage and SwizzleBit, and `PageFileLow` is bits 12-15.
PTE_PAGEFILE_RESERVED = 1 << 1
PTE_PAGEFILE_ALLOCATED = 1 << 2
COLUMNS = [
    ("PID", int),
    ("Process", str),
    ("PPID", int),
    ("Started", datetime.datetime),
    ("Executable", str),
    ("Accel", str),
] + qemu_common.VM_COLUMNS


class WindowsPte:
    """The page table entry formats of the host kernel that matter for a guest page that is not in the image.

    A software PTE (not valid, not transition, not prototype) holds the paging file number (`PageFileLow`) and the
    page's slot in that file (`PageFileHigh`). No slot means demand-zero. The bit positions differ between Windows
    versions: `PageFileLow` is bits 1-4 on kernels without SwizzleBit (unpatched Windows 7 and 8.1) and bits 12-15
    with it; there bits 1-4 are flags, and a PTE with only PageFileReserved set is a slot that was reserved and never
    written. The positions are read from the kernel's symbol table. Windows 10 and later keep compressed pages in a
    "virtual store", a paging file of its own (`_MMPAGING_FILE.VirtualStorePagefile`). Its number is read from the
    kernel's paging file table.
    """

    # The Windows 10 layout, used if the symbol table has no `_MMPTE_SOFTWARE`.
    DEFAULT_LOW = (12, 4)
    DEFAULT_HIGH_SHIFT = 32

    def __init__(
        self, context: interfaces.context.ContextInterface, kernel_module_name: str
    ):
        self.kernel = context.modules[kernel_module_name]
        self._swap_warned = False
        self.low_shift, self.low_width = self.DEFAULT_LOW
        self.high_shift = self.DEFAULT_HIGH_SHIFT
        try:
            members = context.symbol_space.get_type(
                self.kernel.symbol_table_name + constants.BANG + "_MMPTE_SOFTWARE"
            ).vol.members
            low, high = members["PageFileLow"][1].vol, members["PageFileHigh"][1].vol
            self.low_shift = low["start_bit"]
            self.low_width = low["end_bit"] - low["start_bit"]
            self.high_shift = high["start_bit"]
        except (exceptions.SymbolError, KeyError):
            vollog.debug(
                "_MMPTE_SOFTWARE not in the kernel's symbol table; using the Windows 10 layout"
            )

    def check_swap_layers(
        self, layer: interfaces.layers.TranslationLayerInterface
    ) -> None:
        """Warns once if page files were given (`--single-swap-locations`) on a kernel whose PTEs vol3 misreads.

        vol3 (2.28.2 and develop) takes a paged-out page's paging file number from PTE bits 1-4, but on a kernel
        with `PageFileLow` elsewhere (bits 12-15 from Windows 10 on) those bits are flags.
        """
        count = layer.config.get(
            interfaces.configuration.path_join("swap_layers", "number_of_elements"), 0
        )
        if count and self.low_shift != 1 and not self._swap_warned:
            self._swap_warned = True
            store = sorted(self.virtual_store)
            where = (
                f" The compression store is paging file {', '.join(map(str, store))} on this kernel: "
                f"a page file given in that position is read as wrong data."
                if store
                else ""
            )
            vollog.warning(
                "Volatility 3 reads a paged-out page's paging-file number from the wrong PTE bits on Windows 10 and "
                "later (fix proposed in volatility3 PR #2080): with --single-swap-locations, pages are read from the "
                "wrong file or not at all." + where
            )

    @functools.cached_property
    def virtual_store(self) -> Set[int]:
        """The numbers of the paging files that are the compression store; empty before Windows 10 or if unreadable."""
        kernel = self.kernel
        tables = []
        # Windows 10 1607 and later: `MiVisiblePartition` -> `_MI_VISIBLE_PARTITION.PagingFile`.
        try:
            visible = int(
                kernel.object(
                    object_type="pointer",
                    offset=kernel.get_symbol("MiVisiblePartition").address,
                )
            )
            partition = kernel.object(
                object_type="_MI_VISIBLE_PARTITION", offset=visible, absolute=True
            )
            tables.append(partition.PagingFile.vol.offset)
        except (
            exceptions.SymbolError,
            exceptions.InvalidAddressException,
            AttributeError,
        ):
            pass
        try:  # earlier kernels have the array `MmPagingFile`
            tables.append(kernel.offset + kernel.get_symbol("MmPagingFile").address)
        except exceptions.SymbolError:
            pass
        for table in tables:
            store, files = set(), 0
            paging_files = kernel.object(
                object_type="array",
                offset=table,
                absolute=True,
                subtype=kernel.get_type("pointer"),
                count=MAX_PAGING_FILES,
            )
            for number in range(MAX_PAGING_FILES):
                try:
                    pointer = int(paging_files[number])
                    if not pointer:
                        continue
                    paging_file = kernel.object(
                        object_type="_MMPAGING_FILE", offset=pointer, absolute=True
                    )
                    files += 1
                    if paging_file.has_member("VirtualStorePagefile") and int(
                        paging_file.VirtualStorePagefile
                    ):
                        store.add(number)
                except exceptions.InvalidAddressException:
                    continue
            if files:
                return store
        vollog.info(
            "The kernel's paging file table cannot be read: compressed store pages count as pagefile pages"
        )
        return set()

    def reason(self, entry: int, bits: int) -> Optional[str]:
        """Why a page is missing, from the Windows PTE `entry`, or None if it is nothing Windows-specific.

        `bits` is the number of address bits the entry covers: more than 12 means a page table's entry.
        """
        if entry & 1:  # valid, so the frame or the page table is not in the image
            return None
        if bits > 12:
            return "demand-zero" if entry == 0 else "page table paged out"
        if entry & PTE_PROTOTYPE:
            return "prototype"
        if entry & PTE_TRANSITION:
            return "transition (frame not in the image)"
        if entry >> self.high_shift == 0:
            return "demand-zero"
        number = (entry >> self.low_shift) & ((1 << self.low_width) - 1)
        if number in self.virtual_store:
            return "compressed store"
        # Below bit 5 the bits are flags, not the number. On a Windows Server 2025 host 41,968 of 75,804 such pages
        # were zero pages with stale slot data and 33,836 matched the file.
        if (
            self.low_shift > 4
            and entry & PTE_PAGEFILE_RESERVED
            and not entry & PTE_PAGEFILE_ALLOCATED
        ):
            return f"pagefile {number} (slot reserved, content may be stale)"
        return f"pagefile {number}"


class WindowsRamBlock(qemu_common.RamBlock):
    """A RAM block that is a private VirtualAlloc region of the QEMU process."""

    def __init__(self, layer, start: int, size: int, pte: WindowsPte):
        super().__init__(layer, start, size, "VirtualAlloc")
        self._pte = pte

    def _reason(self, entry: int, bits: int) -> str:
        return self._pte.reason(entry, bits) or super()._reason(entry, bits)


class VMs(interfaces.plugins.PluginInterface):
    """Lists QEMU virtual machines running inside a Windows image and dumps their guest-physical memory."""

    _required_framework_version = (2, 23, 0)  # windows pslist.PsList 3.0.0
    _version = (1, 4, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="vadinfo", component=vadinfo.VadInfo, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="cmdline", component=cmdline.CmdLine, version=(1, 0, 0)
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
    def owner_values(
        cls, proc: interfaces.objects.ObjectInterface
    ) -> Dict[str, object]:
        """Who started the VMM, when and from which file: the PPID, Started and Executable columns.

        Args:
            proc: The VMM process (`_EPROCESS`)

        Returns:
            The values by column name; one that cannot be read is left out (N/A). The executable is the image path
            from the PEB's process parameters.
        """
        values: Dict[str, object] = {}
        try:
            values["PPID"] = int(proc.InheritedFromUniqueProcessId)
            started = proc.get_create_time()
            if isinstance(started, datetime.datetime):
                values["Started"] = started
            path = proc.get_peb().ProcessParameters.ImagePathName.get_string()
            if path:
                values["Executable"] = path
        except exceptions.InvalidAddressException:
            pass
        return values

    @classmethod
    def _argv(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        proc: interfaces.objects.ObjectInterface,
    ) -> List[str]:
        """The command line of a process, from its PEB, split into arguments."""
        kernel = context.modules[kernel_module_name]
        try:
            line = cmdline.CmdLine.get_cmdline(context, kernel.symbol_table_name, proc)
        except exceptions.InvalidAddressException:
            return []
        return qemu_cmdline.QemuCmdline.split_command_line(line or "")

    @classmethod
    def _rw_private_vads(cls, proc, protect_values) -> Iterator[Tuple[int, int]]:
        """(start, size) of the private read-write VADs: VirtualAlloc'd memory such as QEMU's guest RAM and heaps."""
        for vad in vadinfo.VadInfo.list_vads(proc):
            try:
                if not vad.get_private_memory():
                    continue
                if (
                    vad.get_protection(protect_values, vadinfo.winnt_protections)
                    not in RW
                ):
                    continue
                start, end = int(vad.get_start()), int(vad.get_end())
            except exceptions.InvalidAddressException:
                continue
            yield start, end + 1 - start

    @classmethod
    def _mapped_files(cls, proc) -> Iterator[str]:
        """The names of the files a process maps (its image and DLLs). The libraries reveal a renamed QEMU."""
        for vad in vadinfo.VadInfo.list_vads(proc):
            try:
                if vad.get_private_memory():
                    continue
                name = vad.get_file_name()
            except exceptions.InvalidAddressException:
                continue
            if isinstance(name, str) and name:
                yield name

    @classmethod
    def _vmm_info(cls, argv: List[str]) -> qemu_common.VmmInfo:
        """The VMM columns: accelerator and command line. The vCPU count is not known on Windows."""
        return qemu_common.VmmInfo(
            # TCG is QEMU's default accelerator.
            accel=(qemu_cmdline.QemuCmdline.accelerator(argv) or "tcg").upper(),
            vcpus=renderers.NotAvailableValue(),
            argv=argv,
        )

    @classmethod
    def _process_guests(
        cls,
        proc: interfaces.objects.ObjectInterface,
        blocks: List[WindowsRamBlock],
        heaps: List[Tuple[int, int]],
        argv: List[str],
    ) -> List[Optional[qemu_common.GuestVM]]:
        """The guests whose RAM a process holds.

        For a process that is certainly a VMM (by command line or DLLs) whose RSDP was not found, the guest placed
        from its command line alone, if there is one.
        """
        pid = int(proc.UniqueProcessId)
        guests, unplaced, signal = qemu_common.QemuCommon.detect_guests(
            pid,
            blocks,
            argv,
            functools.partial(cls._mapped_files, proc),
            functools.partial(iter, heaps),
        )
        return guests if guests or signal < 2 else [unplaced]

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
        """Every x86 PC guest whose RAM a process holds, and every VMM process whose guest was not found.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the Windows kernel module
            pids: Only these process IDs (all if None or empty)

        Yields:
            (process, guest, info), one per guest; the guest is None for a VMM whose RSDP was not found
        """
        kernel = context.modules[kernel_module_name]
        protect_values = vadinfo.VadInfo.protect_values(
            context, kernel.layer_name, kernel.symbol_table_name
        )
        pte = WindowsPte(context, kernel_module_name)
        filter_func = pslist.PsList.create_pid_filter(pids)
        for proc in pslist.PsList.list_processes(
            context, kernel_module_name, filter_func=filter_func
        ):
            try:
                layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException:
                continue
            if layer_name is None:
                continue
            layer = context.layers[layer_name]
            pte.check_swap_layers(layer)
            vads = list(cls._rw_private_vads(proc, protect_values))
            blocks = [
                WindowsRamBlock(layer, start, size, pte)
                for start, size in vads
                if size >= qemu_common.MIN_RAM
            ]
            if not blocks:
                continue
            argv = cls._argv(context, kernel_module_name, proc)
            heaps = [
                (start, start + size)
                for start, size in vads
                if size <= qemu_common.HEAP_MAX
            ]
            info = cls._vmm_info(argv)
            for guest in cls._process_guests(proc, blocks, heaps, argv):
                yield proc, guest, info

    def _generator(self):
        dump = self.config.get("dump")
        for proc, vm, info in self.find_vms(
            self.context, self.config["kernel"], self.config.get("pid")
        ):
            process = {
                "PID": int(proc.UniqueProcessId),
                "Process": utility.array_to_string(proc.ImageFileName),
            }
            yield from qemu_common.QemuCommon.vm_rows(
                COLUMNS, process, info, vm, self.open, dump, self.owner_values(proc)
            )

    def run(self):
        return renderers.TreeGrid(COLUMNS, self._generator())
