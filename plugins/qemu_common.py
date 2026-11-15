# This file is Copyright 2026 Michael Külper and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
#
"""OS-independent part of finding QEMU guests in a host memory image (used by linux.qemu and windows.qemu).

A QEMU guest's RAM is one or more large read-write allocations of the QEMU process. The guest is found by the ACPI
RSDP that its firmware leaves in low guest memory. The RAM blocks are joined in NUMA node order and mapped to
guest-physical addresses with the PC memory map of the machine type. The result can be written as an ELF core.

`QemuCommon` is the versioned interface: the plugins call its classmethods, and its version covers the whole module.
The command line is read by `qemu_cmdline.QemuCmdline`, the guest's ACPI tables by `qemu_acpi.QemuAcpi`.
"""

import collections
import logging
import re
import struct
from typing import (
    Callable,
    ContextManager,
    Counter,
    Dict,
    Iterable,
    Iterator,
    List,
    NamedTuple,
    Optional,
    Set,
    Tuple,
)

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins import qemu_acpi, qemu_cmdline

vollog = logging.getLogger(__name__)

PAGE = 0x1000
MIN_RAM = 16 * 1024 * 1024  # smaller allocations are not guest RAM
HEAP_MAX = 256 << 20  # larger allocations are guest RAM, not heap
SCAN_CHUNK = 1 << 20  # bytes of guest RAM read at a time when scanning or dumping
# QEMU's `RAMBlock` record (include/exec/ramblock.h) starts with `host`, the block's start address. `used_length`
# (the block size) follows within RAMBLOCK_USED_LENGTH bytes. The id string `idstr` follows 52 bytes after `host`
# (RAMBLOCK_IDSTR); RAMBLOCK_RECORD bytes are read for it. Device regions have a PCI path or ROM name as id.
RAMBLOCK_USED_LENGTH = (8, 64)
RAMBLOCK_RECORD = 0x100
RAMBLOCK_IDSTR = 52
RAMBLOCK_ID = re.compile(rb"([A-Za-z0-9_./:@+-]{2,127})\x00")
RAMBLOCK_DEVICE = re.compile(r"/|vram|\.rom$|\.bios$|^pc\.(bios|rom)|pflash")
VGA_HOLE = (0xA0000, 0xC0000)
GIB = 1 << 30
# Where QEMU's PC machine types end the RAM below 4 GiB (hw/i386/pc_piix.c, pc_q35.c). RAM smaller than `*_FULL` is
# mapped whole below 4 GiB. Larger RAM is split: `*_SPLIT` bytes go below 4 GiB, the rest above.
# The `pc` limit is `qemu_acpi.PC_LOW_RAM_MAX` (0xE0000000, the highest of both machine types), defined only there.
Q35_LOWMEM_SPLIT, Q35_LOWMEM_FULL = 0x80000000, 0xB0000000
PC_LOWMEM_SPLIT = 0xC0000000
# A Linux banner. The length bound skips format strings such as "Linux version %s".
LINUX_BANNER = re.compile(rb"Linux version \d[ -~]{40,400}")
# A complete banner has a build number after the toolchain part. Since Linux 6.1 a second, weak `linux_banner` from
# init/version.c ends in `) # SMP ` without number and date.
LINUX_BANNER_BUILD = re.compile(r"\) #\d")
# The other banners of the same kernel image are looked for this far after the first one.
BANNER_WINDOW = 64 << 20
# The CodeView record (RSDS, GUID, age, PDB name) in the debug directory of the NT kernel image.
NT_MP_KERNELS = (b"ntkrnlmp.pdb", b"ntkrpamp.pdb")
NT_RSDS = re.compile(
    rb"RSDS([\s\S]{16})([\s\S]{4})(ntkrnlmp\.pdb|ntoskrnl\.pdb|ntkrnlpa\.pdb|ntkrpamp\.pdb)\x00"
)
# Libraries (lower-case file name start, Linux .so and Windows .dll alike) that mark a process as QEMU: the Windows
# hypervisor platform (WHPX) and libraries that QEMU uses and few other programs do. glib and pixman together are a
# weak marker, unless cairo is mapped too: desktop programs load that pair through cairo and GTK.
QEMU_STRONG_LIBRARIES = (
    "winhvplatform",
    "winhvemulation",
    "libslirp",
    "libfdt",
    "libvirglrenderer",
    "libspice-server",
    "libusbredirparser",
)
QEMU_COMMON_LIBRARIES = ("libpixman-1", "libglib-2.0")
DESKTOP_LIBRARY = "libcairo"
# pages that only the page cache of a file has
RAM_RECOVERED = "read from the page cache"
# a present page table entry whose frame the host image lacks
FRAME_MISSING = "frame not in the image"


class Segment(NamedTuple):
    guest_phys: int  # guest-physical address
    ram_offset: int  # offset into the guest's flat RAM (all blocks back to back)
    length: int


# --- RAM blocks ------------------------------------------------------------------------------------


class RamBlock:
    """One RAM allocation of the QEMU process, read through the process layer.

    `fallback(offset)` may supply a page that the process layer cannot translate (Linux: the page cache `struct page`
    of a shared file backend). Pages that neither has read as zeros.
    """

    def __init__(
        self,
        layer: interfaces.layers.DataLayerInterface,
        start: int,
        size: int,
        backing: str,
        fallback: Optional[
            Callable[[int], Optional[interfaces.objects.ObjectInterface]]
        ] = None,
    ):
        self.layer, self.start, self.size, self.backing = layer, start, size, backing
        self._fallback = fallback

    @property
    def has_fallback(self) -> bool:
        """Whether the block has a fallback source for the pages that the process layer does not translate."""
        return self._fallback is not None

    def _holes(self, offset: int, length: int) -> Iterator[int]:
        """Offsets in the block of the pages in a page-aligned range that the process layer does not translate."""
        cursor = self.start + offset
        for addr, size, _mapped, _msize, _layer in self.layer.mapping(
            cursor, length, ignore_errors=True
        ):
            yield from range(cursor - self.start, addr - self.start, PAGE)
            cursor = addr + size
        yield from range(cursor - self.start, offset + length, PAGE)

    def read(self, offset: int, length: int) -> bytes:
        """Reads zero-padded: untranslatable pages come from the fallback, else they are zeros."""
        return self._read(offset, length, False)[0]

    def read_with_missing(self, offset: int, length: int) -> Tuple[bytes, int]:
        """Like `read`, and counts the pages that neither the process layer nor the fallback has.

        Args:
            offset: Where to start in the block (page-aligned)
            length: How many bytes to read (page-aligned)

        Returns:
            The data and the number of missing pages
        """
        return self._read(offset, length, True)

    def _read(self, offset: int, length: int, count: bool) -> Tuple[bytes, int]:
        first, end = offset & ~(PAGE - 1), (offset + length + PAGE - 1) & ~(PAGE - 1)
        data = bytearray(self.layer.read(self.start + first, end - first, pad=True))
        missing = 0
        for page in self._holes(first, end - first) if self._fallback or count else ():
            cached = self._fallback(page) if self._fallback else None
            content = cached.get_content() if cached is not None else None
            if content:
                data[page - first : page - first + PAGE] = content
            # `get_content` is None when the page is cached but its frame is not in the image
            missing += not content
        return bytes(data[offset - first : offset - first + length]), missing

    def resident_pages(self) -> int:
        """Pages that the process layer translates or the fallback has."""
        return self.residency()[0]

    def residency(self) -> Tuple[int, Dict[str, int]]:
        """(pages the image holds, pages by reason) from one walk over the untranslatable pages.

        The reason comes from the page table entry (`_reason`). Pages the fallback supplied count as held and are
        listed as RAM_RECOVERED, unless the page is cached and its frame is not in the image (`get_content` is
        None): that is FRAME_MISSING. The entry is read once per run of pages that share it: a missing page table
        covers 512 pages or more.
        """
        reasons: Counter[str] = collections.Counter()
        missing, covered_to, reason = 0, 0, ""
        for page in self._holes(0, self.size):
            cached = self._fallback(page) if self._fallback else None
            if cached is not None:
                if cached.get_content():
                    reasons[RAM_RECOVERED] += 1
                else:
                    missing += 1
                    reasons[FRAME_MISSING] += 1
                continue
            missing += 1
            if page >= covered_to:
                reason, covered_to = self._classify(page)
            reasons[reason] += 1
        return self.size // PAGE - missing, reasons

    def _classify(self, page: int) -> Tuple[str, int]:
        """(reason, end of the run of pages with the same entry) for a page the process layer does not translate.

        Only the public `translate` is used. It raises with the entry for a page that is not present and for a
        missing page table, where one run covers all pages of that table. For a present entry whose frame the image
        lacks it raises with the layer below, and the run is one page: the public API does not give the size of the
        page the entry maps. A missing 2 MiB page therefore costs one `translate` per 4 KiB page: 0.77 s instead of
        0.04 s for 212,000 pages of a hugetlbfs guest. The private `Intel._translate_entry` is faster, but it reports
        a present 2 MiB entry as "page table not in the image".
        """
        address = self.start + page
        try:
            self.layer.translate(address)
        except exceptions.PagedInvalidAddressException as excp:
            # Page not present, or its page table is not in the image. The entry says which and how many address
            # bits it covers, so a missing page table is classified once for all the pages it holds.
            end = (address | ((1 << excp.invalid_bits) - 1)) + 1 - self.start
            return self._reason(excp.entry, excp.invalid_bits), max(end, page + PAGE)
        except exceptions.InvalidAddressException as excp:
            # The entry is present but the layer below has no data there: the frame is not in the image.
            # An error in the process layer itself means the table cannot be read.
            if excp.layer_name != self.layer.name:
                return FRAME_MISSING, page + PAGE
        except AttributeError:  # not a translation layer
            pass
        return "unknown", page + PAGE

    def _reason(self, entry: int, bits: int) -> str:
        """Why a page is missing, from its page table entry.

        `bits` is the number of address bits the entry covers: more than 12 means an upper-level entry, so a whole page
        table is missing. Subclasses add the operating system's own non-present formats.
        """
        if entry == 0:
            return "never present"
        if entry & 1:
            return "page table not in the image" if bits > 12 else FRAME_MISSING
        return "not present (other entry)"


class GuestRam:
    """A guest's RAM as one flat range: several RAM blocks back to back, as in QEMU's machine RAM container.

    Plain `-m` gives one block. With `-numa node,memdev=...` each node has its own backend and allocation. QEMU
    places the nodes one after another in node order (hw/core/numa.c) and applies the PC memory map to the result.
    """

    def __init__(
        self,
        blocks: List[RamBlock],
        names: Optional[List[str]] = None,
        dimm_slots: Optional[List[Tuple[int, Optional[int]]]] = None,
    ):
        """`blocks` are the machine RAM blocks in node order, then the pc-dimm blocks that were found.

        `dimm_slots` lists every cold-plugged DIMM in plug order as (size, index into `blocks`, or None if its block is
        missing). A DIMM's address depends on all DIMMs before it (see `_guest_segments`).
        """
        self.blocks = blocks
        self.names = names or [""] * len(blocks)
        self.dimm_slots = dimm_slots or []
        self.machine_blocks = len(blocks) - sum(
            1 for _size, index in self.dimm_slots if index is not None
        )
        self.bases, base = [], 0
        for block in blocks:
            self.bases.append(base)
            base += block.size
        self.size = base
        self.start = blocks[0].start
        self._residency: Optional[Tuple[int, Dict[str, int]]] = None
        self.machine_size = sum(b.size for b in blocks[: self.machine_blocks])

    @property
    def backing(self) -> str:
        """The backing of the first block; all blocks of a guest have the same kind."""
        return self.blocks[0].backing

    def _locate(self, offset: int) -> Tuple[RamBlock, int, int]:
        """(block, offset in block, bytes left in block) for an offset into the flat RAM."""
        for block, base in zip(self.blocks, self.bases):
            if base <= offset < base + block.size:
                return block, offset - base, base + block.size - offset
        raise IndexError(offset)

    def read(self, offset: int, length: int) -> bytes:
        """Reads `length` bytes of the flat RAM at `offset`, across block ends, zero-padded as `RamBlock.read`."""
        parts = []
        while length > 0:
            block, inner, left = self._locate(offset)
            n = min(length, left)
            parts.append(block.read(inner, n))
            offset, length = offset + n, length - n
        return b"".join(parts)

    def runs(self, segments: List[Segment]) -> Iterator[Tuple[int, RamBlock, int, int]]:
        """(guest-physical address, block, offset in block, length): the memory map split at block ends."""
        for seg in segments:
            for block, base in zip(self.blocks, self.bases):
                start = max(seg.ram_offset, base)
                end = min(seg.ram_offset + seg.length, base + block.size)
                if start < end:
                    yield (
                        seg.guest_phys + start - seg.ram_offset,
                        block,
                        start - base,
                        end - start,
                    )

    def residency(self) -> Tuple[int, Dict[str, int]]:
        """(pages of all blocks that the image holds, pages by reason), walked once and cached."""
        if self._residency is None:
            held = 0
            reasons: Counter[str] = collections.Counter()
            for block in self.blocks:
                block_held, block_reasons = block.residency()
                held += block_held
                reasons.update(block_reasons)
            self._residency = (held, reasons)
        return self._residency

    def resident_pages(self) -> int:
        """Pages of all blocks that the image holds."""
        return self.residency()[0]

    @property
    def resident_percent(self) -> float:
        """The share of the RAM that the image holds, in percent."""
        return round(100.0 * self.resident_pages() * PAGE / self.size, 1)


class GuestVM(NamedTuple):
    pid: int  # of the VMM process
    ram: GuestRam
    segments: List[Segment]
    machine: str
    rsdp: Optional[qemu_acpi.Rsdp] = None  # None if the guest was found another way
    # Set for a confidential guest ("SEV", "SEV-SNP", "TDX", ...): `ram` is then ciphertext and `segments` is empty.
    encrypted: Optional[str] = None


class VmmInfo(NamedTuple):
    """What a plugin reports about a VMM process besides its guest."""

    accel: str  # "KVM", "TCG", or the -accel option (upper case)
    vcpus: object  # number of vCPU fds, or NotAvailableValue
    argv: List[str]
    # confidential guest: "SEV", "SEV-ES", "SEV-SNP", "TDX" or "guest_memfd"
    encrypted: Optional[str] = None


# --- virtio-mem ----------------------------------------------------------------------------------------


def _unnamed_virtio_mem(
    vmem: List[Tuple[str, Optional[int], int]],
    size: Optional[int],
    named: Dict[int, str],
) -> bool:
    """Whether a virtio-mem backend of `size` has no RAMBlock record, so its block cannot be told from RAM by size."""
    return bool(size) and any(
        vsize == size and memdev not in named.values() for memdev, vsize, _n in vmem
    )


# --- memory map --------------------------------------------------------------------------------------


def _below_4g(machine: str, ram_size: int) -> int:
    """Bytes of machine RAM mapped below 4 GiB: all of it, or 2 GiB (q35) / 3 GiB (pc) from 2.75 / 3.5 GiB of RAM."""
    if machine == "q35":
        full, split = Q35_LOWMEM_FULL, Q35_LOWMEM_SPLIT
    else:
        full, split = qemu_acpi.PC_LOW_RAM_MAX, PC_LOWMEM_SPLIT
    return min(ram_size, split if ram_size >= full else full)


def _device_memory_base(machine: str, ram_size: int, high_base: int = 4 * GIB) -> int:
    """The first GiB boundary after the RAM above 4 GiB, where the hotplug region starts (hw/i386/pc.c); used without an
    SRAT."""
    return (high_base + ram_size - _below_4g(machine, ram_size) + GIB - 1) & ~(GIB - 1)


def _dimm_addresses(base: int, sizes: List[int], align: int = 2 << 20) -> List[int]:
    """Guest-physical address of each cold-plugged DIMM: placed in plug order from the device memory base."""
    # QEMU aligns a DIMM to its backend's alignment: the huge page size of a hugetlbfs file (up to 1 GiB), 64 KiB for
    # VirtualAlloc'd memory on Windows. The fixed 2 MiB is wrong only if a DIMM before it is not a multiple of the
    # real alignment.
    addrs, cursor = [], base
    for size in sizes:
        cursor = (cursor + align - 1) & ~(align - 1)
        addrs.append(cursor)
        cursor += size
    return addrs


def _guest_segments(
    machine: str, ram: "GuestRam", uefi: bool = False, acpi_root: Optional[int] = None
) -> List[Segment]:
    """The whole guest-physical layout: machine RAM through the PC memory map, then each DIMM at its address.

    The start of the RAM above 4 GiB and of the hotplug region comes from the guest's SRAT if there is one. QEMU
    moves both to 1 TiB on AMD CPUs when the maximum address would reach the HyperTransport hole (for example
    Proxmox `hotplug: memory` with a 4 TiB maximum). Without an SRAT both follow the classic rules.
    """
    srat_high, srat_hotplug = (
        qemu_acpi.QemuAcpi.memory_bases(ram, acpi_root) if acpi_root else (None, None)
    )
    high_base = 4 * GIB if srat_high is None else srat_high
    segments = _x86_memory_map(machine, ram.machine_size, uefi, high_base)
    base = (
        _device_memory_base(machine, ram.machine_size, high_base)
        if srat_hotplug is None
        else srat_hotplug
    )
    for (size, index), gpa in zip(
        ram.dimm_slots, _dimm_addresses(base, [size for size, _i in ram.dimm_slots])
    ):
        if index is not None:
            segments.append(Segment(gpa, ram.bases[index], size))
    return segments


def _x86_memory_map(
    machine: str, ram_size: int, uefi: bool = False, high_base: int = 4 * GIB
) -> List[Segment]:
    """Guest-physical layout of a QEMU x86 PC guest's RAM (hw/i386/pc_piix.c, pc_q35.c, gigabyte_align on).

    RAM below 4 GiB is identity mapped except the legacy VGA window. The rest starts at `high_base`. SeaBIOS copies
    itself into RAM at 0xE0000-0xFFFFF. Under UEFI that range holds the firmware ROM instead, so it is left out.

    On q35 the TSEG (SMRAM, hw/pci-host/q35.c `mch_update_smram`) is not left out. It is the top
    `extended-tseg-mbytes` of the RAM below 4 GiB (16 MiB for machine types 2.10 to 10.1, 64 MiB from 10.2 on) and
    exists once the firmware has turned SMM on. Its bytes are ordinary guest RAM in the block, so they appear here as
    RAM at their own addresses. This is harmless: the firmware reserves the TSEG in the memory map it gives the guest
    OS, so no kernel, page table or process lives there; the guest itself sees 0xFF there while the TSEG is closed.
    The KVM path reads the memslots of address space 0, where a closed TSEG is a hole, and the SMM address space
    (as_id 1, `--smm`) apart. This path shows the SMM firmware modules and their state, if any.
    """
    below = _below_4g(machine, ram_size)
    holes = [VGA_HOLE] + ([qemu_acpi.BIOS_AREA] if uefi else [])
    segments, start = [], 0
    for hole_start, hole_end in holes:
        if start < hole_start:
            segments.append(Segment(start, start, min(hole_start, below) - start))
        start = hole_end
    if below > start:
        segments.append(Segment(start, start, below - start))
    if ram_size > below:
        segments.append(Segment(high_base, below, ram_size - below))
    return segments


# --- NUMA: several RAM blocks per guest --------------------------------------------------------------


def _ramblock_hits(
    layer: interfaces.layers.DataLayerInterface,
    heap_ranges: Iterable[Tuple[int, int]],
    blocks: List[RamBlock],
) -> Iterator[Tuple[RamBlock, bytes, int]]:
    """Finds QEMU's RAMBlock records for `blocks` in its heap: (block, scanned data, offset of the record in it).

    A record has the block's start at an 8-byte aligned offset and its size within RAMBLOCK_USED_LENGTH after it. Each
    chunk is read RAMBLOCK_RECORD bytes further, so a record at the chunk end is complete.
    """
    wanted = {struct.pack("<Q", b.start): b for b in blocks}
    lo, hi = RAMBLOCK_USED_LENGTH
    for start, end in heap_ranges:
        for base in range(start, end, SCAN_CHUNK):
            data = layer.read(
                base, min(SCAN_CHUNK + RAMBLOCK_RECORD, end - base), pad=True
            )
            for pattern, block in wanted.items():
                for m in re.finditer(re.escape(pattern), data):
                    off = m.start()
                    if (
                        off % 8
                        or struct.pack("<Q", block.size)
                        not in data[off + lo : off + hi]
                    ):
                        continue
                    yield block, data, off


def _ramblock_names(
    layer: interfaces.layers.DataLayerInterface,
    heap_ranges: Iterable[Tuple[int, int]],
    blocks: List[RamBlock],
    ids: List[str],
) -> Dict[int, str]:
    """{block start: memdev id} for the ids in `ids` that appear in a block's RAMBlock record."""
    found: Dict[int, str] = {}
    for block, data, off in _ramblock_hits(layer, heap_ranges, blocks):
        window = data[off : off + RAMBLOCK_RECORD]
        for memdev in ids:
            if b"\x00" + memdev.encode() + b"\x00" in window:
                found.setdefault(block.start, memdev)
        if len(found) == len(blocks):
            break
    return found


def _ramblock_records(
    layer: interfaces.layers.DataLayerInterface,
    heap_ranges: Iterable[Tuple[int, int]],
    blocks: List[RamBlock],
) -> Dict[int, str]:
    """{block start: idstr} read from the RAMBlock records, for blocks whose id is not in a known list."""
    found: Dict[int, str] = {}
    for block, data, off in _ramblock_hits(layer, heap_ranges, blocks):
        ident = RAMBLOCK_ID.match(data[off + RAMBLOCK_IDSTR : off + RAMBLOCK_RECORD])
        if ident:
            found.setdefault(block.start, ident.group(1).decode())
        if len(found) == len(blocks):
            break
    return found


def _warn_unused_blocks(
    pid: int,
    blocks: List[RamBlock],
    argv: List[str],
    rams: List[GuestRam],
    heap_ranges: Callable[[], Iterable[Tuple[int, int]]],
) -> None:
    """Warns, once per VMM process, about RAM blocks that no rebuilt guest uses.

    Typical case: a DIMM hot-added at run time (QMP `device_add`), which is not on the command line. The kvm plugins
    place it from the memslots. Blocks that the command line names and device regions such as `vga.vram` do not count.
    """
    used = {b.start for ram in rams for b in ram.blocks}
    spare = [b for b in blocks if b.start not in used]
    if not rams or not spare:
        return
    dimms, vmem = qemu_cmdline.QemuCmdline.memory_devices(argv)
    known = {m for m, _s in qemu_cmdline.QemuCmdline.numa_memdevs(argv) + dimms}
    known.update(m for m, _s, _n in vmem)
    names = _ramblock_records(spare[0].layer, heap_ranges(), spare)
    vollog.debug(
        f"PID {pid}: RAM blocks outside the guest: "
        + ", ".join(
            f"{b.start:#x} {b.size >> 20} MiB {names.get(b.start, '(no record)')}"
            for b in spare
        )
    )
    unused = [
        f"{names[b.start]} ({b.size >> 20} MiB)"
        for b in sorted(spare, key=lambda b: b.start)
        if b.start in names
        and names[b.start] not in known
        and not RAMBLOCK_DEVICE.search(names[b.start])
    ]
    if unused:
        vollog.warning(
            f"PID {pid}: RAM block(s) with a QEMU RAMBlock record that the rebuilt guest does not use: "
            f"{', '.join(unused)}; memory added at run time (QMP device_add) is not on the command line and "
            "is not placed; linux.kvm.VMs / linux.kvm.Slots place it from the KVM memslots"
        )


def _same_size(
    blocks: List[RamBlock], size: Optional[int], skip: Iterable[int] = ()
) -> List[RamBlock]:
    """The blocks of `size` (not starting in `skip`), earliest created first: QEMU allocates top-down."""
    found = [b for b in blocks if b.size == size and b.start not in skip]
    return sorted(found, key=lambda b: -b.start)


def _numa_uefi_candidate(
    blocks: List[RamBlock],
    argv: List[str],
    heap_ranges: Callable[[], Iterable[Tuple[int, int]]],
) -> Optional[Tuple[RamBlock, qemu_acpi.Rsdp]]:
    """(node 0 block, RSDP) for a UEFI guest with NUMA nodes.

    OVMF puts its ACPI tables near the top of low RAM, which can lie in node 1's block, so searching one block fails.
    Node 0 is the block named by its RAMBlock record, else the earliest-created block of node 0's size. The assembled
    RAM is then searched as a whole.
    """
    nodes = qemu_cmdline.QemuCmdline.numa_memdevs(argv)
    if len(nodes) < 2 or not blocks:
        return None
    vmem = qemu_cmdline.QemuCmdline.memory_devices(argv)[1]
    named = _ramblock_names(
        blocks[0].layer,
        heap_ranges(),
        blocks,
        [nodes[0][0]] + [memdev for memdev, _size, _n in vmem],
    )
    first = [b for b in blocks if named.get(b.start) == nodes[0][0]]
    if not first and not _unnamed_virtio_mem(vmem, nodes[0][1], named):
        first = _same_size(blocks, nodes[0][1], named)[:1]
    if not first:
        return None
    found = qemu_acpi.QemuAcpi.deep_rsdp(
        _assemble_guest_ram(first[0], blocks, argv, heap_ranges, lambda _msg: None)
    )
    return (first[0], found) if found else None


class _BlockPicker:
    """Hands out the RAM blocks of one guest, each once: by the RAMBlock record's name, else by backend size."""

    def __init__(
        self,
        first: RamBlock,
        blocks: List[RamBlock],
        named: Dict[int, str],
        vmem: List[Tuple[str, Optional[int], int]],
        warn: Callable[[str], None],
    ):
        self.blocks, self.named, self.vmem, self.warn = blocks, named, vmem, warn
        self.used = {first.start}
        # Blocks taken by size where several have that size; only their address order tells them apart.
        self.ambiguous: Set[int] = set()

    def pick(self, memdev: str, size: Optional[int]) -> Optional[RamBlock]:
        """The block of the backend `memdev` (`size` bytes by the command line), or None."""
        by_name = [
            b
            for b in self.blocks
            if self.named.get(b.start) == memdev and b.start not in self.used
        ]
        by_size = _same_size(self.blocks, size, self.used.union(self.named))
        if not by_name and _unnamed_virtio_mem(self.vmem, size, self.named):
            self.warn(
                f"{memdev}: a virtio-mem backend has the same size and no RAMBlock record names either block"
            )
            return None
        found = (by_name or by_size or [None])[0]
        if found is None or (size and found.size != size):
            return None
        if not by_name and len(by_size) > 1:
            self.ambiguous.add(found.start)
        self.used.add(found.start)
        return found

    def take(
        self, block: RamBlock, memdev: str, chosen: List[RamBlock], names: List[str]
    ) -> None:
        """Appends a picked block and its memdev id to the guest's blocks and names."""
        chosen.append(block)
        names.append(memdev)
        if block.start in self.ambiguous:
            # If QEMU created the backends in another order than the command line lists them, the equal-sized
            # nodes or DIMMs are swapped in the rebuilt guest.
            self.warn(
                f"{memdev}: RAM block {block.start:#x} taken by size and address order only (several blocks have "
                "its size and no RAMBlock record names them): equal-sized NUMA nodes or DIMMs may be swapped"
            )
        elif block.start not in self.named:
            vollog.info(f"{memdev}: RAM block {block.start:#x} identified by its size")


def _dimm_slots(
    dimms: List[Tuple[str, Optional[int]]],
    vmem: List[Tuple[str, Optional[int], int]],
    picker: _BlockPicker,
    chosen: List[RamBlock],
    names: List[str],
) -> List[Tuple[int, Optional[int]]]:
    """The DIMM slots of a guest as `GuestRam` takes them, in plug order. Found DIMM blocks go to `chosen`/`names`."""
    slots: List[Tuple[int, Optional[int]]] = []
    # A pc-dimm plugged after a virtio-mem device starts behind its region, whose size is uncertain: not placed.
    unplaced_from = min((n for _m, _s, n in vmem), default=len(dimms))
    for i, (memdev, size) in enumerate(dimms):
        if i >= unplaced_from:
            picker.warn(
                f"DIMM {memdev} is plugged after a virtio-mem device; its address is not known"
            )
            slots.append((size or 0, None))
            continue
        block = picker.pick(memdev, size) if size else None
        if block is None:
            picker.warn(
                f"no RAM block for DIMM {memdev}; its {(size or 0) >> 20} MiB are missing"
            )
            slots.append((size or 0, None))
            continue
        slots.append((size, len(chosen)))
        picker.take(block, memdev, chosen, names)
    return slots


def _assemble_guest_ram(
    first: RamBlock,
    others: List[RamBlock],
    argv: List[str],
    heap_ranges: Callable[[], Iterable[Tuple[int, int]]],
    warn: Callable[[str], None],
) -> GuestRam:
    """The guest's whole RAM: `first`, the other NUMA nodes' blocks in node order and the cold-plugged DIMMs.

    `first` is the block with the firmware tables: machine RAM, or NUMA node 0. Every other block is identified by its
    RAMBlock record (memdev id as `idstr`), else by the backend size from the command line (see `_same_size`).
    """
    nodes = qemu_cmdline.QemuCmdline.numa_memdevs(argv)
    dimms, vmem = qemu_cmdline.QemuCmdline.memory_devices(argv)
    if len(nodes) < 2 and not dimms:
        return GuestRam([first])
    nodes = nodes if len(nodes) >= 2 else [("machine RAM", first.size)]
    blocks = [first] + [b for b in others if b.start != first.start]
    # The virtio-mem ids are looked up too, so that no size match takes their blocks for RAM or DIMMs.
    named = _ramblock_names(
        first.layer,
        heap_ranges(),
        blocks,
        [m for m, _ in nodes + dimms] + [m for m, _size, _n in vmem],
    )
    if len(nodes) >= 2 and named.get(first.start, nodes[0][0]) != nodes[0][0]:
        warn(f"firmware block is {named[first.start]}, not NUMA node 0 ({nodes[0][0]})")
    picker = _BlockPicker(first, blocks, named, vmem, warn)
    chosen, names = [first], [nodes[0][0]]
    for i, (memdev, size) in enumerate(nodes[1:], 1):
        block = picker.pick(memdev, size)
        if block is None:
            warn(f"no RAM block for NUMA node {i} ({memdev}); only node 0 is used")
            return GuestRam([first], [nodes[0][0]])
        picker.take(block, memdev, chosen, names)
    return GuestRam(chosen, names, _dimm_slots(dimms, vmem, picker, chosen, names))


# --- output ------------------------------------------------------------------------------------------

# The columns the QEMU plugins share. A guest whose RAM is several blocks (NUMA nodes, DIMMs) gets one child row per
# block with its Name (memdev id), RAM MiB, RAM at and Backing.
VM_COLUMNS = [
    ("Name", str),
    ("VMID", int),
    ("Forwards", str),
    ("Network", str),
    ("Control", str),
    ("Images", str),
    ("Machine", str),
    ("RAM MiB", int),
    ("RAM at", format_hints.Hex),
    ("RAM blocks", int),
    ("Backing", str),
    ("Resident %", float),
    ("Firmware", str),
    ("ACPI OEM", str),
    ("RSDP at", format_hints.Hex),
    ("Encrypted", str),
    ("Guest banner", str),
    ("File output", str),
]


OpenFile = Callable[[str], ContextManager[interfaces.plugins.FileHandlerInterface]]

EHDR_SIZE, PHDR_SIZE = 64, 56
PT_LOAD = 1
PF_RWX = 7  # PF_X | PF_W | PF_R
# ELF64, little endian, version 1, padded to 16 bytes
ELF_IDENT = b"\x7fELF\x02\x01\x01"
# The ELF header up to phnum: ET_CORE, EM_X86_64, version 1, no entry, phoff, no shoff, flags, ehsize, phentsize.
EHDR_FIXED = struct.pack(
    "<16sHHIQQQIHH", ELF_IDENT, 4, 62, 1, 0, EHDR_SIZE, 0, 0, EHDR_SIZE, PHDR_SIZE
)


def _write_elf(
    f: interfaces.plugins.FileHandlerInterface, ram: GuestRam, segments: List[Segment]
) -> int:
    """Writes an ELF64 core to `f` with one PT_LOAD per segment (`p_paddr` = guest-physical address); returns the number
    of zero-filled pages the host image does not hold.
    """
    n = len(segments)
    data_off = (EHDR_SIZE + n * PHDR_SIZE + PAGE - 1) & ~(PAGE - 1)
    ehdr = EHDR_FIXED + struct.pack("<4H", n, 0, 0, 0)  # phnum, no section headers
    phdrs, off = b"", data_off
    for seg in segments:
        # p_type, p_flags, p_offset, p_vaddr (none), p_paddr, p_filesz, p_memsz, p_align
        phdrs += struct.pack(
            "<IIQQQQQQ",
            PT_LOAD,
            PF_RWX,
            off,
            0,
            seg.guest_phys,
            seg.length,
            seg.length,
            PAGE,
        )
        off += seg.length
    missing = 0
    f.write(ehdr + phdrs + b"\x00" * (data_off - EHDR_SIZE - len(phdrs)))
    for _gpa, block, offset, length in ram.runs(segments):
        for off in range(offset, offset + length, SCAN_CHUNK):
            n = min(SCAN_CHUNK, offset + length - off)
            data, holes = block.read_with_missing(off, n)
            f.write(data)
            missing += holes
    return missing


# --- the versioned interface ----------------------------------------------------------------------


class QemuCommon(interfaces.configuration.VersionableInterface):
    """The functions that linux.qemu, windows.qemu, linux.qemu_guest and linux.kvm call.

    Its version covers the whole module, including the types and constants (`Segment`, `RamBlock`, `GuestRam`,
    `GuestVM`, `VmmInfo`, `PAGE`, `VM_COLUMNS`, ...). Functions starting with `_` are internal.
    """

    _required_framework_version = (2, 13, 0)
    _version = (3, 0, 2)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """The components this one calls: the command line and the ACPI helpers."""
        return [
            requirements.VersionRequirement(
                name="qemu_cmdline",
                component=qemu_cmdline.QemuCmdline,
                version=(1, 0, 0),
            ),
            requirements.VersionRequirement(
                name="qemu_acpi", component=qemu_acpi.QemuAcpi, version=(1, 0, 0)
            ),
        ]

    @classmethod
    def _library_reason(cls, files: Iterable[str]) -> Optional[Tuple[str, bool]]:
        """(reason, strong) if a mapped file marks the process as QEMU, else None.

        `files` are paths or 'directory/name'. The glib + pixman match is weak, all others are strong.
        """
        strong: Dict[str, str] = {}
        common: Dict[str, str] = {}
        desktop = False
        for path in files:
            *folders, name = re.split(r"[\\/]", path)
            lower = name.lower()
            if any(folder.lower() == "qemu" for folder in folders):
                strong.setdefault("qemu", f"{name} in a qemu directory")
            desktop = desktop or lower.startswith(DESKTOP_LIBRARY)
            for prefix in QEMU_STRONG_LIBRARIES:
                if lower.startswith(prefix):
                    strong.setdefault(prefix, name)
            for prefix in QEMU_COMMON_LIBRARIES:
                if lower.startswith(prefix):
                    common.setdefault(prefix, name)
        if strong:
            return f"maps {', '.join(strong.values())}", True
        if len(common) == len(QEMU_COMMON_LIBRARIES) and not desktop:
            return f"maps {', '.join(common.values())}", False
        return None

    @classmethod
    def vmm_signal(
        cls,
        pid: int,
        argv: List[str],
        files: Optional[Callable[[], Iterable[str]]] = None,
        kvm: bool = False,
    ) -> int:
        """How sure it is that a process is a VMM: 0 not, 1 possibly, 2 certainly.

        Any signal earns the deep RSDP search over whole blocks. A false positive only costs time, because an RSDP is
        accepted only with a valid RSDT/XSDT behind it, and a false negative would lose a UEFI guest. Only signal 2
        (KVM file, two QEMU options on the command line, strong QEMU libraries) justifies listing the process when
        no guest is found. The reason is logged at info level. `files` is called only if the command line does not
        decide, because walking the mappings is slow.
        """
        reason, strong = (
            (
                "holds a KVM VM file"
                if kvm
                else qemu_cmdline.QemuCmdline.argv_reason(argv)
            ),
            True,
        )
        if reason is None and files is not None:
            found = cls._library_reason(files())
            reason, strong = found if found else (None, False)
        if reason is not None:
            vollog.info(
                f"PID {pid}: treated as a VMM: {reason}"
                + (
                    ""
                    if strong
                    else " (weak evidence: searched, but not listed without a guest)"
                )
            )
        return 0 if reason is None else (2 if strong else 1)

    @classmethod
    def vmas(
        cls, mm: interfaces.objects.ObjectInterface
    ) -> Iterator[interfaces.objects.ObjectInterface]:
        """The valid VMAs of an `mm_struct` in address order, like `mm.get_vma_iter()` but without its crash.

        `vm_area_struct.is_valid()` raises AttributeError on a file mapping whose `get_inode()` is None, such as SysV
        shared memory segment 0 (volatility3#2082, fix proposed in volatility3 PR #2083, present in 2.28.2). Such a mapping is
        kept.

        Args:
            mm: The process's `mm_struct`
        """
        # `_do_get_vma_iter` is the walk without the failing check. 2.28.2 has no public equivalent.
        for vma in getattr(mm, "_do_get_vma_iter", mm.get_vma_iter)():
            try:
                if not vma.is_valid():
                    continue
            except AttributeError:
                pass
            yield vma

    @classmethod
    def encrypted_block(
        cls, blocks: List["RamBlock"], argv: List[str]
    ) -> Optional["RamBlock"]:
        """The RAM block of a confidential guest: the one block of the `-m` size, whatever it holds; None if none or
        several.

        Its content is ciphertext, or with SEV-SNP/TDX on guest_memfd kernels only the shared pages.

        Args:
            blocks: The process's read-write allocations of at least MIN_RAM bytes
            argv: The VMM's command line
        """
        ram_size = qemu_cmdline.QemuCmdline.ram_size(argv)
        same = [b for b in blocks if b.size == ram_size]
        return same[0] if len(same) == 1 else None

    @classmethod
    def unplaced_guest(
        cls,
        pid: int,
        blocks: List["RamBlock"],
        argv: List[str],
        heap_ranges: Callable[[], Iterable[Tuple[int, int]]],
    ) -> Optional[GuestVM]:
        """The guest of a certain VMM whose ACPI RSDP is not in the image, with `rsdp` None; None if no block.

        The RAM block is the one of the `-m` size, else the largest. The machine type comes from the command line
        and the memory map is the classic one, since there are no ACPI tables to read.
        """
        if not blocks:
            return None
        block = cls.encrypted_block(blocks, argv) or max(blocks, key=lambda b: b.size)
        ram = _assemble_guest_ram(
            block,
            blocks,
            argv,
            heap_ranges,
            lambda msg: vollog.warning(f"PID {pid}: {msg}"),
        )
        machine = qemu_cmdline.QemuCmdline.machine_type(argv)
        return GuestVM(pid, ram, _guest_segments(machine, ram), machine)

    @classmethod
    def guest_banner(cls, ram: GuestRam) -> object:
        """The guest's kernel as text, as a hint for picking a symbol table; NotAvailableValue if none is found.

        That is the first complete Linux banner in the guest's RAM, or for a Windows guest the kernel's PDB name with
        GUID and age, as vol3 names its symbol files ('Windows kernel ntkrnlmp.pdb 1A2B...-1'). A multiprocessor kernel
        (ntkrnlmp, ntkrpamp) wins over ntoskrnl or ntkrnlpa records, which a Windows guest also holds for other images.
        Both kernels randomize their physical address, so the RAM is read until a banner turns up.

        Args:
            ram: The guest's RAM
        """
        fallback = None
        for off in range(0, ram.size, SCAN_CHUNK):
            data = ram.read(off, min(SCAN_CHUNK + 512, ram.size - off))
            linux = LINUX_BANNER.search(data)
            if linux:
                return cls.preferred_banner(cls.linux_banners(ram, off))
            for match in NT_RSDS.finditer(data):
                if match.group(3) in NT_MP_KERNELS:
                    return cls._nt_kernel(match)
                fallback = fallback or cls._nt_kernel(match)
        return fallback or renderers.NotAvailableValue()

    @classmethod
    def linux_banners(cls, ram: GuestRam, start: int = 0) -> List[str]:
        """The distinct Linux banners in the guest's RAM, in address order; empty if there is none.

        These are the first banner from `start` and the ones within BANNER_WINDOW after it. A kernel image holds
        several: the real `linux_banner`, a weak one without build number, and copies in the log buffer or page cache.
        Volatility's stackers match a symbol table by any of them, so a caller checking for a known table must try them
        all.

        Args:
            ram: The guest's RAM
            start: Where to begin (a multiple of SCAN_CHUNK)
        """
        found: List[str] = []
        end, windowed = ram.size, False
        for off in range(start, ram.size, SCAN_CHUNK):
            if off >= end:
                break
            data = ram.read(off, min(SCAN_CHUNK + 512, ram.size - off))
            last = off + SCAN_CHUNK >= ram.size
            for match in LINUX_BANNER.finditer(data):
                if match.start() >= SCAN_CHUNK and not last:
                    break  # the next chunk reads it whole
                if windowed and off + match.start() >= end:
                    return found
                if not windowed:
                    end, windowed = off + match.start() + BANNER_WINDOW, True
                text = match.group().decode("ascii")
                if text not in found:
                    found.append(text)
        return found

    @classmethod
    def preferred_banner(cls, banners: List[str]) -> str:
        """The banner that names the guest's kernel: the first one with a build number, else the first of `banners`, not
        empty."""
        return next((b for b in banners if LINUX_BANNER_BUILD.search(b)), banners[0])

    @classmethod
    def _nt_kernel(cls, match) -> str:
        """'Windows kernel <pdb> <GUID>-<age>' from an NT_RSDS match."""
        guid, age, pdb = match.group(1), match.group(2), match.group(3)
        d1, d2, d3 = struct.unpack_from("<IHH", guid)
        age_value = struct.unpack("<I", age)[0]
        return (
            f"Windows kernel {pdb.decode()} "
            f"{d1:08X}{d2:04X}{d3:04X}{guid[8:].hex().upper()}-{age_value}"
        )

    @classmethod
    def find_guests(
        cls,
        pid: int,
        blocks: List[RamBlock],
        argv: List[str],
        deep: bool,
        heap_ranges: Callable[[], Iterable[Tuple[int, int]]],
    ) -> Iterator[GuestVM]:
        """The x86 PC guests whose RAM is among `blocks`, the large read-write allocations of one VMM process.

        Low RAM is found by its ACPI RSDP in the BIOS area. With `deep` the whole blocks are searched too, for UEFI.
        A UEFI guest with NUMA nodes needs the assembled RAM for that (`_numa_uefi_candidate`). Arguments are as for
        `detect_guests`.
        """
        found = [
            (b, f)
            for b in blocks
            for f in [
                qemu_acpi.QemuAcpi.bios_rsdp(b)
                or (qemu_acpi.QemuAcpi.deep_rsdp(b) if deep else None)
            ]
            if f
        ]
        if not found and deep:
            found = [c for c in [_numa_uefi_candidate(blocks, argv, heap_ranges)] if c]
        vmem = qemu_cmdline.QemuCmdline.memory_devices(argv)[1]
        if vmem and found:
            devices = ", ".join(f"{m} ({(n or 0) >> 20} MiB)" for m, n, _d in vmem)
            vollog.warning(
                f"PID {pid}: virtio-mem on the command line, memdev {devices}: this memory is not rebuilt "
                "(only -m RAM, NUMA nodes and cold-plugged DIMMs are); linux.kvm.VMs / linux.kvm.Slots "
                "place it from the KVM memslots"
            )
        guests = []
        for block, rsdp in found:
            ram = _assemble_guest_ram(
                block,
                blocks,
                argv,
                heap_ranges,
                lambda msg: vollog.warning(f"PID {pid}: {msg}"),
            )
            machine = cls._guest_machine(pid, argv, ram, rsdp.root)
            guests.append(
                GuestVM(
                    pid,
                    ram,
                    _guest_segments(machine, ram, rsdp.firmware == "UEFI", rsdp.root),
                    machine,
                    rsdp,
                )
            )
        _warn_unused_blocks(pid, blocks, argv, [g.ram for g in guests], heap_ranges)
        yield from guests

    @classmethod
    def _guest_machine(cls, pid: int, argv: List[str], ram: GuestRam, root: int) -> str:
        """The machine type of a guest, which decides where RAM below 4 GiB ends.

        It is the command line's `-machine` if that looks like QEMU's, else the ACPI tables' (`QemuAcpi.machine`), else
        the QEMU default pc. The source is logged.
        """
        cmdline = qemu_cmdline.QemuCmdline
        named = cmdline.named_machine(argv)
        if named and cmdline.looks_like_qemu(argv):
            machine, source = named, "the command line"
        else:
            acpi = qemu_acpi.QemuAcpi.machine(ram, root)
            if acpi:
                machine, source = acpi[0], f"the ACPI tables ({acpi[1]})"
            else:
                machine, source = (
                    cmdline.machine_type(argv),
                    "the default (no usable ACPI evidence)",
                )
        vollog.info(f"PID {pid}: machine type {machine} from {source}")
        return machine

    @classmethod
    def row(
        cls, columns: List[Tuple[str, type]], values: Dict[str, object]
    ) -> List[object]:
        """`values` in column order; a column without a value is N/A.

        Args:
            columns: The plugin's TreeGrid columns, as (name, type)
            values: The cell values by column name
        """
        return [
            values.get(name, renderers.NotAvailableValue()) for name, _type in columns
        ]

    @classmethod
    def warn_no_guest(
        cls, pid: int, blocks: List[RamBlock], guest: Optional[GuestVM] = None
    ) -> None:
        """Warns that a process was taken for a VMM but no ACPI RSDP was found in its RAM blocks.

        Probably the page that holds it is not in the image (paged out, compressed, never written), or the guest has
        no ACPI. `guest` is what `unplaced_guest` made of the blocks, None if the process is listed without RAM.
        """
        pages = sum(b.size for b in blocks) // PAGE
        # `guest.ram` caches its count, because the table row asks for it again.
        covered = {b.start for b in guest.ram.blocks} if guest else set()
        held = guest.ram.resident_pages() if guest else 0
        held += sum(b.resident_pages() for b in blocks if b.start not in covered)
        if guest:
            vollog.warning(
                f"PID {pid}: treated as a VMM, but its ACPI RSDP is not in the image: guest RAM "
                f"{100.0 - 100.0 * held / max(pages, 1):.1f} % not resident ({pages * PAGE >> 20} MiB in "
                f"{len(blocks)} large read-write blocks); listed with {guest.ram.size >> 20} MiB of RAM, "
                "without firmware"
            )
            return
        vollog.warning(
            f"PID {pid}: treated as a VMM, but no ACPI RSDP was found in its {len(blocks)} large read-write "
            f"blocks ({pages * PAGE >> 20} MiB, {100.0 * held / max(pages, 1):.1f} % resident): the page that "
            "holds it is not resident, or the guest has no ACPI; the process is listed without RAM or firmware"
        )

    @classmethod
    def detect_guests(
        cls,
        pid: int,
        blocks: List[RamBlock],
        argv: List[str],
        files: Callable[[], Iterable[str]],
        heap_ranges: Callable[[], Iterable[Tuple[int, int]]],
        kvm: bool = False,
    ) -> Tuple[List[GuestVM], Optional[GuestVM], int]:
        """What one process holds, in the order every VMM plugin asks.

        First how sure it is a VMM (`vmm_signal`), then the guests in its RAM blocks (`find_guests`, deep if any signal
        is there). A process that is certainly a VMM, has no KVM VM file and no guest gets the guest placed from its
        command line alone (`unplaced_guest`, with the `warn_no_guest` warning).

        Args:
            pid: The process ID
            blocks: The process's read-write allocations of at least MIN_RAM bytes
            argv: The process's command line (empty if unreadable or overwritten)
            files: Returns the names of the files the process maps, called only if needed
            heap_ranges: Returns the (start, end) ranges that may hold QEMU's RAMBlock records, called only for guests
                with several RAM blocks
            kvm: The process holds a KVM VM file (Linux); such a process is never "unplaced"

        Returns:
            (guests, unplaced guest or None, `vmm_signal` result; 0 if there are no blocks)
        """
        signal = cls.vmm_signal(pid, argv, files, kvm) if blocks else 0
        guests = list(cls.find_guests(pid, blocks, argv, signal > 0, heap_ranges))
        unplaced = None
        if not guests and not kvm and signal >= 2:
            unplaced = cls.unplaced_guest(pid, blocks, argv, heap_ranges)
            cls.warn_no_guest(pid, blocks, unplaced)
        return guests, unplaced, signal

    @classmethod
    def log_residency(cls, label: str, ram: GuestRam) -> None:
        """Warns, once per VM, how many guest pages the image does not hold and why.

        The page table entry of each untranslatable page tells whether the host swapped it out, never backed it, or
        (Windows) holds it in a transition state or the compression store. The Resident % column gives only the count.
        What becomes of such a page depends on the caller: the ELF dump writes zeros, `qemu_guest.Run` reads zeros
        only for a page that was never backed and treats the others as invalid.

        Args:
            label: What the message is about, such as "PID 4000"
            ram: The guest's RAM
        """
        held, reasons = ram.residency()
        recovered = reasons.get(RAM_RECOVERED, 0)
        missing = ram.size // PAGE - held
        if not missing and not recovered:
            return
        lost = sorted(
            ((n, why) for why, n in reasons.items() if why != RAM_RECOVERED),
            reverse=True,
        )
        text = (
            f"{label}: {missing} of {ram.size // PAGE} guest pages "
            f"({100.0 * missing * PAGE / ram.size:.1f} %) are not in the image"
        )
        if lost:
            text += ": " + ", ".join(f"{why} {n}" for n, why in lost)
        if recovered:
            text += f"; {recovered} more {RAM_RECOVERED}"
        vollog.warning(text)

    @classmethod
    def ram_values(
        cls, vm: GuestVM, open_file: OpenFile, dump: bool
    ) -> Dict[str, object]:
        """The RAM columns of a VM by name; with `dump` its RAM is also written as an ELF core (not if encrypted)."""
        if not dump:
            output = "Disabled"
        elif vm.encrypted:
            output = renderers.NotAvailableValue()
        else:
            output = cls.dump_elf(open_file, f"vm.{vm.pid}.{vm.ram.start:#x}.elf", vm)
        values = {
            "Machine": vm.machine,
            "RAM MiB": vm.ram.size >> 20,
            "RAM at": format_hints.Hex(vm.ram.start),
            "RAM blocks": len(vm.ram.blocks),
            "Backing": vm.ram.backing,
            "Resident %": vm.ram.resident_percent,
            "File output": output,
        }
        if vm.rsdp:
            values.update(
                {
                    "Firmware": vm.rsdp.firmware,
                    "ACPI OEM": vm.rsdp.oem,
                    "RSDP at": format_hints.Hex(vm.rsdp.address),
                }
            )
        if vm.encrypted:
            values["Encrypted"] = vm.encrypted
        else:
            values["Guest banner"] = cls.guest_banner(vm.ram)
            cls.log_residency(f"PID {vm.pid}", vm.ram)
        return values

    @classmethod
    def vm_rows(
        cls,
        columns: List[Tuple[str, type]],
        process: Dict[str, object],
        info: VmmInfo,
        vm: Optional[GuestVM],
        open_file: OpenFile,
        dump: bool,
        owner: Optional[Dict[str, object]] = None,
    ) -> Iterator[Tuple[int, List[object]]]:
        """The rows of one VMM process: the VM (level 0) and, for several RAM blocks, one row per block (level 1).

        Args:
            columns: The plugin's TreeGrid columns
            process: The process columns that every row repeats (PID, process name)
            info: What the plugin found about the VMM process
            vm: The guest, or None for a VMM whose guest was not rebuilt
            open_file: The plugin's `open`, for the ELF core
            dump: Whether to write the guest's RAM as an ELF core
            owner: More process columns for the VM row only (parent, user, start time, executable)

        Yields:
            (tree level, row values in column order)
        """
        values = {
            **process,
            **(owner or {}),
            "Accel": info.accel,
            "vCPUs": info.vcpus,
            **qemu_cmdline.QemuCmdline.argv_values(info.argv),
        }
        if vm:
            values.update(cls.ram_values(vm, open_file, dump))
        elif info.encrypted:  # confidential guest, RAM block not identified
            values["Machine"] = qemu_cmdline.QemuCmdline.machine_type(info.argv)
            values["Encrypted"] = info.encrypted
        yield 0, cls.row(columns, values)
        for block in cls.block_values(vm) if vm else []:
            yield 1, cls.row(columns, {**process, **block})

    @classmethod
    def block_values(cls, vm: GuestVM) -> List[Dict[str, object]]:
        """One child row per block, in guest RAM order; none for a guest with a single block."""
        if len(vm.ram.blocks) < 2:
            return []
        return [
            {
                "Name": name or renderers.NotAvailableValue(),
                "RAM MiB": block.size >> 20,
                "RAM at": format_hints.Hex(block.start),
                "Backing": block.backing,
            }
            for name, block in zip(vm.ram.names, vm.ram.blocks)
        ]

    @classmethod
    def dump_elf(cls, open_file: OpenFile, name: str, vm: GuestVM) -> str:
        """Writes the guest's RAM as an ELF core into the plugin's output file `name` and returns the name.

        Args:
            open_file: The plugin's `open`
            name: The file name for the output
            vm: The guest; its RAM is written through its memory map
        """
        with open_file(name) as f:
            missing = _write_elf(f, vm.ram, vm.segments)
        vollog.info(f"{name}: {missing} non-resident pages written as zeros")
        return name
