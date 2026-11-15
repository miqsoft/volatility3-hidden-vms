# This file is Copyright 2026 Michael Külper and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
#
"""The ACPI tables of a QEMU x86 PC guest, read from its RAM: the RSDP, the machine type and the SRAT memory ranges.

SeaBIOS puts the RSDP in the BIOS area, UEFI firmware (OVMF) near the top of low RAM. The functions take any object
with `size` and `read(offset, length)` (`AcpiRam`), so this module does not depend on qemu_common. `QemuAcpi` is the
versioned interface, and its version covers the whole module.
"""

import itertools
import logging
import re
import struct
import time
from typing import Iterator, List, NamedTuple, Optional, Protocol, Tuple

from volatility3.framework import interfaces

vollog = logging.getLogger(__name__)

SCAN_CHUNK = 1 << 20  # bytes of guest RAM read at a time when searching for an RSDP
GIB = 1 << 30
# The highest end that RAM below the 32-bit PCI hole can have on any QEMU PC machine type. pc maps RAM below 3.5 GiB
# whole and splits larger RAM at 3 GiB. q35 maps RAM below 2.75 GiB whole and splits larger RAM at 2 GiB.
# Below this limit, guest-physical address = offset into the machine RAM, so tables there are found by address.
# The machine type is not known yet when the RSDP is searched for, so the higher bound is used.
PC_LOW_RAM_MAX = 0xE0000000
# An ACPI table has a 36-byte header (signature, u32 length at offset 4, checksum at offset 9). All bytes of a table
# sum to 0 mod 256.
ACPI_HEADER = 36  # sizeof(struct acpi_table_header)
ACPI_TABLE_MAX = 1 << 20  # sanity limit for the length field of one table
# SRAT: the 36-byte header and 12 reserved bytes, then the structures. A memory affinity structure (type 1, 40 bytes)
# holds the range's base and length (u64 each) from offset 8 and its flags (u32) at offset 28.
SRAT_HEADER = 48
SRAT_MEMORY, SRAT_MEMORY_LENGTH = 1, 40
SRAT_BASE_OFFSET, SRAT_FLAGS_OFFSET = 8, 28
SRAT_ENABLED, SRAT_HOTPLUGGABLE = 1, 2
# ACPI RSDP: the signature "RSD PTR ", a checksum over the first 20 bytes (ACPI 1.0) and, from revision 2 on, a
# 36-byte structure with the XSDT address at offset 24.
RSDP_SIGNATURE = b"RSD PTR "
RSDP_V1_LENGTH, RSDP_V2_LENGTH = 20, 36
# The BIOS area of a PC guest is shadow RAM inside its RAM block. SeaBIOS puts the RSDP there.
BIOS_AREA = (0xE0000, 0x100000)


class AcpiRam(Protocol):
    """The guest RAM that the functions below read: a `RamBlock` or `GuestRam` of qemu_common, or any like object."""

    size: int

    def read(self, offset: int, length: int) -> bytes:
        """`length` bytes at `offset`, zero-padded where the image has no data."""
        ...


class Rsdp(NamedTuple):
    """An ACPI RSDP found in guest RAM."""

    firmware: str  # "BIOS" (found in the BIOS area: SeaBIOS) or "UEFI" (found elsewhere: OVMF)
    oem: str  # OEM ID
    address: int  # guest-physical address of the RSDP
    root: int  # guest-physical address of the RSDT/XSDT


def _iter_rsdp(data: bytes) -> Iterator[Tuple[int, str, int]]:
    """ACPI RSDPs with a valid checksum on 16-byte boundaries: (offset, OEM ID, RSDT/XSDT address)."""
    for match in re.finditer(re.escape(RSDP_SIGNATURE), data):
        off = match.start()
        if (
            off % 16
            or off + RSDP_V2_LENGTH > len(data)
            or sum(data[off : off + RSDP_V1_LENGTH]) & 0xFF
        ):
            continue
        oem = data[off + 9 : off + 15].decode("ascii", "replace").strip()
        revision, rsdt = data[off + 15], struct.unpack_from("<I", data, off + 16)[0]
        xsdt = struct.unpack_from("<Q", data, off + 24)[0] if revision >= 2 else 0
        yield off, oem, xsdt or rsdt


def _table_limit(ram: AcpiRam) -> int:
    """The end of the low RAM in which a table address is an offset into it, as far as `ram` reaches."""
    return min(ram.size, PC_LOW_RAM_MAX)


def _read_table(ram: AcpiRam, gpa: int, limit: int) -> Optional[bytes]:
    """The ACPI table at `gpa` if it lies below `limit`, has a sane length and a valid checksum, else None."""
    if not 0 < gpa < limit - ACPI_HEADER:
        return None
    length = struct.unpack_from("<I", ram.read(gpa, ACPI_HEADER), 4)[0]
    if not ACPI_HEADER <= length <= ACPI_TABLE_MAX or gpa + length > limit:
        return None
    data = ram.read(gpa, length)
    return data if sum(data) & 0xFF == 0 else None


def _acpi_table(ram: AcpiRam, root: int, signature: bytes) -> Optional[bytes]:
    """The ACPI table `signature` (such as b"SRAT") listed in the RSDT/XSDT at `root`, read from low RAM."""
    limit = _table_limit(ram)
    root_table = _read_table(ram, root, limit)
    if not root_table or root_table[:4] not in (b"RSDT", b"XSDT"):
        return None
    width = 8 if root_table[:4] == b"XSDT" else 4
    for off in range(ACPI_HEADER, len(root_table) - width + 1, width):
        entry = int.from_bytes(root_table[off : off + width], "little")
        if 0 < entry and entry + 4 <= limit and ram.read(entry, 4) == signature:
            return _read_table(ram, entry, limit)
    return None


def _srat_memory(ram: AcpiRam, root: int) -> List[Tuple[int, int, int]]:
    """Enabled SRAT memory ranges as (base, length, flags); SRAT_HOTPLUGGABLE marks the hotplug region.

    QEMU writes them for every guest with NUMA nodes, and memory hotplug implies NUMA: one or more ranges per node,
    then the whole hotplug region.
    """
    srat = _acpi_table(ram, root, b"SRAT")
    ranges, off = [], SRAT_HEADER
    while srat and off + 2 <= len(srat):
        kind, length = srat[off], srat[off + 1]
        if length < 2:
            break
        if kind == SRAT_MEMORY and length >= SRAT_MEMORY_LENGTH:
            base, size = struct.unpack_from("<QQ", srat, off + SRAT_BASE_OFFSET)
            flags = struct.unpack_from("<I", srat, off + SRAT_FLAGS_OFFSET)[0]
            if flags & SRAT_ENABLED and size:
                ranges.append((base, size, flags))
        off += length
    return ranges


def _bios_rsdp(block: AcpiRam) -> Optional[Rsdp]:
    """The RSDP in the BIOS area, where SeaBIOS puts it."""
    found = next(
        _iter_rsdp(block.read(BIOS_AREA[0], BIOS_AREA[1] - BIOS_AREA[0])), None
    )
    if not found:
        return None
    off, oem, root = found
    return Rsdp("BIOS", oem, BIOS_AREA[0] + off, root)


def _deep_rsdp(block: AcpiRam) -> Optional[Rsdp]:
    """The RSDP of a UEFI guest. OVMF can put it anywhere in RAM, so the whole block is searched.

    An RSDP is accepted only if the RSDT/XSDT it points to is a valid table in the same RAM.

    OVMF allocates its ACPI tables near the top of low RAM: about 0xBF000000 on an i440fx machine with 3 GiB or more,
    0x9F000000 to 0xAF000000 on q35 with 2 to 2.75 GiB. So the machine RAM below `PC_LOW_RAM_MAX` is read from the top
    down, then the rest. Assembled DIMM memory lies at high addresses and is not part of the first part. Each chunk is
    read `RSDP_V2_LENGTH` bytes past its end, so an RSDP that straddles two chunks is found whole. If a guest holds
    several valid RSDPs, such as stale tables from before a firmware reset, the one nearest the top of low RAM wins.
    """
    limit = _table_limit(block)
    # Chunks from `low` down are machine RAM below the PCI hole; chunks from `rest` up are everything else.
    low = min(getattr(block, "machine_size", block.size), PC_LOW_RAM_MAX)
    rest = (low + SCAN_CHUNK - 1) // SCAN_CHUNK * SCAN_CHUNK
    started, read = time.monotonic(), 0

    def scan(base: int) -> Optional[Rsdp]:
        nonlocal read
        data = block.read(base, min(SCAN_CHUNK + RSDP_V2_LENGTH, block.size - base))
        read += len(data)
        for off, oem, table in _iter_rsdp(data):
            if off >= SCAN_CHUNK:
                continue
            root = _read_table(block, table, limit)
            if root and root[:4] in (b"RSDT", b"XSDT"):
                return Rsdp("UEFI", oem, base + off, table)
        return None

    top_down = range((low - 1) // SCAN_CHUNK * SCAN_CHUNK, -1, -SCAN_CHUNK)
    found = None
    for base in itertools.chain(top_down, range(rest, block.size, SCAN_CHUNK)):
        found = scan(base)
        if found:
            break
    vollog.debug(
        f"UEFI RSDP search: {read >> 20} MiB read in {time.monotonic() - started:.1f} s, "
        + (f"found at {found.address:#x}" if found else "none found")
    )
    return found


class QemuAcpi(interfaces.configuration.VersionableInterface):
    """What the QEMU plugins read from a guest's ACPI tables.

    Its version covers the whole module, including `Rsdp` and the constants.
    """

    _required_framework_version = (2, 13, 0)
    _version = (1, 0, 0)

    @classmethod
    def bios_rsdp(cls, block: AcpiRam) -> Optional[Rsdp]:
        """The ACPI RSDP in the BIOS area of a RAM block, or None.

        SeaBIOS puts it there. It must have a valid checksum.

        Args:
            block: A RAM block that may hold a PC guest's low memory (offset = guest-physical address)
        """
        return _bios_rsdp(block)

    @classmethod
    def deep_rsdp(cls, ram: AcpiRam) -> Optional[Rsdp]:
        """The ACPI RSDP of a UEFI guest, searched in the whole RAM.

        Its RSDT/XSDT must be a valid table in the same RAM below PC_LOW_RAM_MAX, where OVMF puts them.

        Args:
            ram: A RAM block, or a guest's assembled RAM. An optional `machine_size` is the machine RAM part, which is
                searched first
        """
        return _deep_rsdp(ram)

    @classmethod
    def machine(cls, ram: AcpiRam, root: int) -> Optional[Tuple[str, str]]:
        """The machine type and the evidence for it from the guest's ACPI tables.

        QEMU generates the tables and both firmwares load them from fw_cfg. q35 has an MCFG table (PCIe memory-mapped
        config space), i440fx has none. A FADT must exist, to show that the table list was read at all. The FADT's PM1a
        event block does not tell the machines apart: it is 0x600 on both.

        Args:
            ram: The guest's RAM
            root: The guest-physical address of the RSDT/XSDT

        Returns:
            ("q35" or "pc", evidence), or None if the tables say nothing
        """
        if _acpi_table(ram, root, b"MCFG"):
            return "q35", "MCFG table"
        if _acpi_table(ram, root, b"FACP"):
            return "pc", "no MCFG table"
        return None

    @classmethod
    def memory_bases(
        cls, ram: AcpiRam, root: int
    ) -> Tuple[Optional[int], Optional[int]]:
        """Where the SRAT puts the RAM above 4 GiB and the hotplug (device memory) region.

        QEMU moves both to 1 TiB on AMD CPUs when the maximum address would reach the HyperTransport hole (for example
        Proxmox `hotplug: memory` with a 4 TiB maximum).

        Args:
            ram: The guest's RAM
            root: The guest-physical address of the RSDT/XSDT

        Returns:
            (base of the lowest enabled non-hotplug range at or above 4 GiB, base of the lowest hotplug range); a base
            is None if there is no SRAT or no such range
        """
        srat = _srat_memory(ram, root)
        high = [
            base
            for base, _size, flags in srat
            if base >= 4 * GIB and not flags & SRAT_HOTPLUGGABLE
        ]
        hotplug = [base for base, _size, flags in srat if flags & SRAT_HOTPLUGGABLE]
        return (min(high) if high else None, min(hotplug) if hotplug else None)
