"""Unit tests for qemu_acpi: RSDP detection (BIOS area and deep search) and the tables behind it, on synthetic RAM."""

import ast
import os
import struct

import pytest
from volatility3.plugins import qemu_acpi

GIB = 1 << 30
CHUNK = qemu_acpi.SCAN_CHUNK


class SparseRam:
    """Guest RAM of `size` bytes that is zeros except for the `pieces` (guest-physical address -> bytes). It is the
    duck type that qemu_acpi reads (`size`, `read`, optionally `machine_size`), without any class of qemu_common."""

    def __init__(self, size, pieces, machine_size=None):
        self.size, self.pieces = size, pieces
        if machine_size is not None:
            self.machine_size = machine_size

    def read(self, offset, length):
        out = bytearray(length)
        for at, data in self.pieces.items():
            lo, hi = max(at, offset), min(at + len(data), offset + length)
            if lo < hi:
                out[lo - offset : hi - offset] = data[lo - at : hi - at]
        return bytes(out)


def acpi_table(signature: bytes, body: bytes = b"", checksum_ok=True) -> bytes:
    """A table with a valid header (signature, length, checksum) and `body` after the 36-byte header."""
    table = bytearray(signature + bytes(32) + body)
    struct.pack_into("<I", table, 4, len(table))
    table[9] = (-sum(table) & 0xFF) if checksum_ok else (-sum(table) + 1) & 0xFF
    return bytes(table)


def rsdp(root: int, revision=2, oem=b"BOCHS ", checksum_ok=True) -> bytes:
    """An RSDP: revision 0 puts `root` in the RSDT field, from revision 2 in the XSDT field."""
    data = bytearray(36)
    data[0:8] = b"RSD PTR "
    data[9:15] = oem
    data[15] = revision
    if revision >= 2:
        struct.pack_into("<Q", data, 24, root)
    else:
        struct.pack_into("<I", data, 16, root)
    data[8] = (-sum(data[:20]) & 0xFF) if checksum_ok else (-sum(data[:20]) + 1) & 0xFF
    return bytes(data)


def memory_affinity(base: int, size: int, flags: int) -> bytes:
    """An SRAT memory affinity structure (type 1, 40 bytes)."""
    return struct.pack("<BBIHQQIIQ", 1, 40, 0, 0, base, size, 0, flags, 0)


def guest_with_tables(tables: dict, size: int = 0x10000) -> SparseRam:
    """A guest of `size` bytes with the tables put at their guest-physical addresses."""
    return SparseRam(size, tables)


def test_the_module_does_not_import_qemu_common():
    """qemu_common imports qemu_acpi, not the other way round (no cycle; the RAM is duck-typed)."""
    tree = ast.parse(open(qemu_acpi.__file__).read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
            imported.update(alias.name for alias in node.names)
    assert not any("qemu_common" in name for name in imported)


# --- _iter_rsdp -----------------------------------------------------------------------------------------


def test_iter_rsdp_cases():
    """(data, expected): signature on a 16-byte boundary, checksum of the first 20 bytes, room for 36 bytes."""
    good = rsdp(0xBF000100)
    legacy = rsdp(0x2000, revision=0, oem=b"SeaBIOS"[:6])
    cases = [
        (bytes(16) + good, [(16, "BOCHS", 0xBF000100)]),
        (bytes(16) + legacy, [(16, "SeaBIO", 0x2000)]),  # revision 0: the RSDT address
        (bytes(8) + good, []),  # not on a 16-byte boundary
        (bytes(16) + rsdp(0x2000, checksum_ok=False), []),
        (bytes(16) + good[:30], []),  # too short for the 36-byte structure
        (good + bytes(12) + legacy, [(0, "BOCHS", 0xBF000100), (48, "SeaBIO", 0x2000)]),
        (bytes(64), []),
    ]
    for data, expected in cases:
        assert list(qemu_acpi._iter_rsdp(data)) == expected


def test_iter_rsdp_prefers_the_xsdt_and_falls_back_to_the_rsdt():
    data = bytearray(rsdp(0, revision=2))
    struct.pack_into("<I", data, 16, 0x1000)  # RSDT address, XSDT address 0
    data[8] = 0
    data[8] = -sum(data[:20]) & 0xFF
    assert [root for _o, _oem, root in qemu_acpi._iter_rsdp(bytes(data))] == [0x1000]


# --- the BIOS area (SeaBIOS) ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "at, expected",
    [
        (0xF52E0, qemu_acpi.Rsdp("BIOS", "BOCHS", 0xF52E0, 0x2000)),
        (0xE0000, qemu_acpi.Rsdp("BIOS", "BOCHS", 0xE0000, 0x2000)),
        (0xF52E8, None),  # misaligned
        (0xDFFF0, None),  # below the BIOS area
        (0x100000, None),  # above it
    ],
)
def test_bios_rsdp(at, expected):
    ram = SparseRam(1 << 21, {at: rsdp(0x2000)})
    assert qemu_acpi.QemuAcpi.bios_rsdp(ram) == expected


# --- the deep search (OVMF) -------------------------------------------------------------------------


def uefi_ram(size, root_at, rsdp_at, table=None, machine_size=None, extra=None):
    """RAM with an RSDP at `rsdp_at` pointing to the XSDT (`table`, default a valid one) at `root_at`."""
    pieces = {rsdp_at: rsdp(root_at), root_at: table or acpi_table(b"XSDT")}
    pieces.update(extra or {})
    return SparseRam(size, pieces, machine_size)


# the case ids say what the guest is: OVMF puts the tables near the top of low RAM
DEEP_CASES = {
    "i440fx 4 GiB (tables at 0xBF...)": (4 * GIB, 0xBF000100, 0xBF000010, 4 * GIB),
    "i440fx 3 GiB (0xBF...)": (3 * GIB, 0xBF000100, 0xBF000010, 3 * GIB),
    "i440fx 3.5 GiB (0xDF...)": (0xE0000000, 0xDF000100, 0xDF000010, 0xE0000000),
    "q35 2.5 GiB (0x9F...)": (0xA0000000, 0x9F000100, 0x9F000010, 0xA0000000),
    "q35 2.75 GiB (0xAF...)": (0xB0000000, 0xAF000100, 0xAF000010, 0xB0000000),
    "q35 8 GiB (below 2 GiB)": (8 * GIB, 0x7F000100, 0x7F000010, 8 * GIB),
    "small guest": (0x20000000, 0x1F000100, 0x1F000010, 0x20000000),
    "rsdp in the DIMM area, root in low RAM": (
        6 * GIB,
        0x1F000100,
        4 * GIB + 0x10,
        2 * GIB,
    ),
}


@pytest.mark.parametrize("case", sorted(DEEP_CASES))
def test_deep_rsdp_finds_the_tables_near_the_top_of_low_ram(case):
    size, root_at, rsdp_at, machine = DEEP_CASES[case]
    ram = uefi_ram(size, root_at, rsdp_at, machine_size=machine)
    found = qemu_acpi.QemuAcpi.deep_rsdp(ram)
    assert found == qemu_acpi.Rsdp("UEFI", "BOCHS", rsdp_at, root_at)


def test_deep_rsdp_without_a_machine_size_takes_the_ram_size():
    ram = uefi_ram(0xC0000000, 0xBF000100, 0xBF000010)
    assert qemu_acpi.QemuAcpi.deep_rsdp(ram).root == 0xBF000100


def test_deep_rsdp_tables_above_every_low_ram_end_are_not_found():
    """The RSDT/XSDT must lie below the highest end of low RAM of any PC machine (0xE0000000)."""
    for root_at in (0xE0000100, 0xF0000100, 3 * GIB + 0x40000100):
        ram = uefi_ram(5 * GIB, root_at, 0x2000)
        assert qemu_acpi.QemuAcpi.deep_rsdp(ram) is None


def test_deep_rsdp_root_table_must_be_a_valid_table():
    """Signature, length and checksum are all checked: a stray RSDP-looking string is not a guest."""
    size = 0xC0000000
    bad_checksum = acpi_table(b"XSDT", checksum_ok=False)
    wrong_signature = acpi_table(b"FACP")
    insane = bytearray(acpi_table(b"XSDT"))
    struct.pack_into("<I", insane, 4, 0xFFFFFFFF)
    short = bytearray(acpi_table(b"XSDT"))
    struct.pack_into("<I", short, 4, 8)
    past_the_ram = acpi_table(b"XSDT", bytes(0x1000))
    cases = [
        (bad_checksum, 0xBF000100),
        (wrong_signature, 0xBF000100),
        (bytes(insane), 0xBF000100),
        (bytes(short), 0xBF000100),
        (past_the_ram, size - 0x100),  # starts in the RAM, ends after it
    ]
    for table, root_at in cases:
        assert (
            qemu_acpi.QemuAcpi.deep_rsdp(uefi_ram(size, root_at, 0xBF000010, table))
            is None
        )


def test_deep_rsdp_accepts_an_rsdt_as_well_as_an_xsdt():
    ram = SparseRam(
        0xC0000000,
        {0xBF000010: rsdp(0xBF000100, revision=0), 0xBF000100: acpi_table(b"RSDT")},
    )
    assert qemu_acpi.QemuAcpi.deep_rsdp(ram) == qemu_acpi.Rsdp(
        "UEFI", "BOCHS", 0xBF000010, 0xBF000100
    )


def test_deep_rsdp_straddling_a_chunk_boundary_is_found_whole():
    at = 0xBF000000 - 16  # its 36 bytes end 20 bytes into the next chunk
    ram = uefi_ram(0xC0000000, 0xBE000100, at)
    assert qemu_acpi.QemuAcpi.deep_rsdp(ram).address == at


def test_deep_rsdp_prefers_the_highest_chunk_over_a_stale_one():
    """Stale tables from before a firmware reset sit lower: the one nearest the top of low RAM wins."""
    stale = {0x1010: rsdp(0x1100), 0x1100: acpi_table(b"XSDT")}
    ram = uefi_ram(0xC0000000, 0xBF000100, 0xBF000010, extra=stale)
    assert qemu_acpi.QemuAcpi.deep_rsdp(ram).address == 0xBF000010


def test_deep_rsdp_nothing_there():
    assert qemu_acpi.QemuAcpi.deep_rsdp(SparseRam(0x10000000, {})) is None


# --- the tables behind the RSDP ---------------------------------------------------------------------


def test_srat_memory_ranges():
    srat = acpi_table(
        b"SRAT",
        bytes(12)
        + memory_affinity(0, 1 << 30, 1)
        + memory_affinity(1 << 40, 1 << 30, 3)
        + memory_affinity(2 << 40, 1 << 30, 0),  # not enabled
    )
    rsdt = acpi_table(b"RSDT", struct.pack("<I", 0x2000))
    ram = guest_with_tables({0x1000: rsdt, 0x2000: srat})
    assert qemu_acpi._srat_memory(ram, 0x1000) == [
        (0, 1 << 30, 1),
        (1 << 40, 1 << 30, 3),
    ]


def test_memory_bases_cases():
    """(SRAT ranges, (high base, hotplug base)): the lowest enabled range at or above 4 GiB, the lowest hotplug one."""
    cases = [
        ([], (None, None)),
        ([(0, 2 * GIB, 1)], (None, None)),
        ([(0, 2 * GIB, 1), (4 * GIB, 2 * GIB, 1)], (4 * GIB, None)),
        (
            [(0, 2 * GIB, 1), (4 * GIB, 2 * GIB, 1), (6 * GIB, GIB, 3)],
            (4 * GIB, 6 * GIB),
        ),
        # AMD HyperTransport hole: RAM above 4 GiB and the hotplug region start at 1 TiB
        (
            [(0, 2 * GIB, 1), (1 << 40, 2 * GIB, 1), (1 << 41, GIB, 3)],
            (1 << 40, 1 << 41),
        ),
        ([(4 * GIB, GIB, 1), (8 * GIB, GIB, 1)], (4 * GIB, None)),
    ]
    for ranges, expected in cases:
        srat = acpi_table(
            b"SRAT", bytes(12) + b"".join(memory_affinity(*r) for r in ranges)
        )
        ram = guest_with_tables(
            {0x1000: acpi_table(b"RSDT", struct.pack("<I", 0x2000)), 0x2000: srat}
        )
        assert qemu_acpi.QemuAcpi.memory_bases(ram, 0x1000) == expected


def test_memory_bases_without_an_srat():
    ram = guest_with_tables({0x1000: acpi_table(b"RSDT", struct.pack("<I", 0x2000))})
    assert qemu_acpi.QemuAcpi.memory_bases(ram, 0x1000) == (None, None)
    assert qemu_acpi.QemuAcpi.memory_bases(ram, 0x8000) == (None, None)


def test_machine_type_from_the_tables():
    def rsdt_for(*tables):
        return acpi_table(b"RSDT", b"".join(struct.pack("<I", at) for at in tables))

    cases = [
        (
            {0x1000: rsdt_for(0x2000), 0x2000: acpi_table(b"MCFG")},
            ("q35", "MCFG table"),
        ),
        (
            {0x1000: rsdt_for(0x2000), 0x2000: acpi_table(b"FACP")},
            ("pc", "no MCFG table"),
        ),
        (
            {
                0x1000: rsdt_for(0x2000, 0x3000),
                0x2000: acpi_table(b"FACP"),
                0x3000: acpi_table(b"MCFG"),
            },
            ("q35", "MCFG table"),
        ),
        (
            {0x1000: rsdt_for(0x2000), 0x2000: acpi_table(b"APIC")},
            None,
        ),  # no FADT: the list was not read
        ({}, None),
    ]
    for tables, expected in cases:
        assert qemu_acpi.QemuAcpi.machine(guest_with_tables(tables), 0x1000) == expected


def test_acpi_table_root_beyond_the_rebuilt_ram_is_not_found():
    """Only NUMA node 0 is assembled: the RSDT of a guest may lie beyond that block, which is not an error."""
    ram = guest_with_tables({})
    assert qemu_acpi._acpi_table(ram, 0x20000, b"SRAT") is None


def test_acpi_table_entry_beyond_the_rebuilt_ram_is_skipped():
    rsdt = acpi_table(b"RSDT", struct.pack("<II", 0x7000_0000, 0x2000))
    ram = guest_with_tables({0x1000: rsdt, 0x2000: acpi_table(b"SRAT")})
    found = qemu_acpi._acpi_table(ram, 0x1000, b"SRAT")
    assert found is not None and found[:4] == b"SRAT"


def test_acpi_table_ending_beyond_the_rebuilt_ram_is_not_found():
    rsdt = acpi_table(b"RSDT", struct.pack("<I", 0xFFF0))
    big = acpi_table(b"SRAT", bytes(0x100))  # starts in the RAM, ends after it
    ram = guest_with_tables({0x1000: rsdt, 0xFFF0: big[:16]})
    assert qemu_acpi._acpi_table(ram, 0x1000, b"SRAT") is None


def test_acpi_tables_above_two_gib_are_read():
    """The limit is the highest end of low RAM (0xE0000000), not 2 GiB: an XSDT at 0xBF000000 lists its tables."""
    xsdt = acpi_table(b"XSDT", struct.pack("<Q", 0xBF001000))
    srat = acpi_table(b"SRAT", bytes(12) + memory_affinity(4 * GIB, GIB, 1))
    ram = SparseRam(4 * GIB, {0xBF000000: xsdt, 0xBF001000: srat})
    assert qemu_acpi._acpi_table(ram, 0xBF000000, b"SRAT") == srat
    assert qemu_acpi.QemuAcpi.memory_bases(ram, 0xBF000000) == (4 * GIB, None)


def test_the_high_limit_is_the_highest_low_ram_end_of_the_pc_machines():
    from volatility3.plugins import qemu_common

    # pc maps RAM below 0xE0000000 whole, so its highest low RAM end is 0xDFFFFFFF
    ends = [
        qemu_common._below_4g(machine, size)
        for machine in ("pc", "q35")
        for size in (1 * GIB, 0xAFFFFFFF, 0xB0000000, 0xDFFFFFFF, 0xE0000000, 16 * GIB)
    ]
    assert max(ends) == qemu_acpi.PC_LOW_RAM_MAX - 1


def test_the_component_is_versioned():
    assert qemu_acpi.QemuAcpi.version == (1, 0, 0)
    assert os.path.basename(qemu_acpi.__file__) == "qemu_acpi.py"
