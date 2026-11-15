"""Unit tests for the x86 guest-physical memory map of qemu_common: pc and q35, RAM below and above the 4 GiB split."""

import struct

import pytest
from volatility3.plugins import qemu_common

Segment = qemu_common.Segment
MIB, GIB = 1 << 20, 1 << 30
VGA = qemu_common.VGA_HOLE
BIOS = (0xE0000, 0x100000)


# --- _below_4g -------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "machine, ram, below",
    [
        ("pc", 512 * MIB, 512 * MIB),
        ("pc", 2 * GIB, 2 * GIB),
        ("pc", 0xDFFFF000, 0xDFFFF000),  # just under 3.5 GiB: mapped whole
        ("pc", 0xE0000000, 0xC0000000),  # 3.5 GiB: split at 3 GiB
        ("pc", 8 * GIB, 0xC0000000),
        ("q35", 512 * MIB, 512 * MIB),
        ("q35", 0xA0000000, 0xA0000000),  # 2.5 GiB: whole
        ("q35", 0xAFFFF000, 0xAFFFF000),
        ("q35", 0xB0000000, 0x80000000),  # 2.75 GiB: split at 2 GiB
        ("q35", 8 * GIB, 0x80000000),
        ("microvm", 8 * GIB, 0xC0000000),  # any other name takes the i440fx rules
    ],
)
def test_below_4g(machine, ram, below):
    assert qemu_common._below_4g(machine, ram) == below


# --- _x86_memory_map ---------------------------------------------------------------------------------------


def seg(guest, offset, length):
    return Segment(guest, offset, length)


MAP_CASES = {
    "pc 1 GiB, SeaBIOS": (
        ("pc", GIB, False, 4 * GIB),
        [seg(0, 0, 0xA0000), seg(0xC0000, 0xC0000, GIB - 0xC0000)],
    ),
    "pc 1 GiB, UEFI (BIOS area is ROM)": (
        ("pc", GIB, True, 4 * GIB),
        [
            seg(0, 0, 0xA0000),
            seg(0xC0000, 0xC0000, 0xE0000 - 0xC0000),
            seg(0x100000, 0x100000, GIB - 0x100000),
        ],
    ),
    "pc 4 GiB: 3 GiB below, 1 GiB above 4 GiB": (
        ("pc", 4 * GIB, False, 4 * GIB),
        [
            seg(0, 0, 0xA0000),
            seg(0xC0000, 0xC0000, 0xC0000000 - 0xC0000),
            seg(4 * GIB, 0xC0000000, GIB),
        ],
    ),
    "q35 4 GiB: 2 GiB below, 2 GiB above": (
        ("q35", 4 * GIB, False, 4 * GIB),
        [
            seg(0, 0, 0xA0000),
            seg(0xC0000, 0xC0000, 0x80000000 - 0xC0000),
            seg(4 * GIB, 0x80000000, 2 * GIB),
        ],
    ),
    "q35 2.5 GiB: all below the hole": (
        ("q35", 0xA0000000, False, 4 * GIB),
        [seg(0, 0, 0xA0000), seg(0xC0000, 0xC0000, 0xA0000000 - 0xC0000)],
    ),
    "q35 8 GiB, RAM above 4 GiB moved to 1 TiB (AMD HyperTransport hole)": (
        ("q35", 8 * GIB, False, 1 << 40),
        [
            seg(0, 0, 0xA0000),
            seg(0xC0000, 0xC0000, 0x80000000 - 0xC0000),
            seg(1 << 40, 0x80000000, 6 * GIB),
        ],
    ),
    "q35 8 GiB, UEFI": (
        ("q35", 8 * GIB, True, 4 * GIB),
        [
            seg(0, 0, 0xA0000),
            seg(0xC0000, 0xC0000, 0x20000),
            seg(0x100000, 0x100000, 0x80000000 - 0x100000),
            seg(4 * GIB, 0x80000000, 6 * GIB),
        ],
    ),
    "tiny RAM ends inside the VGA window": (
        ("pc", 0x80000, False, 4 * GIB),
        [seg(0, 0, 0x80000)],
    ),
    "RAM that ends exactly at the VGA window": (
        ("pc", 0xA0000, False, 4 * GIB),
        [seg(0, 0, 0xA0000)],
    ),
}


@pytest.mark.parametrize("case", sorted(MAP_CASES))
def test_x86_memory_map(case):
    args, expected = MAP_CASES[case]
    segments = qemu_common._x86_memory_map(*args)
    assert segments == expected
    # the segments together hold every byte of RAM except the holes, once
    ram = args[1]
    holes = [VGA] + ([BIOS] if args[2] else [])
    lost = sum(max(0, min(ram, end) - start) for start, end in holes)
    assert sum(s.length for s in segments) == ram - lost


# --- _dimm_addresses ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "base, sizes, align, expected",
    [
        (6 * GIB, [], 2 * MIB, []),
        (6 * GIB, [512 * MIB], 2 * MIB, [6 * GIB]),
        (6 * GIB, [512 * MIB, GIB], 2 * MIB, [6 * GIB, 6 * GIB + 512 * MIB]),
        # not a multiple of the alignment: the next DIMM moves up to it
        (4 * GIB, [3 * MIB, MIB], 2 * MIB, [4 * GIB, 4 * GIB + 4 * MIB]),
        (4 * GIB + 1, [MIB], 2 * MIB, [4 * GIB + 2 * MIB]),
        # a backend with 1 GiB pages aligns the DIMMs to 1 GiB
        (4 * GIB, [GIB + 2 * MIB, GIB], GIB, [4 * GIB, 6 * GIB]),
    ],
)
def test_dimm_addresses(base, sizes, align, expected):
    assert qemu_common._dimm_addresses(base, sizes, align) == expected


def test_device_memory_base_is_the_next_gib_after_the_ram_above_4_gib():
    # q35 with 4 GiB: 2 GiB above 4 GiB, so the region starts at 6 GiB; with 5.5 GiB it rounds up to 8 GiB
    assert qemu_common._device_memory_base("q35", 4 * GIB) == 6 * GIB
    assert qemu_common._device_memory_base("q35", 5 * GIB + 512 * MIB) == 8 * GIB
    assert (
        qemu_common._device_memory_base("pc", 2 * GIB) == 4 * GIB
    )  # no RAM above 4 GiB
    assert (
        qemu_common._device_memory_base("q35", 8 * GIB, 1 << 40) == (1 << 40) + 6 * GIB
    )


# --- _guest_segments ---------------------------------------------------------------------------------------


class SparseBlock(qemu_common.RamBlock):
    """A RAM block of `size` bytes that is zeros except for the `pieces` (offset -> bytes)."""

    def __init__(self, size, pieces=None):
        super().__init__(None, 0, size, "test")
        self.pieces = pieces or {}

    def read(self, offset, length):
        out = bytearray(length)
        for at, data in self.pieces.items():
            lo, hi = max(at, offset), min(at + len(data), offset + length)
            if lo < hi:
                out[lo - offset : hi - offset] = data[lo - at : hi - at]
        return bytes(out)


def acpi_table(signature, body=b""):
    table = bytearray(signature + bytes(32) + body)
    struct.pack_into("<I", table, 4, len(table))
    table[9] = -sum(table) & 0xFF
    return bytes(table)


def srat_pieces(*ranges):
    """An RSDT at 0x1000 that lists an SRAT at 0x2000 with the memory ranges (base, size, flags)."""
    memory = b"".join(
        struct.pack("<BBIHQQIIQ", 1, 40, 0, 0, base, size, 0, flags, 0)
        for base, size, flags in ranges
    )
    return {
        0x1000: acpi_table(b"RSDT", struct.pack("<I", 0x2000)),
        0x2000: acpi_table(b"SRAT", bytes(12) + memory),
    }


def guest(machine_size, dimms=(), pieces=None):
    """(GuestRam, dimm sizes): machine RAM and one block per DIMM; a DIMM size 0 stands for a block that was not found."""
    blocks = [SparseBlock(machine_size, pieces)]
    slots = []
    for size in dimms:
        if size < 0:  # a DIMM whose block is missing
            slots.append((-size, None))
        else:
            blocks.append(SparseBlock(size))
            slots.append((size, len(blocks) - 1))
    return qemu_common.GuestRam(blocks, dimm_slots=slots)


def test_guest_segments_without_dimms_is_the_memory_map():
    ram = guest(4 * GIB)
    assert qemu_common._guest_segments("q35", ram) == qemu_common._x86_memory_map(
        "q35", 4 * GIB
    )
    assert qemu_common._guest_segments(
        "pc", ram, uefi=True
    ) == qemu_common._x86_memory_map("pc", 4 * GIB, True)


def test_guest_segments_place_dimms_from_the_device_memory_base():
    ram = guest(4 * GIB, [512 * MIB, GIB])
    segments = qemu_common._guest_segments("q35", ram)
    # RAM above 4 GiB ends at 6 GiB: the DIMMs follow there, in plug order, each from its own block
    assert segments[-2:] == [
        seg(6 * GIB, 4 * GIB, 512 * MIB),
        seg(6 * GIB + 512 * MIB, 4 * GIB + 512 * MIB, GIB),
    ]
    assert segments[:-2] == qemu_common._x86_memory_map("q35", 4 * GIB)


def test_guest_segments_a_missing_dimm_block_still_takes_its_room():
    """A DIMM whose block was not found leaves a gap: the DIMMs after it keep their addresses."""
    ram = guest(4 * GIB, [-(512 * MIB), 256 * MIB])
    segments = qemu_common._guest_segments("q35", ram)
    assert segments[-1] == seg(6 * GIB + 512 * MIB, 4 * GIB, 256 * MIB)
    assert len([s for s in segments if s.guest_phys >= 6 * GIB]) == 1


def test_guest_segments_take_the_bases_from_the_srat():
    """AMD host: RAM above 4 GiB at 1 TiB and the hotplug region at 2 TiB, as the guest's SRAT says."""
    pieces = srat_pieces((0, 2 * GIB, 1), (1 << 40, 2 * GIB, 1), (2 << 40, 64 * GIB, 3))
    ram = guest(4 * GIB, [GIB], pieces)
    segments = qemu_common._guest_segments("q35", ram, acpi_root=0x1000)
    above = [s for s in segments if s.guest_phys >= 4 * GIB]
    assert above == [seg(1 << 40, 0x80000000, 2 * GIB), seg(2 << 40, 4 * GIB, GIB)]


def test_guest_segments_srat_without_a_hotplug_range_uses_the_classic_base():
    pieces = srat_pieces((0, 2 * GIB, 1), (4 * GIB, 2 * GIB, 1))
    ram = guest(4 * GIB, [GIB], pieces)
    above = [
        s
        for s in qemu_common._guest_segments("q35", ram, acpi_root=0x1000)
        if s.guest_phys >= 4 * GIB
    ]
    assert above == [seg(4 * GIB, 0x80000000, 2 * GIB), seg(6 * GIB, 4 * GIB, GIB)]


def test_guest_segments_unreadable_srat_falls_back_to_the_classic_rules():
    ram = guest(4 * GIB, [GIB])  # no tables at all
    assert qemu_common._guest_segments("q35", ram, acpi_root=0x1000)[-1] == seg(
        6 * GIB, 4 * GIB, GIB
    )
