"""Unit tests for qemu_common and the version requirements of the repo's components (the BTF and kallsyms tests are in test_kernel_btf.py)."""

import importlib
import inspect
import logging
import os
import struct
from types import SimpleNamespace

from volatility3.framework import contexts, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins import qemu_acpi, qemu_common

PAGE = qemu_common.PAGE


# --- qemu_common: one pass over the RAM when dumping ---------------------------------------------------


class CountingLayer:
    """A layer that translates the pages in `mapped`; counts the calls of `mapping`."""

    def __init__(self, mapped):
        self.mapped, self.calls = set(mapped), 0

    def read(self, address, length, pad=False):
        out = bytearray(length)
        for page in self.mapped:
            lo, hi = max(page * PAGE, address), min((page + 1) * PAGE, address + length)
            if lo < hi:
                out[lo - address : hi - address] = b"\x11" * (hi - lo)
        return bytes(out)

    def mapping(self, offset, length, ignore_errors=False):
        self.calls += 1
        for page in range(offset // PAGE, (offset + length) // PAGE):
            if page in self.mapped:
                yield page * PAGE, PAGE, page * PAGE, PAGE, "base"


def test_write_elf_walks_each_chunk_once():
    layer = CountingLayer({0, 3})
    cached = SimpleNamespace(get_content=lambda: b"\xaa" * PAGE)
    block = qemu_common.RamBlock(
        layer, 0, 4 * PAGE, "memfd", lambda off: cached if off == PAGE else None
    )
    ram = qemu_common.GuestRam([block])
    segments = [qemu_common.Segment(0, 0, 4 * PAGE)]
    out = FakeFile()
    missing = qemu_common._write_elf(out, ram, segments)
    assert missing == 1  # page 2: neither mapped nor in the page cache
    layer.calls = 0
    block.read_with_missing(0, 4 * PAGE)
    assert layer.calls == 1
    data, count = block.read_with_missing(0, 4 * PAGE)
    assert (data, count) == (block.read(0, 4 * PAGE), 4 - block.resident_pages())
    assert out.data[-4 * PAGE :] == data


def test_a_cached_page_whose_frame_is_missing_is_missing():
    """`get_content` is None for a page that the cache lists but whose frame the image lacks: it is not read from the
    page cache, so it is counted as missing and listed under a missing reason."""
    layer = CountingLayer({0})
    pages = {
        PAGE: SimpleNamespace(get_content=lambda: b"\xaa" * PAGE),
        2 * PAGE: SimpleNamespace(get_content=lambda: None),
    }
    block = qemu_common.RamBlock(layer, 0, 4 * PAGE, "memfd", pages.get)
    data, missing = block.read_with_missing(0, 4 * PAGE)
    assert missing == 2  # the cached page without frame, and the page not cached at all
    assert data[PAGE : 2 * PAGE] == b"\xaa" * PAGE
    assert data[2 * PAGE : 3 * PAGE] == bytes(PAGE)
    held, reasons = block.residency()
    assert held == 2 == block.resident_pages()
    assert reasons[qemu_common.RAM_RECOVERED] == 1
    assert reasons[qemu_common.FRAME_MISSING] == 1
    assert sum(reasons.values()) == 3


class FakeFile:
    def __init__(self):
        self.data = b""

    def write(self, chunk):
        self.data += chunk


# --- qemu_common: RAM blocks of a NUMA guest -----------------------------------------------------------


def heap_with_records(records):
    """A QEMU heap with a RAMBlock record per (block start, size, id): host, used_length at +24, idstr at +52."""
    heap = bytearray(0x1000)
    for i, (start, size, ident) in enumerate(records):
        at = 0x100 * (i + 1)
        heap[at : at + 8] = struct.pack("<Q", start)
        heap[at + 24 : at + 32] = struct.pack("<Q", size)
        heap[at + 52 : at + 52 + len(ident) + 1] = ident.encode() + b"\0"
    layer = SimpleNamespace(
        read=lambda address, length, pad=False: bytes(heap[address : address + length])
    )
    return layer, [(0, len(heap))]


def test_ramblock_records_name_blocks_by_id_or_by_list():
    size = 16 << 20
    layer, heap = heap_with_records(
        [(0x7F0000000000, size, "node1"), (0x7E0000000000, size, "node0")]
    )
    blocks = [
        qemu_common.RamBlock(layer, a, size, "x")
        for a in (0x7E0000000000, 0x7F0000000000)
    ]
    assert qemu_common._ramblock_records(layer, heap, blocks) == {
        0x7F0000000000: "node1",
        0x7E0000000000: "node0",
    }
    assert qemu_common._ramblock_names(layer, heap, blocks, ["node1", "other"]) == {
        0x7F0000000000: "node1"
    }


def test_assemble_guest_ram_numa_nodes_and_a_dimm_in_command_line_order():
    size = 16 << 20
    starts = {"n1": 0x7F0000000000, "n0": 0x7E0000000000, "d0": 0x7D0000000000}
    layer, heap = heap_with_records([(a, size, name) for name, a in starts.items()])
    blocks = [qemu_common.RamBlock(layer, a, size, "x") for a in starts.values()]
    argv = ["qemu", "-m", "32M"]
    for name in ("n0", "n1"):
        argv += ["-object", f"memory-backend-ram,id={name},size=16M"]
        argv += ["-numa", f"node,memdev={name}"]
    argv += ["-object", "memory-backend-ram,id=d0,size=16M"]
    argv += ["-device", "pc-dimm,id=dimm0,memdev=d0"]
    warnings = []
    ram = qemu_common._assemble_guest_ram(
        blocks[1], blocks, argv, lambda: heap, warnings.append
    )
    assert ram.names == ["n0", "n1", "d0"]
    assert [b.start for b in ram.blocks] == [starts["n0"], starts["n1"], starts["d0"]]
    assert ram.dimm_slots == [(size, 2)] and not warnings
    # a block that is missing: only node 0 is used, and the reason is given
    only_first = qemu_common._assemble_guest_ram(
        blocks[1], blocks[1:2], argv, lambda: heap, warnings.append
    )
    assert only_first.names == ["n0"] and "NUMA node 1" in warnings[-1]


def test_warn_no_guest_counts_the_guest_ram_once(caplog):
    layer = CountingLayer({0, 1})
    block = qemu_common.RamBlock(layer, 0, 4 * PAGE, "x")
    guest = qemu_common.GuestVM(
        1, qemu_common.GuestRam([block]), [qemu_common.Segment(0, 0, 4 * PAGE)], "pc"
    )
    with caplog.at_level(logging.WARNING):
        qemu_common.QemuCommon.warn_no_guest(1, [block], guest)
        walks = layer.calls
        guest.ram.residency()  # what the table row asks for next
    assert layer.calls == walks
    assert "50.0 % not resident" in caplog.text


def detection(monkeypatch, signal, guests=()):
    """`QemuCommon.detect_guests` with the three steps replaced by fakes; returns the calls they got."""
    calls = []
    monkeypatch.setattr(
        qemu_common.QemuCommon,
        "vmm_signal",
        lambda pid, argv, files=None, kvm=False: (
            calls.append(("signal", kvm)) or signal
        ),
    )
    monkeypatch.setattr(
        qemu_common.QemuCommon,
        "find_guests",
        lambda pid, blocks, argv, deep, heaps: (
            calls.append(("find", deep)) or iter(guests)
        ),
    )
    monkeypatch.setattr(
        qemu_common.QemuCommon,
        "unplaced_guest",
        lambda pid, blocks, argv, heaps: calls.append(("unplaced",)) or "placed",
    )
    monkeypatch.setattr(
        qemu_common.QemuCommon,
        "warn_no_guest",
        lambda pid, blocks, guest=None: calls.append(("warn", guest)),
    )
    return calls


def detect(blocks=("b",), kvm=False):
    return qemu_common.QemuCommon.detect_guests(
        1, list(blocks), ["qemu"], list, list, kvm
    )


def test_detect_guests_certain_vmm_without_a_guest_is_unplaced_and_warned(monkeypatch):
    calls = detection(monkeypatch, 2)
    assert detect() == ([], "placed", 2)
    assert calls == [
        ("signal", False),
        ("find", True),
        ("unplaced",),
        ("warn", "placed"),
    ]


def test_detect_guests_leaves_a_weak_signal_or_a_kvm_user_unplaced(monkeypatch):
    calls = detection(monkeypatch, 1)
    assert detect() == ([], None, 1)
    assert ("unplaced",) not in calls
    calls = detection(monkeypatch, 2)
    assert detect(kvm=True) == ([], None, 2)
    assert calls == [("signal", True), ("find", True)]


def test_detect_guests_with_a_guest_or_without_blocks_asks_nothing_more(monkeypatch):
    calls = detection(monkeypatch, 2, guests=["g"])
    assert detect() == (["g"], None, 2)
    assert ("unplaced",) not in calls
    calls = detection(monkeypatch, 2)
    assert detect(blocks=()) == ([], None, 0)
    assert calls == [("find", False)]


# --- qemu_common: why a page is missing (public layer API only) ------------------------------------------


class TranslatingLayer:
    """A process layer that translates nothing; `translate` fails the way the Intel layer does, by page."""

    name = "process"

    def __init__(self, failures):
        self.failures, self.calls = failures, []

    def mapping(self, offset, length, ignore_errors=False):
        return iter(())

    def translate(self, address):
        self.calls.append(address)
        raise self.failures(address)


START = 0x40000000  # aligned to 2 MiB, so that a missing page table covers a whole run


def test_classify_uses_what_translate_raises():
    """translate() raises with the entry for a page that is not present, and with the layer below for a present
    entry whose frame the image lacks; an error in the process layer itself is not classified."""
    failures = {
        0: exceptions.PagedInvalidAddressException("process", START, 12, 0),
        1: exceptions.InvalidAddressException("memory", 0x5000),
        2: exceptions.InvalidAddressException("process", START + 2 * PAGE),
        3: exceptions.PagedInvalidAddressException(
            "process", START + 3 * PAGE, 12, 0x1
        ),
        4: exceptions.PagedInvalidAddressException(
            "process", START + 4 * PAGE, 12, 0x2
        ),
    }
    layer = TranslatingLayer(lambda address: failures[(address - START) // PAGE])
    block = qemu_common.RamBlock(layer, START, 5 * PAGE, "x")
    held, reasons = block.residency()
    assert held == 0
    assert dict(reasons) == {
        "never present": 1,
        qemu_common.FRAME_MISSING: 2,  # a present entry, and the layer below failing
        "unknown": 1,
        "not present (other entry)": 1,
    }


def test_classify_names_each_case():
    cases = [
        (
            exceptions.PagedInvalidAddressException("process", START, 12, 0),
            "never present",
        ),
        (
            exceptions.PagedInvalidAddressException("process", START, 12, 3),
            qemu_common.FRAME_MISSING,
        ),
        (
            exceptions.PagedInvalidAddressException("process", START, 21, 3),
            "page table not in the image",
        ),
        (
            exceptions.PagedInvalidAddressException("process", START, 12, 0x200),
            "not present (other entry)",
        ),
        (
            exceptions.InvalidAddressException("memory", 0x5000),
            qemu_common.FRAME_MISSING,
        ),
        (exceptions.InvalidAddressException("process", START), "unknown"),
    ]
    for failure, reason in cases:
        layer = TranslatingLayer(lambda address, failure=failure: failure)
        block = qemu_common.RamBlock(layer, START, PAGE, "x")
        assert block._classify(0)[0] == reason


def test_classify_not_a_translation_layer_is_unknown():
    block = qemu_common.RamBlock(CountingLayer(set()), START, PAGE, "x")
    assert block._classify(0) == ("unknown", PAGE)


def test_a_missing_page_table_is_classified_once_for_all_its_pages():
    missing_table = exceptions.PagedInvalidAddressException("process", START, 21, 0x1)
    layer = TranslatingLayer(lambda address: missing_table)
    block = qemu_common.RamBlock(layer, START, 1024 * PAGE, "x")
    held, reasons = block.residency()
    assert (held, dict(reasons)) == (0, {"page table not in the image": 1024})
    assert len(layer.calls) == 2  # 1024 pages, 512 per page table


def test_residency_adds_the_reasons_of_all_blocks():
    never = exceptions.PagedInvalidAddressException("process", START, 21, 0)
    blocks = [
        qemu_common.RamBlock(
            TranslatingLayer(lambda address: never), START, 512 * PAGE, "x"
        ),
        qemu_common.RamBlock(
            TranslatingLayer(lambda address: never), START, 256 * PAGE, "x"
        ),
    ]
    held, reasons = qemu_common.GuestRam(blocks).residency()
    assert (held, dict(reasons)) == (0, {"never present": 768})


# --- qemu_common: block picking, virtio-mem warning --------------------------------------------------------


def numa_argv(sizes):
    argv = ["qemu", "-m", "32M"]
    for name, size in sizes.items():
        argv += ["-object", f"memory-backend-ram,id={name},size={size}"]
        argv += ["-numa", f"node,memdev={name}"]
    return argv


def test_equal_sized_numa_nodes_without_records_are_a_warning():
    """No RAMBlock record names the blocks: node 1 is taken by size and address order only, which can swap nodes."""
    size = 16 << 20
    layer, heap = heap_with_records([])
    blocks = [
        qemu_common.RamBlock(layer, a, size, "x")
        for a in (0x7E0000000000, 0x7F0000000000, 0x7D0000000000)
    ]
    warnings = []
    ram = qemu_common._assemble_guest_ram(
        blocks[0],
        blocks,
        numa_argv({"n0": "16M", "n1": "16M"}),
        lambda: heap,
        warnings.append,
    )
    assert len(ram.blocks) == 2
    assert len(warnings) == 1 and "n1" in warnings[0] and "swapped" in warnings[0]


def test_numa_node_found_by_a_unique_size_is_not_a_warning(caplog):
    layer, heap = heap_with_records([])
    blocks = [
        qemu_common.RamBlock(layer, 0x7E0000000000, 16 << 20, "x"),
        qemu_common.RamBlock(layer, 0x7F0000000000, 32 << 20, "x"),
    ]
    warnings = []
    with caplog.at_level(logging.INFO):
        ram = qemu_common._assemble_guest_ram(
            blocks[0],
            blocks,
            numa_argv({"n0": "16M", "n1": "32M"}),
            lambda: heap,
            warnings.append,
        )
    assert len(ram.blocks) == 2 and not warnings
    assert "identified by its size" in caplog.text


class AcpiBlock(qemu_common.RamBlock):
    """A 1 MiB RAM block whose BIOS area holds an RSDP that points to an RSDT (with a FADT) at 0x1000."""

    def __init__(self, start):
        super().__init__(None, start, 1 << 20, "test")
        data = bytearray(1 << 20)
        rsdp = bytearray(36)
        rsdp[0:8], rsdp[9:15] = b"RSD PTR ", b"BOCHS "
        struct.pack_into("<I", rsdp, 16, 0x1000)
        rsdp[8] = -sum(rsdp[:20]) & 0xFF
        data[0xE0000 : 0xE0000 + 36] = rsdp
        for at, table in ((0x1000, rsdt(0x2000)), (0x2000, acpi(b"FACP"))):
            data[at : at + len(table)] = table
        self.data = bytes(data)

    def read(self, offset, length):
        return self.data[offset : offset + length].ljust(length, b"\0")


def acpi(signature, body=b""):
    table = bytearray(signature + bytes(32) + body)
    struct.pack_into("<I", table, 4, len(table))
    table[9] = -sum(table) & 0xFF
    return bytes(table)


def rsdt(*addresses):
    return acpi(b"RSDT", b"".join(struct.pack("<I", a) for a in addresses))


class EmptyBlock(qemu_common.RamBlock):
    def __init__(self):
        super().__init__(None, 0x7E0000000000, 1 << 20, "test")

    def read(self, offset, length):
        return bytes(length)


def find(blocks, argv):
    return list(qemu_common.QemuCommon.find_guests(7, blocks, argv, False, list))


def test_virtio_mem_warning_once_per_process_not_per_guest(caplog):
    argv = [
        "qemu", "-object", "memory-backend-ram,id=v0,size=1G",
        "-device", "virtio-mem-pci,id=vm0,memdev=v0",
    ]  # fmt: skip
    blocks = [AcpiBlock(0x7E0000000000), AcpiBlock(0x7F0000000000)]
    with caplog.at_level(logging.WARNING):
        guests = find(blocks, argv)
    assert len(guests) == 2 and all(g.rsdp.firmware == "BIOS" for g in guests)
    assert [r.getMessage() for r in caplog.records].count(
        "PID 7: virtio-mem on the command line, memdev v0 (1024 MiB): this memory is not rebuilt "
        "(only -m RAM, NUMA nodes and cold-plugged DIMMs are); linux.kvm.VMs / linux.kvm.Slots "
        "place it from the KVM memslots"
    ) == 1


def test_virtio_mem_warning_only_when_a_guest_was_found(caplog):
    argv = [
        "qemu",
        "-object",
        "memory-backend-ram,id=v0,size=1G",
        "-device",
        "virtio-mem-pci,memdev=v0",
    ]
    with caplog.at_level(logging.WARNING):
        assert find([EmptyBlock()], argv) == []
    assert "virtio-mem" not in caplog.text


def test_guest_machine_from_the_command_line_or_the_tables():
    """-machine counts when the command line looks like QEMU's; else the ACPI tables, else the default."""
    block = AcpiBlock(0x7E0000000000)
    ram = qemu_common.GuestRam([block])
    cases = [
        (["qemu", "-m", "1G", "-machine", "q35"], "q35"),  # named and QEMU-like
        (
            ["qemu", "-machine", "q35"],
            "pc",
        ),  # one QEMU option only: the tables say i440fx (FADT, no MCFG)
        ([], "pc"),
    ]
    for argv, machine in cases:
        assert qemu_common.QemuCommon._guest_machine(7, argv, ram, 0x1000) == machine
    empty = qemu_common.GuestRam([EmptyBlock()])
    assert (
        qemu_common.QemuCommon._guest_machine(
            7, ["x", "-machine", "microvm"], empty, 0x1000
        )
        == "microvm"
    )


def test_common_requires_its_two_helpers():
    required = {r.name: r for r in qemu_common.QemuCommon.get_requirements()}
    assert {n: (r._component, r._version) for n, r in required.items()} == {
        "qemu_cmdline": (qemu_common.qemu_cmdline.QemuCmdline, (1, 0, 0)),
        "qemu_acpi": (qemu_acpi.QemuAcpi, (1, 0, 0)),
    }


# --- the components' version requirements ----------------------------------------------------------------


def our_components():
    """(plugin class, requirement) for every VersionRequirement on a component of this repo."""
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "plugins"))
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for name in filenames:
            if not name.endswith(".py") or name == "__init__.py":
                continue
            rel = os.path.relpath(os.path.join(dirpath, name[:-3]), root)
            module = importlib.import_module(
                "volatility3.plugins." + rel.replace(os.sep, ".")
            )
            for _name, cls in inspect.getmembers(module, inspect.isclass):
                if cls.__module__ != module.__name__ or not hasattr(
                    cls, "get_requirements"
                ):
                    continue
                for requirement in cls.get_requirements():
                    if not isinstance(requirement, requirements.VersionRequirement):
                        continue
                    source = inspect.getsourcefile(requirement._component)
                    if source and os.path.abspath(source).startswith(root + os.sep):
                        yield cls, requirement


def test_requirements_on_our_components_are_met_and_name_the_current_major():
    seen = list(our_components())
    assert len(seen) > 20
    context = contexts.Context()
    for cls, requirement in seen:
        component, version = requirement._component, requirement._version
        label = f"{cls.__module__}.{cls.__name__} -> {component.__name__}"
        assert not requirement.unsatisfied(context, "x"), label
        assert version[0] == component._version[0], label
