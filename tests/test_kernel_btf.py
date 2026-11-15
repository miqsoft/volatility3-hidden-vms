"""Tests for kernel_btf, kallsyms_scan and linux.btf_isf: synthetic BTF, kallsyms tables and memory images."""

import json
import logging
import lzma
import os
import struct
from types import SimpleNamespace

import pytest
from volatility3 import schemas
from volatility3.framework import contexts, exceptions, interfaces
from volatility3.framework.layers import physical
from volatility3.plugins import kallsyms_scan, kernel_btf
from volatility3.plugins.linux import btf_isf

# --- synthetic BTF -------------------------------------------------------------------------------------


def btf_blob(types, base_strings=0):
    """BTF bytes for `types`: (name, kind, vlen, size_or_type, extra[, kind_flag]) per type, IDs from 1.

    `extra` is the bytes after struct btf_type, or for a struct, union or enum a list of members
    `(name, type ID, bit offset)` or enumerators `(name, value)`, whose names go to the string section. With
    `base_strings` the name offsets are those of a split BTF on a base with that many string bytes."""
    strings, body = b"\0", b""

    def offset(name):
        nonlocal strings
        if not name:
            return 0
        found = len(strings) + base_strings
        strings += name.encode() + b"\0"
        return found

    for name, kind, vlen, size, extra, *flag in types:
        head = kernel_btf.TYPE.pack(
            offset(name), kind << 24 | vlen | (flag[0] << 31 if flag else 0), size
        )
        if isinstance(extra, list):
            fmt = "<Ii" if kind == kernel_btf.ENUM else "<III"
            extra = b"".join(
                struct.pack(fmt, offset(item[0]), *item[1:]) for item in extra
            )
        body += head + extra
    header = kernel_btf.HEADER.pack(
        kernel_btf.BTF_MAGIC,
        1,
        0,
        kernel_btf.HEADER.size,
        0,
        len(body),
        len(body),
        len(strings),
    )
    return header + body + strings


def kernel_types():
    """The BTF of a small kernel: char, unsigned int, list_head, task_struct (with a bitfield), an enum, a VAR."""
    char = (
        "char",
        kernel_btf.INT,
        0,
        1,
        struct.pack("<I", (kernel_btf.INT_SIGNED | kernel_btf.INT_CHAR) << 24 | 8),
    )
    return [
        char,  # 1
        ("unsigned int", kernel_btf.INT, 0, 4, struct.pack("<I", 32)),  # 2
        (  # 3
            "list_head",
            kernel_btf.STRUCT,
            2,
            16,
            [("next", 4, 0), ("prev", 4, 64)],
        ),
        ("", kernel_btf.PTR, 0, 3, b""),  # 4
        (  # 5: a 3-bit field at bit 36 (kind_flag: the member offset has the bit size in its top byte)
            "task_struct",
            kernel_btf.STRUCT,
            4,
            64,
            [
                ("state", 2, 0),
                ("tasks", 3, 64),
                ("flags", 2, 3 << 24 | 36),
                ("comm", 6, 192),
            ],
            1,
        ),
        ("", kernel_btf.ARRAY, 0, 0, struct.pack("<III", 1, 2, 16)),  # 6
        ("mode", kernel_btf.ENUM, 2, 4, [("MODE_A", 0), ("MODE_B", 1)]),  # 7
        ("pid_t", kernel_btf.TYPEDEF, 0, 2, b""),  # 8
        ("init_task", kernel_btf.VAR, 0, 5, struct.pack("<I", 1)),  # 9
    ]


def test_builder_output_is_a_valid_isf(monkeypatch):
    """The standalone builder's dictionary passes the schema of the ISF format it declares (6.2.0)."""
    pytest.importorskip("jsonschema")
    # the framework records every validated hash in the user's cache directory
    monkeypatch.setattr(schemas, "record_cached_validations", lambda validations: None)
    isf = kernel_btf.IsfBuilder(None, kernel_btf.Btf(btf_blob(kernel_types()))).build()
    assert isf["metadata"]["format"] == "6.2.0"
    assert isf["user_types"]["task_struct"]["fields"]["tasks"]["type"] == {
        "kind": "struct",
        "name": "list_head",
    }
    assert schemas.validate(isf, use_cache=False)


def test_isf_fields_bitfield_array_and_enum():
    isf = kernel_btf.IsfBuilder(None, kernel_btf.Btf(btf_blob(kernel_types()))).build()
    fields = isf["user_types"]["task_struct"]["fields"]
    assert fields["flags"] == {
        "offset": 4,  # unit-aligned: bit 36 of a 4-byte int is in the unit at byte 4
        "type": {
            "kind": "bitfield",
            "bit_position": 4,
            "bit_length": 3,
            "type": {"kind": "base", "name": "unsigned int"},
        },
    }
    assert fields["comm"]["type"] == {
        "kind": "array",
        "count": 16,
        "subtype": {"kind": "base", "name": "char"},
    }
    assert isf["enums"]["mode"]["constants"] == {"MODE_A": 0, "MODE_B": 1}


def test_globals_the_framework_reads_get_a_real_type():
    """`timekeeper_data` (kernels 6.13+) and `tk_core` (older ones) carry what linux.boottime reads."""
    types = [
        ("unsigned int", kernel_btf.INT, 0, 4, struct.pack("<I", 32)),  # 1
        ("timekeeper", kernel_btf.STRUCT, 1, 8, [("xtime_sec", 1, 0)]),  # 2
        ("tk_data", kernel_btf.STRUCT, 1, 8, [("seq", 1, 0)]),  # 3
        ("", kernel_btf.STRUCT, 2, 16, [("seq", 1, 0), ("timekeeper", 2, 64)]),  # 4
        ("", kernel_btf.ENUM, 2, 4, [("TIMEKEEPERS_MAX", 3), ("OTHER", 9)]),  # 5
    ]
    builder = kernel_btf.IsfBuilder(None, kernel_btf.Btf(btf_blob(types)))
    fixed = lambda name: kernel_btf.KernelBtf._fixed_type(builder, None, name)  # noqa: E731
    assert fixed("timekeeper_data") == {
        "kind": "array",
        "count": 3,
        "subtype": {"kind": "struct", "name": "tk_data"},
    }
    assert fixed("timekeeper") == {"kind": "struct", "name": "timekeeper"}
    assert fixed("tk_core") == {"kind": "struct", "name": "unnamed_struct_4"}


# --- the image of a whole kernel ------------------------------------------------------------------------

RELATIVE_BASE = 0xFFFFFFFF81000000
# the kernel image's runtime address of physical address 0 (the kernel is at physical 0x200000)
DELTA = RELATIVE_BASE - 0x200000
BANNER = b"Linux version 6.1.0-test (builder@host) (gcc) #1 SMP\n\0"


def build_kallsyms(count=2000, special=None):
    """The kallsyms tables of a Linux 6.1 kernel with `count` symbols `sym_<n>` (the first is `_text`).

    `special` maps a symbol index to (name, nm type letter); symbol n is at `RELATIVE_BASE + 16 * n`."""
    special = dict(special or {})
    special[0] = ("_text", "T")
    names = [special.get(i, (f"sym_{i}", "T")) for i in range(count)]
    entries, marks, size = [], [], 0
    for i, (name, letter) in enumerate(names):
        text = letter.encode() + name.encode()
        if i % 256 == 0:
            marks.append(size)
        # one token per character: token n is byte n
        entries.append(bytes([len(text)]) + text)
        size += len(entries[-1])
    names_blob = b"".join(entries).ljust((size + 7) & ~7, b"\0")
    tokens = [b"Z"] + [bytes([n]) for n in range(1, 256)]
    token_table = b"".join(t + b"\0" for t in tokens)
    token_index, at = b"", 0
    for token in tokens:
        token_index += struct.pack("<H", at)
        at += len(token) + 1
    offsets = struct.pack(f"<{count}i", *range(0, 16 * count, 16))
    return (
        offsets.ljust((len(offsets) + 7) & ~7, b"\0")
        + struct.pack("<Q", RELATIVE_BASE)
        + struct.pack("<II", count, 0)
        + names_blob
        + struct.pack(f"<{len(marks)}I", *marks).ljust(len(marks) * 4 + 4, b"\0")
        + token_table
        + token_index
    )


def physical_of(index):
    """Physical address of symbol `index` of `build_kallsyms`."""
    return RELATIVE_BASE + 16 * index - DELTA


def memory_image(banner=BANNER, types=None):
    """A physical memory image of a tiny kernel: its kallsyms tables, its BTF and its banner."""
    btf_index, banner_index = 1000, 1500
    special = {
        10: ("init_task", "D"),
        btf_index: ("__start_BTF", "R"),
        banner_index: ("linux_banner", "R"),
    }
    data = bytearray(physical_of(2200))
    tables = build_kallsyms(2100, special)
    data[0x1000 : 0x1000 + len(tables)] = tables
    blob = btf_blob(types or kernel_types())
    start = physical_of(btf_index)
    assert start + len(blob) < physical_of(banner_index)
    data[start : start + len(blob)] = blob
    at = physical_of(banner_index)
    data[at : at + len(banner)] = banner
    return bytes(data)


def context_with(data, name="primary"):
    context = contexts.Context()
    context.add_layer(physical.BufferDataLayer(context, "plugins.test", name, data))
    return context


def run_build(context, tmp_path, **config):
    context.config["plugins.Build.primary"] = "primary"
    for key, value in config.items():
        context.config[f"plugins.Build.{key}"] = value
    plugin = btf_isf.Build(context, "plugins.Build")

    class Handler(interfaces.plugins.FileHandlerInterface):
        def __init__(self, filename):
            super().__init__(filename)
            self.handle = open(tmp_path / filename, "wb")

        def writable(self):
            return True

        def write(self, data):
            return self.handle.write(data)

        def close(self):
            self.handle.close()
            super().close()

    plugin.set_open_method(Handler)
    return list(plugin._generator())


def test_build_writes_a_valid_isf_for_a_synthetic_kernel(tmp_path, monkeypatch):
    rows = run_build(context_with(memory_image()), tmp_path)
    assert len(rows) == 1
    name, banner, types, symbols, btf_at, count, shift = rows[0][1]
    assert name == "6.1.0-test.json.xz"
    assert banner.startswith("Linux version 6.1.0-test")
    assert (types, count, int(shift)) == (2, 2100, 0)
    with lzma.open(tmp_path / name) as handle:
        isf = json.load(handle)
    assert isf["symbols"]["init_task"]["address"] == RELATIVE_BASE + 16 * 10
    # typed from the BTF's variable, not left void
    assert isf["symbols"]["init_task"]["type"] == {
        "kind": "struct",
        "name": "task_struct",
    }
    assert (
        "linux_banner" in isf["symbols"]
        and "constant_data" in isf["symbols"]["linux_banner"]
    )
    assert isf["metadata"]["linux"]["types"][0]["kind"] == "dwarf"
    pytest.importorskip("jsonschema")
    monkeypatch.setattr(schemas, "record_cached_validations", lambda validations: None)
    assert schemas.validate(isf, use_cache=False)


def test_build_names_the_layer_below_the_page_tables(tmp_path):
    """A kernel that was stacked on the physical layer already is scanned through the physical layer."""
    from volatility3.framework.layers import intel

    context = context_with(memory_image())
    context.config["plugins.test.top.memory_layer"] = "primary"
    context.config["plugins.test.top.page_map_offset"] = 0
    top = intel.Intel(context, "plugins.test.top", "top")
    context.add_layer(top)
    context.config["plugins.Build.primary"] = "top"
    plugin = btf_isf.Build(context, "plugins.Build")
    assert plugin._physical_layer() == "primary"


def test_build_without_btf_raises_instead_of_logging(tmp_path, caplog):
    context = context_with(bytes(1 << 16))
    with caplog.at_level(logging.ERROR):
        with pytest.raises(exceptions.VolatilityException, match="no vmlinux BTF"):
            run_build(context, tmp_path)
    assert not caplog.records
    assert not list(tmp_path.iterdir())


def test_build_for_another_release_says_which_one_it_found(tmp_path):
    context = context_with(memory_image())
    with pytest.raises(kernel_btf.BtfError, match="release 5.4.0.*found 6.1.0-test"):
        run_build(context, tmp_path, release="5.4.0")
    assert run_build(context_with(memory_image()), tmp_path, release="6.1.0-test")


# --- choosing among several kernels ------------------------------------------------------------------------


def test_kernel_image_takes_the_requested_release(monkeypatch):
    """A host image can hold guest kernels: `release` picks one; without it the largest BTF wins."""
    candidates = [(0x1000, "big"), (0x2000, "small")]
    releases = {0x1000: "6.1.0-guest", 0x2000: "6.8.0-host"}

    monkeypatch.setattr(
        kernel_btf.KernelBtf,
        "find_vmlinux_btf",
        classmethod(lambda cls, context, layer, progress=None: iter(candidates)),
    )
    monkeypatch.setattr(
        kernel_btf.KernelBtf,
        "_vmcoreinfo",
        classmethod(lambda cls, context, layer, progress=None: {}),
    )

    def locate(cls, context, layer, address, btf, vmcoreinfo, timings):
        banner = f"Linux version {releases[address]} (x) #1\n".encode() + b"\0"
        return kernel_btf.KernelImage(btf, address, None, 0, 0, banner, None, timings)

    monkeypatch.setattr(kernel_btf.KernelBtf, "_locate", classmethod(locate))
    pick = kernel_btf.KernelBtf.kernel_image
    assert pick(None, "p").btf_address == 0x1000
    assert pick(None, "p", release="6.8.0-host").btf_address == 0x2000
    assert pick(None, "p", release="6.8.0-host").release == "6.8.0-host"
    with pytest.raises(kernel_btf.BtfError, match="no kernel of release 4.9.0"):
        pick(None, "p", release="4.9.0")


# --- module BTF, referring to the kernel's symbol table ---------------------------------------------------


def isf_file(directory, isf, name):
    path = directory / name
    path.write_text(json.dumps(isf))
    return path.as_uri()


def test_module_table_refers_to_the_kernel_table_through_table_mapping(
    tmp_path, monkeypatch
):
    from volatility3.framework.symbols import intermed

    monkeypatch.setattr(schemas, "record_cached_validations", lambda validations: None)

    # the kernel's own table has list_head and the types it refers to
    vmlinux = btf_blob(kernel_types()[:4])
    kernel_isf = kernel_btf.IsfBuilder(None, kernel_btf.Btf(vmlinux)).build()
    context = context_with(bytes(4096))
    kernel = intermed.IntermediateSymbolTable(
        context,
        "plugins.kernel",
        "real_kernel",
        isf_file(tmp_path, kernel_isf, "k.json"),
    )
    context.symbol_space.append(kernel)
    context.module("real_kernel", "primary", 0)
    # the module's split BTF, after vmlinux's types: struct holder { struct list_head l; unsigned int n; }
    holder = [("holder", kernel_btf.STRUCT, 2, 24, [("l", 3, 0), ("n", 2, 128)])]
    strings = len(kernel_btf.Btf(vmlinux).strings)
    btf = kernel_btf.Btf(vmlinux, btf_blob(holder, base_strings=strings))
    monkeypatch.setattr(
        kernel_btf.KernelBtf, "module_btf", classmethod(lambda cls, *args: btf)
    )
    # the module's ISF is our own: it is not validated, which would write valid_isf.hashcache, and its temporary
    # directory is gone once the table is made
    directories = []
    real_directory = kernel_btf.tempfile.TemporaryDirectory

    def directory(*args, **kwargs):
        made = real_directory(*args, **kwargs)
        directories.append(made.name)
        return made

    def validated(*args, **kwargs):
        raise AssertionError("the module's ISF must not be validated")

    monkeypatch.setattr(kernel_btf.tempfile, "TemporaryDirectory", directory)
    monkeypatch.setattr(schemas, "validate", validated)
    monkeypatch.setattr(schemas, "record_cached_validations", validated)
    table = kernel_btf.KernelBtf.module_symbol_table(context, "real_kernel", "mod")
    assert len(directories) == 1 and not os.path.exists(directories[0])
    assert not hasattr(context.symbol_space[table], "btf_directory")
    name = kernel_btf.KernelBtf.type_name(context, "real_kernel", table, "holder")
    assert name == table + "!holder"
    # the file says `kernel_symbols!list_head`; the table maps that name to the context's one
    field = context.symbol_space.get_type(name).vol.members["l"][1]
    assert field.vol.type_name == "real_kernel!list_head"
    assert context.symbol_space[table].config["isf_url"].startswith("file:")
    assert kernel_btf.KERNEL_TABLE not in context.symbol_space


# --- names ---------------------------------------------------------------------------------------------------


def test_enums_of_one_name_follow_the_last_id_whatever_the_order():
    # two enums called `mode` (the second is the last one in the BTF): constant `a` = 1, `b` = 2; names "a", "b" at 5, 7
    blob = btf_blob(
        [
            ("mode", kernel_btf.ENUM, 1, 4, struct.pack("<Ii", 6, 1)),
            ("mode", kernel_btf.ENUM, 1, 4, struct.pack("<Ii", 6, 2)),
        ]
    )
    # the strings are "\0mode\0mode\0"; the enumerator names point at the "mode" strings, which is fine here
    for first in (1, 2):
        builder = kernel_btf.IsfBuilder(None, kernel_btf.Btf(blob))
        names = {i: builder.descriptor(i)["name"] for i in (first, 3 - first)}
        assert names == {1: "mode_1", 2: "mode"}
        enums = builder.build()["enums"]
        assert enums["mode"]["constants"] == {"mode": 2}
        assert enums["mode_1"]["constants"] == {"mode": 1}


def test_structs_of_one_name_follow_the_last_id_and_anonymous_ones_their_id():
    struct_type = lambda name: (name, kernel_btf.STRUCT, 0, 4, b"")  # noqa: E731
    blob = btf_blob([struct_type("same"), struct_type("same"), struct_type("")])
    builder = kernel_btf.IsfBuilder(None, kernel_btf.Btf(blob))
    assert builder._unique_name("same", 1, [1, 2], "x") == "same_1"
    assert builder._unique_name("same", 2, [1, 2], "x") == "same"
    assert builder._unique_name("", 3, [], "anon_3") == "anon_3"
    assert builder.descriptor(3)["name"] == "unnamed_struct_3"
    isf = builder.build()
    assert set(isf["user_types"]) == {"same", "same_1", "unnamed_struct_3"}


def test_the_release_comes_from_the_banner_once():
    image = kernel_btf.KernelImage(
        None, 0, None, 0, 0, b"Linux version 6.1.0-54-cloud-amd64 (a) #1\n\0", None, {}
    )
    assert image.release == "6.1.0-54-cloud-amd64"
    assert (
        image.banner_text.startswith("Linux version") and "\0" not in image.banner_text
    )


# --- errors ----------------------------------------------------------------------------------------------------


def test_errors_are_volatility_exceptions():
    assert issubclass(kernel_btf.BtfError, exceptions.VolatilityException)
    assert issubclass(kallsyms_scan.KallsymsError, exceptions.VolatilityException)


def test_truncated_btf_is_a_btf_error():
    with pytest.raises(kernel_btf.BtfError):
        kernel_btf.Btf(b"\x9f\xeb\x01")


class FakeKernel:
    layer_name = "primary"

    def __init__(self, btf):
        self.btf = btf

    def object(self, name, offset, absolute):
        if isinstance(self.btf, Exception):
            raise self.btf
        return self.btf

    def has_symbol(self, name):
        return True

    def object_from_symbol(self, name):
        raise exceptions.InvalidAddressException("primary", 0x1000)


class FakeLayers(dict):
    def __init__(self, error=None):
        super().__init__(primary=SimpleNamespace(read=self.read))
        self.error = error

    def read(self, address, length, pad=False):
        raise self.error


def test_btf_bytes_unreadable_btf_is_a_btf_error():
    context = SimpleNamespace(layers=FakeLayers())
    kernel = FakeKernel(exceptions.InvalidAddressException("primary", 0x1000))
    with pytest.raises(kernel_btf.BtfError):
        kernel_btf._btf_bytes(context, kernel, 0x1000)


def test_btf_bytes_unreadable_data_is_a_btf_error():
    paged = exceptions.PagedInvalidAddressException("primary", 0x2000, 12, 0, "gone")
    context = SimpleNamespace(layers=FakeLayers(paged))
    kernel = FakeKernel(SimpleNamespace(data_size=64, data=0x2000))
    with pytest.raises(kernel_btf.BtfError):
        kernel_btf._btf_bytes(context, kernel, 0x1000)


def test_module_btf_unreadable_vmlinux_btf_is_a_btf_error():
    kernel = FakeKernel(None)
    context = SimpleNamespace(modules={"kernel": kernel}, layers=FakeLayers())
    with pytest.raises(kernel_btf.BtfError):
        kernel_btf.KernelBtf.module_btf(context, "kernel", "kvm")


def test_requirements_are_met_by_the_versions_in_the_repo():
    requirements = kernel_btf.KernelBtf.get_requirements()
    assert {r.name for r in requirements} == {"vmcoreinfo", "kallsyms_scan"}
    context = contexts.Context()
    assert all(not r.unsatisfied(context, "x") for r in requirements)


# --- kallsyms_scan --------------------------------------------------------------------------------------------


def test_kallsyms_decode_synthetic_tables():
    table = kallsyms_scan.KallsymsScan.decode(b"\0" * 64 + build_kallsyms(), 0x1000)
    assert len(table.symbols) == 2000
    assert table.symbols[0] == (RELATIVE_BASE, "T", "_text")
    assert table.address("sym_3") == RELATIVE_BASE + 48
    assert table.size("sym_3") == 16
    assert table.layout["num_syms_value"] == 2000


def test_kallsyms_address_prefers_the_first_global_symbol():
    table = kallsyms_scan.Kallsyms(
        [(5, "t", "x"), (7, "T", "x"), (9, "T", "x"), (11, "d", "y")], {}
    )
    assert table.address("x") == 7
    assert table.address("y") == 11
    assert table.address("missing") is None


def test_kallsyms_scan_has_no_from_layer_and_exports_the_tables():
    assert not hasattr(kallsyms_scan.KallsymsScan, "from_layer")
    assert "token_table" in kallsyms_scan.TABLES
    assert set(kernel_btf.KALLSYMS_ANCHORS) <= set(kallsyms_scan.TABLES)


def test_kallsyms_decode_checks_vmcoreinfo_distances():
    buf = build_kallsyms()
    good = kallsyms_scan.KallsymsScan.decode(buf)
    layout = good.layout
    note = {
        "SYMBOL(kallsyms_names)": 0xFFFFFFFF81800000,
        "SYMBOL(kallsyms_num_syms)": 0xFFFFFFFF81800000
        + layout["num_syms"]
        - layout["names"],
    }
    # ints, as the framework's VMCoreInfo parses every SYMBOL() value
    kallsyms_scan.KallsymsScan.decode(buf, 0, note)
    note["SYMBOL(kallsyms_num_syms)"] += 8
    with pytest.raises(kallsyms_scan.KallsymsError, match="kallsyms_num_syms"):
        kallsyms_scan.KallsymsScan.decode(buf, 0, note)


class NotKallsyms:
    def address(self, name):
        return None


def test_kallsyms_that_ignores_vmcoreinfo_does_not_warn(monkeypatch, caplog):
    """A host image's first VMCOREINFO note may be a guest's: the table is then read without it, at debug level."""
    calls = []

    def decode(buf, base=0, vmcoreinfo=None):
        calls.append(vmcoreinfo)
        if vmcoreinfo:
            raise kallsyms_scan.KallsymsError("not the same distances")
        return NotKallsyms()

    monkeypatch.setattr(kallsyms_scan.KallsymsScan, "decode", staticmethod(decode))
    layer = SimpleNamespace(
        maximum_address=1 << 30, read=lambda address, length, pad=False: bytes(length)
    )
    context = SimpleNamespace(layers={"physical": layer})
    note = {"SYMBOL(kallsyms_names)": 0xFFFFFFFF81800000, "OSRELEASE": "6.1.0"}
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(kernel_btf.BtfError, match="not an x86-64 kernel"):
            kernel_btf.KernelBtf._locate(
                context, "physical", 0x1000, None, note, {"kallsyms": 0.0}
            )
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    # decoded with the note's addresses as numbers, then without it
    assert calls == [{"SYMBOL(kallsyms_names)": 0xFFFFFFFF81800000}, None]


def test_kallsyms_without_vmcoreinfo_fails_once_with_a_btf_error(monkeypatch):
    calls = []

    def decode(buf, base=0, vmcoreinfo=None):
        calls.append(vmcoreinfo)
        raise kallsyms_scan.KallsymsError("no token table")

    monkeypatch.setattr(kallsyms_scan.KallsymsScan, "decode", staticmethod(decode))
    layer = SimpleNamespace(
        maximum_address=1 << 30, read=lambda address, length, pad=False: bytes(length)
    )
    with pytest.raises(kernel_btf.BtfError, match="near the BTF at 0x1000: no token"):
        kernel_btf.KernelBtf._scan_kallsyms(layer, 0x1000, {"OSRELEASE": "6.1.0"})
    assert calls == [None]


class SymbolsAt:
    def __init__(self, **addresses):
        self.addresses = addresses

    def address(self, name):
        return self.addresses.get(name)


def test_vmcoreinfo_of_another_kernel_with_the_same_release_gives_no_shift():
    """A guest that runs the host's distro kernel has the same OSRELEASE: its note must not set the shift."""
    text, uts = kernel_btf.KERNEL_TEXT + 0x2000000, 0xFFFFFFFF82A00000 + 0x2000000
    ks = SymbolsAt(_text=text, init_uts_ns=uts)
    guest = {
        "OSRELEASE": "6.1.0-test",
        "KERNELOFFSET": 0x5000000,
        "SYMBOL(init_uts_ns)": 0xFFFFFFFF82A00000 + 0x5000000,
    }
    host = {
        "OSRELEASE": "6.1.0-test",
        "KERNELOFFSET": 0x2000000,
        "SYMBOL(init_uts_ns)": uts,
    }
    shift = kernel_btf.KernelBtf._kaslr_shift
    # the wrong note first, as in a host image: the shift stays that of `_text`
    assert shift(ks, "6.1.0-test", guest) == 0x2000000
    assert shift(ks, "6.1.0-test", host) == 0x2000000
    # a note of this kernel is trusted: its KERNELOFFSET wins over `_text`, a foreign one still does not
    moved = SymbolsAt(_text=text + 0x1000, init_uts_ns=uts)
    assert shift(moved, "6.1.0-test", guest) == 0x2001000
    assert shift(moved, "6.1.0-test", host) == 0x2000000
    # a note without the symbol is judged by its release only
    assert shift(ks, "6.1.0-test", {"KERNELOFFSET": 0x2000000}) == 0x2000000


# --- the ISF file ----------------------------------------------------------------------------------------------


def test_isf_file_name_is_the_sanitised_release():
    banner = (
        "Linux version 6.1.0-54-cloud-amd64 (debian-kernel@lists.debian.org) #1 SMP"
    )
    assert kernel_btf.KernelBtf.isf_file_name(banner) == "6.1.0-54-cloud-amd64.json.xz"
    odd = "Linux version 6.8.0 rc/1:x (gcc) #1"
    assert kernel_btf.KernelBtf.isf_file_name(odd) == "6.8.0.json.xz"
    odd = "Linux version 5.4.0/x+y~z (gcc) #1"
    assert kernel_btf.KernelBtf.isf_file_name(odd) == "5.4.0_x+y~z.json.xz"


def test_write_isf_streams_compact_json_and_counts_the_bytes(tmp_path):
    isf = {"metadata": {"format": "6.2.0"}, "symbols": {"é": {"address": 1}}}
    path = tmp_path / "x.json.xz"
    with open(path, "wb") as handle:
        size = kernel_btf.KernelBtf.write_isf(isf, handle)
        assert not handle.closed
    assert size == path.stat().st_size
    with lzma.open(path, "rb") as handle:
        raw = handle.read()
    assert raw == json.dumps(isf, separators=(",", ":")).encode()
    assert json.loads(raw) == isf
    fast = tmp_path / "fast.json.xz"
    with open(fast, "wb") as handle:
        kernel_btf.KernelBtf.write_isf(isf, handle, kernel_btf.ISF_XZ_PRESET_TEMPORARY)
    with lzma.open(fast, "rb") as handle:
        assert handle.read() == raw
