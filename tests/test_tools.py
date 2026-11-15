"""Unit tests for the ISF tools (tools/isf_from_map.py and tools/cmp_isf.py), with small fakes instead of images."""

import base64
import importlib.util
import json
import lzma
import os
import struct
from types import SimpleNamespace

import pytest

TOOLS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools")


def load_script(name):
    """A script of tools/ as a module (they are not a package)."""
    path = os.path.join(TOOLS, name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


isf_from_map = load_script("isf_from_map")
cmp_isf = load_script("cmp_isf")


# --- tools/isf_from_map.py ------------------------------------------------------------------------

BANNER = b"Linux version 6.12.11-tc (gcc) #1 SMP\n"
SYSTEM_MAP = (
    "ffffffff81000000 T _text\n"
    "ffffffff82000000 D init_task\n"
    "ffffffff82100000 R linux_banner\n"
    "ffffffff82200000 B init_top_pgt\n"
)


def isf_raw(**overrides):
    """A tiny dwarf2json output: the four mapped symbols and one that only the rebuild has."""
    base = {"kind": "base", "name": "long"}
    symbols = {
        "init_task": {
            "address": 0xFFFFFFFF82000000,
            "type": {"kind": "struct", "name": "task_struct"},
        },
        "linux_banner": {
            "address": 0xFFFFFFFF82100000,
            "type": {"kind": "array", "count": 4, "subtype": base},
            "constant_data": base64.b64encode(b"rebuilt\x00").decode(),
        },
        "init_top_pgt": {
            "address": 0xFFFFFFFF82200000,
            "type": {"kind": "array", "count": 512, "subtype": base},
        },
        "only_in_the_elf": {"address": 0xFFFFFFFF83000000, "type": base},
    }
    symbols.update(overrides)
    return {"metadata": {}, "symbols": symbols, "user_types": {}, "enums": {}}


@pytest.fixture
def files(tmp_path):
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps(isf_raw()))
    sysmap = tmp_path / "System.map"
    sysmap.write_text(SYSTEM_MAP)
    return SimpleNamespace(
        raw=raw, sysmap=sysmap, out=tmp_path / "out.json.xz", dir=tmp_path
    )


def run_main(files, *extra, raw=None, sysmap=None):
    args = [str(raw or files.raw), str(sysmap or files.sysmap), *extra, str(files.out)]
    return isf_from_map.main(args)


def test_read_map(files):
    syms = isf_from_map.read_map(str(files.sysmap))
    assert syms["init_task"] == 0xFFFFFFFF82000000
    assert len(syms) == 4


def test_read_map_first_name_wins(tmp_path):
    path = tmp_path / "map"
    path.write_text("0000000000000010 T a\n0000000000000020 T a\n\nshort line\n")
    assert isf_from_map.read_map(str(path)) == {"a": 0x10}


def test_read_map_malformed_line(tmp_path):
    path = tmp_path / "map"
    path.write_text("0000000000000010 T a\nxyz T b\n")
    with pytest.raises(ValueError, match="map:2"):
        isf_from_map.read_map(str(path))


def test_build_keeps_only_mapped_symbols_and_sets_banner():
    sysmap = {
        "init_task": 1,
        "linux_banner": 2,
        "init_top_pgt": 3,
    }  # build looks up names only
    isf, kept, dropped = isf_from_map.build(isf_raw(), sysmap, BANNER)
    assert (kept, dropped) == (3, 1)
    assert "only_in_the_elf" not in isf["symbols"]
    assert (
        base64.b64decode(isf["symbols"]["linux_banner"]["constant_data"])
        == BANNER + b"\x00"
    )


def test_problems_missing_void_and_moved():
    sysmap = {
        "init_task": 0xFFFFFFFF82000000,
        "linux_banner": 0xFFFFFFFF82100000,
        "init_top_pgt": 5,
    }
    isf = isf_raw(
        init_task={
            "address": 0xFFFFFFFF82000000,
            "type": {"kind": "base", "name": "void"},
        }
    )
    del isf["symbols"]["linux_banner"]
    found = isf_from_map.problems(isf, sysmap)
    assert any("linux_banner is missing" in line for line in found)
    assert any("init_task is typed void" in line for line in found)
    assert any("init_top_pgt is at" in line for line in found)


def test_main_writes_the_table(files, capsys):
    assert run_main(files, "--banner", BANNER.decode()) == 0
    with lzma.open(files.out, "rt") as handle:
        isf = json.load(handle)
    assert sorted(isf["symbols"]) == ["init_task", "init_top_pgt", "linux_banner"]
    assert "3 kept" in capsys.readouterr().out


def test_main_failed_check_is_status_1(files):
    files.raw.write_text(
        json.dumps(
            isf_raw(
                init_task={
                    "address": 1,
                    "type": {"kind": "struct", "name": "task_struct"},
                }
            )
        )
    )
    assert run_main(files, "--banner", BANNER.decode()) == 1
    assert not files.out.exists()


def test_main_not_json_is_status_2(files, capsys):
    files.raw.write_text("{not json")
    assert run_main(files, "--banner", BANNER.decode()) == 2
    err = capsys.readouterr().err
    assert "not a JSON symbol table" in err and "Traceback" not in err


def test_main_not_a_symbol_table_is_status_2(files, capsys):
    files.raw.write_text("[1, 2]")
    assert run_main(files, "--banner", BANNER.decode()) == 2
    assert "no `symbols` table" in capsys.readouterr().err


def test_main_corrupt_xz_is_status_2(files):
    files.raw.write_bytes(b"\xfd7zXZ\x00 this is not a stream")
    assert run_main(files, "--banner", BANNER.decode()) == 2


def test_main_missing_input_is_status_2(files, capsys):
    assert (
        run_main(files, "--banner", BANNER.decode(), raw=files.dir / "absent.json") == 2
    )
    assert "absent.json" in capsys.readouterr().err


def test_main_malformed_map_is_status_2(files, capsys):
    bad = files.dir / "bad.map"
    bad.write_text("ffffffff82100000 R linux_banner\nzzzz T init_task\n")
    assert run_main(files, "--banner", BANNER.decode(), sysmap=bad) == 2
    assert "bad.map:2" in capsys.readouterr().err


def test_main_not_a_banner_is_status_2(files):
    assert run_main(files, "--banner", "hello") == 2


def elf_with_banner(address, text, banner_at=0x100, truncate=None):
    """A minimal ELF64 with one allocated section at `address` that holds `text` and a NUL."""
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", header, 40, 0x200)  # e_shoff
    struct.pack_into("<HH", header, 58, 64, 1)  # e_shentsize, e_shnum
    section = struct.pack(
        "<IIQQQQ", 0, 1, 0x2, address, banner_at, len(text) + 1
    ) + bytes(24)
    image = bytearray(0x200) + section
    image[0:64] = header
    image[banner_at : banner_at + len(text) + 1] = text + b"\x00"
    return bytes(image[:truncate] if truncate else image)


def test_banner_from_kernel(tmp_path):
    kernel = tmp_path / "vmlinux"
    kernel.write_bytes(elf_with_banner(0xFFFFFFFF82100000, BANNER))
    assert isf_from_map.banner_from_kernel(str(kernel), 0xFFFFFFFF82100000) == BANNER
    with pytest.raises(ValueError, match="no allocated section"):
        isf_from_map.banner_from_kernel(str(kernel), 0x1000)


def test_main_reads_the_banner_from_the_kernel(files, tmp_path):
    kernel = tmp_path / "vmlinux"
    kernel.write_bytes(elf_with_banner(0xFFFFFFFF82100000, BANNER.rstrip(b"\n")))
    assert run_main(files, str(kernel)) == 0


@pytest.mark.parametrize("size", [5, 40, 70, 0x200 + 30])
def test_main_truncated_kernel_is_status_2(files, tmp_path, capsys, size):
    kernel = tmp_path / "vmlinux"
    kernel.write_bytes(elf_with_banner(0xFFFFFFFF82100000, BANNER, truncate=size))
    assert run_main(files, str(kernel)) == 2
    err = capsys.readouterr().err
    assert "cannot read the banner" in err and "Traceback" not in err


def test_elf_sections_rejects_other_files():
    with pytest.raises(ValueError):
        isf_from_map.elf_sections(b"MZ\x00\x00")
    with pytest.raises(ValueError, match="truncated"):
        isf_from_map.elf_sections(b"\x7fELF\x02\x01" + bytes(20))


# --- tools/cmp_isf.py -----------------------------------------------------------------------------


def isf_with(**user_types):
    return {"user_types": user_types, "enums": {}, "symbols": {}}


def struct_type(kind="struct", size=8):
    return {
        "kind": kind,
        "size": size,
        "fields": {"x": {"offset": 0, "type": {"kind": "base", "name": "int"}}},
    }


def test_cmp_type_in_neither_file():
    a, b = isf_with(), isf_with()
    assert cmp_isf.compare_type(a, b, "nope") == ["nope: in neither file"]


def test_cmp_type_only_in_one_file():
    a, b = isf_with(t=struct_type()), isf_with()
    assert cmp_isf.compare_type(a, b, "t") == ["t: only in A"]
    assert cmp_isf.compare_type(b, a, "t") == ["t: only in B"]


def test_cmp_type_kind_mismatch_is_not_a_size_difference():
    a, b = isf_with(t=struct_type("struct")), isf_with(t=struct_type("union"))
    [line] = cmp_isf.compare_type(a, b, "t")
    assert "kind struct vs union" in line
    assert "size" not in line


def test_cmp_type_size_mismatch():
    a, b = isf_with(t=struct_type(size=8)), isf_with(t=struct_type(size=16))
    [line] = cmp_isf.compare_type(a, b, "t")
    assert "size 8 vs 16" in line and "kind" not in line


def test_cmp_type_identical():
    a, b = isf_with(t=struct_type()), isf_with(t=struct_type())
    assert cmp_isf.compare_type(a, b, "t") == []
