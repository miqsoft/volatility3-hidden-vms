#!/usr/bin/env python3
# This file is Copyright 2026 Michael Külper and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
#
"""Makes a usable Volatility symbol table (ISF) for a Linux kernel that has no debug package and no BTF, from a rebuild.

    isf_from_map.py RAW.json[.xz] SYSTEM_MAP KERNEL OUT.json.xz
    isf_from_map.py RAW.json[.xz] SYSTEM_MAP --banner TEXT OUT.json.xz

For a kernel whose vendor publishes the source, the configuration and the System.map but no debug information (Tiny
Core Linux): rebuild the kernel with the published configuration plus DWARF, and run

    dwarf2json linux --elf vmlinux.rebuilt --system-map System.map > RAW.json

The types in RAW.json follow the source, the configuration and the compiler, so they are those of the shipped kernel;
the symbol addresses follow the published System.map, which is the shipped kernel's. What is wrong in RAW.json, and
what this script puts right:

- dwarf2json also writes every ELF symbol that the System.map does not name (about 70,000 of them), with the REBUILT
  kernel's address, which differs from the shipped kernel's wherever the toolchain placed things differently. Only the
  symbols whose name is in the System.map are kept: their addresses are the map's.
- `linux_banner` carries the rebuild's banner (its build host, binutils and date), which no shipped kernel will ever
  match; Volatility finds the table for an image by that string. It is replaced by the shipped kernel's own banner:
  KERNEL is the shipped kernel (the ELF, or a bzImage that is unpacked with extract_vmlinux.py from the same
  directory), and the banner is read from it at the address that System.map gives for `linux_banner`; or it is given
  with --banner (a trailing newline is added if missing, then the NUL that ends the C string).

The result is checked: `init_task`, `linux_banner` and, if the System.map has them, `init_top_pgt` and
`swapper_pg_dir` must be in it and must not be typed void. The output is short: symbols kept and dropped, the banner.
The exit status is 1 if a check fails (nothing is written then), 2 for a usage or input error (a file that cannot be
read or is not what it should be, a truncated kernel), 0 otherwise.
"""

import argparse
import base64
import json
import lzma
import os
import struct
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional, Tuple

REQUIRED = ["init_task", "linux_banner"]
OPTIONAL = ["init_top_pgt", "swapper_pg_dir"]  # checked if the System.map names them
SHF_ALLOC = 0x2
SHT_NOBITS = 8


def read_json(path: str) -> Dict:
    """The dwarf2json output at `path` (.json or .json.xz). Raises ValueError if it is not one."""
    with open(path, "rb") as handle:
        xz = handle.read(6) == b"\xfd7zXZ\x00"
    try:
        with lzma.open(path, "rb") if xz else open(path, "rb") as handle:
            raw = json.loads(handle.read().decode("utf-8"))
    except (ValueError, lzma.LZMAError) as excp:
        raise ValueError(f"{path} is not a JSON symbol table: {excp}") from excp
    if not isinstance(raw, dict) or not isinstance(raw.get("symbols"), dict):
        raise ValueError(f"{path} has no `symbols` table: not dwarf2json output")
    return raw


def read_map(path: str) -> Dict[str, int]:
    """name -> address of the System.map (`ADDRESS TYPE NAME`); the first line wins for a name that occurs twice."""
    syms: Dict[str, int] = {}
    with open(path, encoding="ascii", errors="replace") as handle:
        for number, line in enumerate(handle, 1):
            parts = line.split()
            if len(parts) >= 3:
                try:
                    address = int(parts[0], 16)
                except ValueError:
                    raise ValueError(
                        f"{path}:{number}: not a System.map line: {line.strip()[:60]!r}"
                    ) from None
                syms.setdefault(parts[2], address)
    return syms


def elf_sections(data: bytes) -> List[Tuple[int, int, int]]:
    """(address, file offset, size) of every allocated section of an ELF64 little-endian file that has file contents."""
    if data[:4] != b"\x7fELF" or data[4:6] != b"\x02\x01":
        raise ValueError("not an ELF64 little-endian file")
    try:
        shoff = struct.unpack_from("<Q", data, 40)[0]
        shentsize, shnum = struct.unpack_from("<HH", data, 58)
        if not shoff or not shnum:
            raise ValueError("the ELF file has no section headers")
        sections = []
        for i in range(shnum):
            _name, sh_type, flags, addr, offset, size = struct.unpack_from(
                "<IIQQQQ", data, shoff + i * shentsize
            )
            if flags & SHF_ALLOC and sh_type != SHT_NOBITS and size:
                sections.append((addr, offset, size))
    except struct.error as excp:
        raise ValueError(f"truncated ELF file: {excp}") from excp
    return sections


def banner_from_kernel(path: str, address: int) -> bytes:
    """The NUL-terminated string at `address` of the kernel `path` (an ELF, or a bzImage), without the NUL."""
    with open(path, "rb") as handle:
        data = handle.read()
    if data[:4] != b"\x7fELF":
        here = os.path.dirname(os.path.abspath(__file__))
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "vmlinux")
            result = subprocess.run(
                [sys.executable, os.path.join(here, "extract_vmlinux.py"), path, out],
                capture_output=True,
            )
            if result.returncode:
                raise ValueError(
                    f"{path} is neither an ELF nor a bzImage: {result.stderr.decode().strip()}"
                )
            with open(out, "rb") as handle:
                data = handle.read()
    for addr, offset, size in elf_sections(data):
        if addr <= address < addr + size:
            start = offset + address - addr
            end = data.find(b"\x00", start)
            if end < 0:
                raise ValueError(
                    f"the banner at {address:#x} is cut off (truncated kernel?)"
                )
            return data[start:end]
    raise ValueError(f"address {address:#x} is in no allocated section of the kernel")


def build(raw: Dict, sysmap: Dict[str, int], banner: bytes) -> Tuple[Dict, int, int]:
    """The ISF: `raw` with only the symbols named in `sysmap`, and `banner` (with its NUL) in linux_banner."""
    symbols = raw["symbols"]
    kept = {name: sym for name, sym in symbols.items() if name in sysmap}
    dropped = len(symbols) - len(kept)
    if "linux_banner" in kept:
        kept["linux_banner"]["constant_data"] = base64.b64encode(
            banner + b"\x00"
        ).decode("ascii")
    out = dict(raw)
    out["symbols"] = kept
    return out, len(kept), dropped


def problems(isf: Dict, sysmap: Dict[str, int]) -> List[str]:
    found = []
    for name in REQUIRED + [n for n in OPTIONAL if n in sysmap]:
        sym = isf["symbols"].get(name)
        if sym is None:
            note = "" if name in sysmap else " (and not in the System.map)"
            found.append(f"{name} is missing{note}")
            continue
        kind = sym.get("type") or {}
        if not kind or (kind.get("kind") == "base" and kind.get("name") == "void"):
            found.append(f"{name} is typed void (no DWARF type)")
        if sym.get("address") != sysmap.get(name):
            found.append(
                f"{name} is at {sym.get('address')}, the System.map says {sysmap.get(name)}"
            )
    return found


def run(args: argparse.Namespace) -> int:
    """The work of `main`; input errors are raised as ValueError, struct.error, IndexError or OSError."""
    sysmap = read_map(args.system_map)
    if "linux_banner" not in sysmap:
        print("the System.map has no linux_banner", file=sys.stderr)
        return 2
    if args.banner is not None:
        banner = args.banner.encode("utf-8")
    else:
        try:
            banner = banner_from_kernel(args.kernel, sysmap["linux_banner"])
        except (ValueError, struct.error, IndexError, OSError) as excp:
            print(f"cannot read the banner: {excp}", file=sys.stderr)
            return 2
    if not banner.endswith(b"\n"):
        banner += b"\n"  # the kernel's own string ends with its newline
    if not banner.startswith(b"Linux version "):
        print(f"not a Linux banner: {banner[:60]!r}", file=sys.stderr)
        return 2

    raw = read_json(args.raw)
    isf, kept, dropped = build(raw, sysmap, banner)
    print(
        f"symbols: {kept} kept (named in {os.path.basename(args.system_map)}), "
        f"{dropped} dropped (ELF only, rebuilt addresses)"
    )
    print(f"banner: {banner.decode('utf-8', 'replace')!r}")
    bad = problems(isf, sysmap)
    for text in bad:
        print(f"FAIL  {text}")
    if bad:
        return 1
    print(
        "checked: " + ", ".join(n for n in REQUIRED + OPTIONAL if n in isf["symbols"])
    )
    with lzma.open(args.out, "wt", encoding="utf-8", preset=6) as handle:
        json.dump(isf, handle, separators=(",", ":"))
    print(f"wrote {args.out} ({os.path.getsize(args.out)} bytes)")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument(
        "raw",
        help="dwarf2json output (--elf of the rebuilt kernel, --system-map of the shipped one), .json or .json.xz",
    )
    ap.add_argument("system_map", help="the vendor's System.map of the shipped kernel")
    ap.add_argument(
        "kernel",
        nargs="?",
        help="the shipped kernel: ELF vmlinux or bzImage (not with --banner)",
    )
    ap.add_argument("out", help="output file, name it <release>.json.xz")
    ap.add_argument(
        "--banner",
        help="the shipped kernel's linux_banner text, instead of reading it from KERNEL",
    )
    args = ap.parse_args(argv)
    if (args.banner is None) == (args.kernel is None):
        ap.error("give either KERNEL (the shipped kernel) or --banner TEXT")
    try:
        return run(args)
    except (ValueError, struct.error, IndexError, OSError, lzma.LZMAError) as excp:
        # a bad input file: exit status 1 is for a failed check
        print(f"{ap.prog}: {excp}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
