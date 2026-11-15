"""Unpack the ELF vmlinux from a bzImage (gzip, xz or zstd payload).

    extract_vmlinux.py BZIMAGE OUT

A zstd payload can only be unpacked with Python 3.14 or later (`compression.zstd`); with an older Python the script
says so when the kernel has one, instead of reporting that no payload was found.
"""

import lzma
import sys
import zlib
from typing import Optional

try:
    from compression import zstd
except ImportError:  # Python before 3.14
    zstd = None

MAGICS = [
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x1f\x8b\x08", "gzip"),
]


def main() -> Optional[str]:
    """Writes the ELF; returns None, or the error message (which `sys.exit` prints and turns into status 1)."""
    data = open(sys.argv[1], "rb").read()
    zstd_at = None  # where a zstd stream starts that this Python cannot unpack
    for magic, kind in MAGICS:
        i = data.find(magic)
        while i != -1:
            if kind == "zstd" and zstd is None:
                if zstd_at is None:
                    zstd_at = i
                i = data.find(magic, i + 1)
                continue
            try:
                if kind == "zstd":
                    out = zstd.ZstdDecompressor().decompress(data[i:])
                elif kind == "xz":
                    out = lzma.LZMADecompressor().decompress(data[i:])
                else:
                    out = zlib.decompressobj(31).decompress(data[i:])
            except (
                Exception
            ):  # the magic bytes also occur in unrelated data: not a stream
                out = b""
            if out[:4] == b"\x7fELF":
                open(sys.argv[2], "wb").write(out)
                print(kind, "at", hex(i), "->", len(out), "bytes ELF")
                return None
            i = data.find(magic, i + 1)
    if zstd_at is not None:
        return (
            f"no ELF payload found, but the kernel has a zstd stream (at {zstd_at:#x}): unpacking it "
            f"needs Python 3.14 or later (compression.zstd), this is Python {sys.version_info[0]}.{sys.version_info[1]}"
        )
    return "no ELF payload found"


if __name__ == "__main__":
    sys.exit(main())
