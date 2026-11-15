# This file is Copyright 2026 Michael Külper and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
#
"""The kernel's own symbol table (kallsyms), decoded from a memory image without a symbol file.

A kernel that serves `/proc/kallsyms` keeps the names and addresses of its functions (and, with CONFIG_KALLSYMS_ALL,
its variables) in .rodata, as arrays that the build tool emits as assembler data. Each starts on an 8-byte boundary:

    offsets        s32[num_syms]   address of each symbol, relative to `relative_base`
    relative_base  u64             address that the offsets refer to
    num_syms       u32
    names          num_syms entries, each a length (1 byte, or 2 bytes when bit 7 of the first is set: low 7
                   bits first, the next 8 bits shifted up by 7) followed by that many token numbers
    markers        u32[ceil(num_syms / 256)]  byte offset into `names` of every 256th entry
    seqs_of_names  u24[num_syms]   (some kernels, 6.0 to 6.7 at least) big-endian, name-sorted order
    token_table    256 NUL-terminated strings
    token_index    u16[256]        offset of each string in the token table

A symbol's text is the token strings of its entry joined; its first character is the `nm` type letter. Up to
Linux 6.7 the arrays are in the order above. From 6.8 on, offsets and relative_base follow token_index instead.
The scan tries both places and checks the result, so it does not depend on a version number.

The offsets come in two kinds. Plain: `address = relative_base + (u32) offset`. With CONFIG_KALLSYMS_ABSOLUTE_PERCPU
(x86-64 kernels up to some 6.x release, whose per-cpu symbols are small absolute numbers): a non-negative offset is the
address itself and a negative one is `relative_base - 1 - offset`. The right reading is the one that gives ascending
addresses, the order the build tool sorts them in.

The tables are found with no symbol to start from, in four steps. Each is a cross-check:

1. The token table has every printable character as a one-character token, so the digits are tokens 0x30..0x39 and
   appear as the byte string `0\\x001\\x00...9\\x00`. On x86-64 the table directly follows the markers, with no NUL in
   front of token 0. The walk back therefore stops at token 1, and the length of token 0 comes from `token_index[1]`.
   A candidate counts only if the whole u16 index after it matches.
2. The markers are a run of u32 (older kernels may use u64) that starts at 0 and rises in plausible steps, in front of
   the token table.
3. A `num_syms` value that fits the marker count counts only if decoding exactly that many names from behind it ends
   where the markers start, and every 256th name begins at the offset the markers give.
4. offsets and relative_base are read from either place and count only if the addresses are sorted and relative_base
   lies in the upper half of the address space.

If a step fails, `KallsymsError` is raised instead of returning a table that only looks right. The caller may add the
kernel's VMCOREINFO symbol addresses (Linux 6.0 and later) as a further check.

The framework's own `symbols.linux.kallsyms` is not used: it needs the tables' addresses from the kernel's symbol table
or from VMCOREINFO and reads them through the kernel's virtual layer. This scan works on the bytes of a physical layer.
"""

import bisect
import re
import struct
from typing import Any, Dict, List, Optional, Tuple

from volatility3.framework import exceptions, interfaces

# A token table as (start, 256 tokens, token_index offset), a markers array as (offset, width, values).
TokenTable = Tuple[int, List[bytes], int]
Markers = Tuple[int, int, List[int]]

_DIGITS = b"".join(bytes([c]) + b"\x00" for c in b"0123456789")
# Token 0x30 is the first digit and token 1 is this many tokens before it.
_DIGIT_TOKEN_DISTANCE = 0x2F
# Longest token string without its NUL. Token 0 is found by trying every length up to this.
_TOKEN_MAX = 64
# The share of offsets that must be in ascending order for a table to count as sorted.
_SORTED_MIN = 0.99
# A zero followed by a first step as u32 or u64: its second byte is 0x01-0x9c, so the regex lets 256..40191 through
# (a step covers 256 names, so it stays in range). `_STEP` then bounds every step, the first one too, to 400..40000.
_MARKER_START = re.compile(
    rb"(?=\x00{4}.[\x01-\x9c]\x00\x00|\x00{8}.[\x01-\x9c]\x00{6})", re.DOTALL
)
_STEP = (400, 40000)
# How far in front of the token table the markers are looked for.
_MARKER_WINDOW = 4 << 20
# The last markers entry covers at most 256 names of at most 80 bytes each, plus slack for padding. This is how far
# below its upper bound `num_syms` is searched for.
_LAST_STRETCH = 256 * 80 + 4096
# The tables, as `Kallsyms.layout` names them. The kernel symbol of each is `kallsyms_<name>`, its VMCOREINFO key
# (Linux 6.0 and later) `SYMBOL(kallsyms_<name>)`.
TABLES = (
    "names",
    "num_syms",
    "token_table",
    "token_index",
    "offsets",
    "relative_base",
    "markers",
)
SYMBOL_PREFIX = "kallsyms_"


class KallsymsError(exceptions.SymbolSpaceError):
    """No kallsyms table was found, or a candidate failed a check (the message says which).

    A `SymbolSpaceError`, because `vol` prints its message, while a bare `VolatilityException` shows only a generic
    "unexpected situation".
    """


def _align8(value: int) -> int:
    return (value + 7) & ~7


def _percpu_address(relative_base: int, offset: int) -> int:
    """The address for a signed offset in a CONFIG_KALLSYMS_ABSOLUTE_PERCPU table."""
    if offset >= 0:
        return offset
    return (relative_base - 1 - offset) & 0xFFFFFFFFFFFFFFFF


def _token_table_at(buf: bytes, hit: int) -> Optional[TokenTable]:
    """The token table whose token 0x30 starts at `hit` as (start, 256 tokens, token_index offset), or None."""
    pos = hit
    # Walk back to token 1 only, because token 0 may have no NUL in front of it.
    for _ in range(_DIGIT_TOKEN_DISTANCE):
        if pos < 2 or buf[pos - 1] != 0:
            return None
        prev = buf.rfind(b"\x00", 0, pos - 1)
        if prev < 0 or pos - 1 - (prev + 1) < 1:
            return None
        pos = prev + 1
    first = pos
    tokens = []  # type: List[bytes]
    end = first
    for _ in range(255):
        nul = buf.find(b"\x00", end)
        if nul < 0 or nul - end > _TOKEN_MAX or nul == end:
            return None
        tokens.append(buf[end:nul])
        end = nul + 1
    # Offsets of tokens 1..255 relative to token 1. Token 0 shifts them by its own length plus the NUL.
    rel = []
    acc = 0
    for tok in tokens:
        rel.append(acc)
        acc += len(tok) + 1
    window = buf[end : end + 16 + 512]
    for len0 in range(2, _TOKEN_MAX + 2):  # token 0 and its NUL
        if (
            first < len0
            or acc + len0 > 0xFFFF
            or b"\x00" in buf[first - len0 : first - 1]
        ):
            continue
        index = struct.pack("<256H", 0, *[len0 + r for r in rel])
        found = window.find(index)
        if found >= 0:
            return first - len0, [buf[first - len0 : first - 1]] + tokens, end + found
    return None


def _find_token_tables(buf: bytes) -> List[TokenTable]:
    found = []
    pos = 0
    while True:
        hit = buf.find(_DIGITS, pos)
        if hit < 0:
            return found
        pos = hit + 1
        table = _token_table_at(buf, hit)
        if table is not None:
            found.append(table)


def _find_markers(buf: bytes, base: int, lo: int, hi: int) -> List[Markers]:
    """Every plausible markers array that starts in [lo, hi), as (offset, width, values)."""
    out = []
    for match in _MARKER_START.finditer(buf, lo, hi):
        start = match.start()
        if (base + start) % 8:
            continue
        width = 4 if buf[start + 4 : start + 8] != b"\x00\x00\x00\x00" else 8
        fmt = "<I" if width == 4 else "<Q"
        values = [0]
        pos = start + width
        while pos + width <= len(buf):
            value = struct.unpack_from(fmt, buf, pos)[0]
            if not _STEP[0] <= value - values[-1] <= _STEP[1]:
                break
            values.append(value)
            pos += width
        if len(values) >= 8:
            out.append((start, width, values))
    return out


def _decode_names(
    buf: bytes, start: int, count: int, limit: int
) -> Optional[Tuple[List[bytes], List[int], int]]:
    """`count` names entries that fit before `limit`: (entries, entry offsets relative to `start`, end), or None."""
    pos = start
    entries = []
    offsets = []
    for _ in range(count):
        if pos >= limit:
            return None
        length = buf[pos]
        header = 1
        if length & 0x80:
            if pos + 1 >= limit:
                return None
            length = (length & 0x7F) | (buf[pos + 1] << 7)
            header = 2
        if length == 0 or pos + header + length > limit:
            return None
        offsets.append(pos - start)
        entries.append(buf[pos + header : pos + header + length])
        pos += header + length
    return entries, offsets, pos


def _sorted_fraction(values: List[int]) -> float:
    ordered = sum(1 for a, b in zip(values, values[1:]) if b >= a)
    return ordered / (max(len(values), 2) - 1)


class Kallsyms:
    """A decoded kallsyms table.

    Attributes:
        symbols: `(runtime address, nm type letter, name)` in table order.
        layout: address of each table (`base` plus the offset in the buffer, so physical if the buffer came from a
            physical layer): `token_table`, `token_index`, `markers`, `names`, `num_syms`, `offsets`,
            `relative_base`. Also `num_syms_value`, `absolute_percpu` (0/1), `seqs_of_names` (0/1) and
            `markers_width` (4 or 8).
    """

    def __init__(
        self, symbols: List[Tuple[int, str, str]], layout: Dict[str, int]
    ) -> None:
        self.symbols = symbols
        self.layout = layout
        self._by_name = {}  # type: Dict[str, List[Tuple[int, str]]]
        for address, kind, name in symbols:
            self._by_name.setdefault(name, []).append((address, kind))
        self._addresses = None  # type: Optional[List[int]]

    def address(self, name: str) -> Optional[int]:
        """The runtime address of a symbol, or None if it is not in the table.

        Args:
            name: The symbol name. If it occurs several times, the first global (upper-case type) entry wins, else the
                first.
        """
        entries = self._by_name.get(name)
        if not entries:
            return None
        for address, kind in entries:
            if kind.isupper():
                return address
        return entries[0][0]

    def size(self, name: str) -> Optional[int]:
        """The distance from a symbol to the next higher symbol address, which bounds an array's length; None if the
        symbol is missing or the highest one.

        Args:
            name: The symbol name, as for `address`
        """
        start = self.address(name)
        if start is None:
            return None
        if self._addresses is None:
            self._addresses = sorted(
                {address for address, _kind, _name in self.symbols}
            )
        index = bisect.bisect_right(self._addresses, start)
        if index >= len(self._addresses):
            return None
        return self._addresses[index] - start


class KallsymsScan(interfaces.configuration.VersionableInterface):
    """Finds and decodes the kernel's kallsyms tables in a buffer or a layer."""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    @classmethod
    def decode(
        cls, buf: bytes, base: int = 0, vmcoreinfo: Optional[Dict[str, Any]] = None
    ) -> Kallsyms:
        """Finds and decodes the kallsyms tables in `buf`; raises `KallsymsError`, naming the last failed check, if none
        passes.

        Args:
            buf: Bytes that contain the kernel image's .rodata, such as a window around the kernel
            base: The address of `buf[0]`; added to the offsets in `Kallsyms.layout`, and fixes the 8-byte alignment
            vmcoreinfo: The parsed VMCOREINFO note (`SYMBOL(kallsyms_names)` etc. as ints, as the framework's
                `VMCoreInfo` gives them). A candidate whose tables are not at the same distances as the kernel's own
                addresses is rejected.
        """
        reason = "no kallsyms token table (digit tokens) found"
        for table in _find_token_tables(buf):
            where = f"token table at {base + table[0]:#x}"
            reason = f"{where}: no markers array before it"
            for marker in _find_markers(
                buf, base, max(0, table[0] - _MARKER_WINDOW), table[0]
            ):
                try:
                    result = cls._try_markers(buf, base, vmcoreinfo, table, marker)
                except KallsymsError as exc:
                    reason = str(exc)
                    continue
                if result is not None:
                    return result
                reason = f"{where}: names and offsets do not fit the markers at {base + marker[0]:#x}"
        raise KallsymsError(reason)

    @classmethod
    def _try_markers(
        cls,
        buf: bytes,
        base: int,
        vmcoreinfo: Optional[Dict[str, Any]],
        table: TokenTable,
        marker: Markers,
    ) -> Optional[Kallsyms]:
        token_start = table[0]
        marker_off, width, markers = marker
        count = len(markers)
        markers_end = marker_off + width * count
        lo, hi = (count - 1) * 256 + 1, count * 256
        # Newer kernels put `seqs_of_names`, 3 bytes per symbol, between the markers and the token table. A gap
        # of that size gives the expected `num_syms`.
        gap = token_start - _align8(markers_end)
        seq_hint = None
        for pad in range(8):
            if gap - pad >= 0 and (gap - pad) % 3 == 0 and lo <= (gap - pad) // 3 <= hi:
                seq_hint = (gap - pad) // 3
                break
        last = markers[-1]
        if marker_off < last + 8:
            return None
        cand = (marker_off - last - 8) & ~7
        floor = max(0, cand - _LAST_STRETCH)
        # Go backward over 8-byte slots for `num_syms`. The names start 8 bytes after it.
        for num_off in range(cand, floor - 1, -8):
            if (base + num_off) % 8 or num_off + 4 > len(buf):
                continue
            num = struct.unpack_from("<I", buf, num_off)[0]
            if not lo <= num <= hi or (seq_hint is not None and seq_hint != num):
                continue
            names_off = num_off + 8
            decoded = _decode_names(buf, names_off, num, marker_off)
            if decoded is None:
                continue
            entries, name_offsets, names_end = decoded
            if _align8(names_end) != marker_off or any(
                name_offsets[k * 256] != markers[k] for k in range(count)
            ):
                continue
            if seq_hint is not None and not cls._seqs_ok(buf, markers_end, num):
                continue
            result = cls._offsets(
                buf, base, table, marker, num_off, entries, seq_hint is not None
            )
            if result is None:
                continue
            cls._check_vmcoreinfo(result, vmcoreinfo)
            return result
        return None

    @staticmethod
    def _seqs_ok(buf: bytes, markers_end: int, num: int) -> bool:
        """`seqs_of_names` holds each symbol index exactly once, as a big-endian 3-byte number."""
        start = _align8(markers_end)
        raw = buf[start : start + 3 * num]
        if len(raw) < 3 * num:
            return False
        seqs = {
            (a << 16) | (b << 8) | c for a, b, c in zip(raw[0::3], raw[1::3], raw[2::3])
        }
        return len(seqs) == num and max(seqs) == num - 1

    @classmethod
    def _offsets(
        cls,
        buf: bytes,
        base: int,
        table: TokenTable,
        marker: Markers,
        num_off: int,
        entries: List[bytes],
        has_seqs: bool,
    ) -> Optional[Kallsyms]:
        token_start, tokens, index_off = table
        marker_off, width, _markers = marker
        num = len(entries)
        # (start of offsets, location of relative_base): before `num_syms` up to 6.7, after `token_index` from 6.8.
        places = []  # type: List[Tuple[int, int]]
        if num_off >= 8 and num_off - 8 >= _align8(4 * num):
            places.append((num_off - 8 - _align8(4 * num), num_off - 8))
        after = _align8(index_off + 512)
        places.append((after, after + _align8(4 * num)))
        for offsets_off, rel_off in places:
            if rel_off + 8 > len(buf) or offsets_off + 4 * num > len(buf):
                continue
            relative_base = struct.unpack_from("<Q", buf, rel_off)[0]
            if relative_base >> 48 != 0xFFFF:
                continue
            offsets = struct.unpack_from(f"<{num}i", buf, offsets_off)
            if _sorted_fraction([o & 0xFFFFFFFF for o in offsets]) >= _SORTED_MIN:
                percpu = False
                addresses = [
                    (relative_base + (o & 0xFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
                    for o in offsets
                ]
            else:
                percpu = True
                addresses = [_percpu_address(relative_base, o) for o in offsets]
                if _sorted_fraction(addresses) < _SORTED_MIN:
                    continue
            symbols = cls._expand(entries, tokens, addresses)
            if symbols is None:
                continue
            layout = {
                "token_table": base + token_start,
                "token_index": base + index_off,
                "markers": base + marker_off,
                "names": base + num_off + 8,
                "num_syms": base + num_off,
                "offsets": base + offsets_off,
                "relative_base": base + rel_off,
                "num_syms_value": num,
                "absolute_percpu": int(percpu),
                "seqs_of_names": int(has_seqs),
                "markers_width": width,
            }
            return Kallsyms(symbols, layout)
        return None

    @staticmethod
    def _expand(
        entries: List[bytes], tokens: List[bytes], addresses: List[int]
    ) -> Optional[List[Tuple[int, str, str]]]:
        symbols = []
        odd = 0
        for entry, address in zip(entries, addresses):
            text = b"".join([tokens[b] for b in entry])
            kind = chr(text[0])
            if not kind.isalpha():
                odd += 1
            symbols.append((address, kind, text[1:].decode("utf-8", "replace")))
        # A wrong table decodes to noise. A real one has a type letter on every entry.
        if odd * 100 > len(symbols):
            return None
        return symbols

    @staticmethod
    def _check_vmcoreinfo(
        result: Kallsyms, vmcoreinfo: Optional[Dict[str, Any]]
    ) -> None:
        if not vmcoreinfo:
            return
        # The framework's `VMCoreInfo` has already parsed every SYMBOL() value to an int.
        pairs = [
            (key, vmcoreinfo[f"SYMBOL({SYMBOL_PREFIX}{key})"])
            for key in TABLES
            if f"SYMBOL({SYMBOL_PREFIX}{key})" in vmcoreinfo
        ]
        if len(pairs) < 2:
            return
        ref_key, ref_virtual = pairs[0]
        for key, virtual in pairs[1:]:
            want = virtual - ref_virtual
            got = result.layout[key] - result.layout[ref_key]
            if want != got:
                raise KallsymsError(
                    f"VMCOREINFO puts {SYMBOL_PREFIX}{key} {want:#x} bytes from {SYMBOL_PREFIX}{ref_key}, the tables found are {got:#x} apart"
                )
