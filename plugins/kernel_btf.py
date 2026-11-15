# This file is Copyright 2026 Michael Külper and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
#
"""Symbol tables built from the BTF (BPF Type Format, Documentation/bpf/btf.rst) that the kernel keeps in memory.

`KernelBtf.module_symbol_table` reads the BTF of a loaded module and adds it to the context as an ISF symbol table, so
a plugin can read `struct kvm` without a hand-made table. A module's BTF is "split": its type IDs and string offsets
continue after vmlinux's (kernel/bpf/btf.c, btf_parse_module). Structs that the kernel's own symbol table has are
referred to, not copied, so their object classes apply.

`KernelBtf.isf_from_memory` needs no symbol table at all. It finds vmlinux's BTF and the kallsyms (`kallsyms_scan`) in
a physical memory image and builds the kernel's symbol table: types from BTF, addresses from kallsyms.
"""

import base64
import collections
import hashlib
import json
import logging
import lzma
import pathlib
import re
import struct
import tempfile
import time
from typing import (
    Any,
    BinaryIO,
    Callable,
    Dict,
    Iterator,
    List,
    NamedTuple,
    Optional,
    Tuple,
)

from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols import linux as linux_symbols
from volatility3.plugins import kallsyms_scan

vollog = logging.getLogger(__name__)

BTF_MAGIC = 0xEB9F
# magic, version, flags, hdr_len, type_off, type_len, str_off, str_len
HEADER = struct.Struct("<HBBIIIII")
# The start of the header of vmlinux's own BTF: version 1, flags 0, hdr_len 24, type_off 0. It identifies the blob.
HEADER_START = struct.pack("<HBBII", BTF_MAGIC, 1, 0, HEADER.size, 0)
TYPE = struct.Struct("<III")  # name_off, info, size_or_type

# BTF_KIND_* (include/uapi/linux/btf.h)
INT, PTR, ARRAY, STRUCT, UNION, ENUM, FWD, TYPEDEF = range(1, 9)
VOLATILE, CONST, RESTRICT, FUNC, FUNC_PROTO, VAR, DATASEC, FLOAT = range(9, 17)
DECL_TAG, TYPE_TAG, ENUM64 = range(17, 20)
MODIFIERS = (TYPEDEF, VOLATILE, CONST, RESTRICT, TYPE_TAG)
# Bytes that follow `struct btf_type`, per kind: (fixed part, part per `vlen` entry).
EXTRA = {
    INT: (4, 0),
    ARRAY: (12, 0),
    STRUCT: (0, 12),
    UNION: (0, 12),
    ENUM: (0, 8),
    FUNC_PROTO: (0, 8),
    VAR: (4, 0),
    DATASEC: (0, 12),
    DECL_TAG: (4, 0),
    ENUM64: (0, 12),
}
# Kinds whose `size_or_type` word is a type ID (the return type for FUNC_PROTO).
SINGLE_REF = (
    PTR,
    TYPEDEF,
    VOLATILE,
    CONST,
    RESTRICT,
    TYPE_TAG,
    FUNC,
    VAR,
    DECL_TAG,
    FUNC_PROTO,
)
# Kinds with a list of items: (u32 words per item, word with the name offset, word with a type ID).
ITEMS = {
    STRUCT: (3, 0, 1),
    UNION: (3, 0, 1),
    ENUM: (2, 0, None),
    ENUM64: (3, 0, None),
    FUNC_PROTO: (2, 0, 1),
    DATASEC: (3, None, 0),
}
# BTF_INT_ENCODING bits
INT_SIGNED, INT_CHAR, INT_BOOL = 1, 2, 4
BTF_MAX = 256 << 20  # sanity limit: the kernel caps a BTF blob well below this
# x86-64: where the kernel image is mapped, and where an unrandomized kernel has `_text`
KERNEL_MAP = 0xFFFFFFFF80000000
KERNEL_TEXT = 0xFFFFFFFF81000000
# kallsyms type letters of data symbols. The table lists data symbols only with CONFIG_KALLSYMS_ALL.
DATA_LETTERS = "BbDdRrVv"
# The kallsyms tables (names as in `kallsyms_scan.TABLES`) lie next to each other in the kernel image, so each
# gives the address mapping once more.
KALLSYMS_ANCHORS = ("token_table", "names", "markers")
# Bytes before and after the BTF blob that are searched for the kallsyms tables. The linker script puts .BTF last in
# the read-only data (`__end_rodata` is the page after `__stop_BTF`), and kallsyms.S puts the tables into .rodata.
# Before: the first table (`kallsyms_names`) is at most 6.6 MiB before the BTF: Ubuntu 6.8 6.6, Alpine 6.18 4.4,
# Ubuntu 5.15 3.8, Debian 6.1 2.8, Debian 5.10 2.4 MiB. 32 MiB is about 5 times the largest distance seen, to leave
# room for kernels with larger read-only data.
# After: never used, no table lies behind the BTF on any of them; 1 MiB is margin for page alignment.
KALLSYMS_WINDOW = (32 << 20, 1 << 20)
# xz preset for the symbol files `KernelBtf.write_isf` writes: the default, which gives the smallest file among the
# presets that are not much slower.
ISF_XZ_PRESET = 6
# The fast preset, for a symbol file that is built on every run and removed afterwards.
ISF_XZ_PRESET_TEMPORARY = 1
VOID = {"kind": "base", "name": "void"}
# How the ISF of a module's BTF names a type of the kernel's symbol table: `kernel_symbols!list_head`. The context's
# name for that table is unknown when the file is written, so `table_mapping` maps this name to it on loading (as the
# framework's Windows plugins do with `nt_symbols`).
KERNEL_TABLE = "kernel_symbols"


class BtfError(exceptions.SymbolSpaceError):
    """The image has no usable BTF for the request (no BTF in the kernel, module not loaded, type not found).

    A `SymbolSpaceError`, because `vol` prints its message, while a bare `VolatilityException` shows only a generic
    "unexpected situation".
    """


class Btf:
    """One BTF type table: vmlinux's, optionally followed by one module's split BTF."""

    def __init__(self, base: bytes, split: Optional[bytes] = None):
        types, strings = self._sections(base)
        self.raw = base
        self.kinds: List[int] = [0]  # index = type ID; ID 0 is void
        self.names: List[str] = [""]
        # the size, or the referenced type ID for PTR and modifiers
        self.sizes: List[int] = [0]
        self.extra: List[bytes] = [b""]  # the whole record of each type
        self.strings = strings
        self._parse(types)
        # IDs up to here are vmlinux's own types
        self.vmlinux_types = len(self.kinds) - 1
        if split is not None:
            split_types, split_strings = self._sections(split)
            self.strings += split_strings
            self._parse(split_types)

    @classmethod
    def _sections(cls, data: bytes) -> Tuple[bytes, bytes]:
        if len(data) < HEADER.size:
            raise BtfError(f"BTF header truncated ({len(data)} bytes)")
        magic, _version, _flags, hdr_len, type_off, type_len, str_off, str_len = (
            HEADER.unpack_from(data)
        )
        if magic != BTF_MAGIC:
            raise BtfError(f"not BTF (magic {magic:#x})")
        body = data[hdr_len:]
        return body[type_off : type_off + type_len], body[str_off : str_off + str_len]

    def _parse(self, types: bytes) -> None:
        pos = 0
        while pos < len(types):
            if pos + TYPE.size > len(types):
                raise BtfError(f"truncated type record at offset {pos}")
            name_off, info, size = TYPE.unpack_from(types, pos)
            kind, vlen = (info >> 24) & 0x1F, info & 0xFFFF
            fixed, per = EXTRA.get(kind, (0, 0))
            end = pos + TYPE.size + fixed + per * vlen
            if not 0 < kind <= ENUM64 or end > len(types):
                raise BtfError(f"bad type record at offset {pos} (kind {kind})")
            if name_off >= len(self.strings):
                raise BtfError(f"type name outside the string section at offset {pos}")
            self.kinds.append(kind)
            self.names.append(self._string(name_off))
            self.sizes.append(size)
            self.extra.append(types[pos:end])
            pos = end

    def check(self) -> None:
        """Raises `BtfError` unless the table stands on its own.

        Every type ID that a record refers to must be in the table, and every member, parameter and enumerator name
        must be inside the string section. A module's split BTF fails this without its base, which tells it apart
        from vmlinux's own blob.
        """
        count, strings = len(self.kinds), len(self.strings)
        for type_id in range(1, count):
            kind, extra = self.kinds[type_id], self.extra[type_id]
            refs = [self.sizes[type_id]] if kind in SINGLE_REF else []
            if kind == ARRAY:
                refs = struct.unpack_from("<II", extra, TYPE.size)
            elif kind in ITEMS:
                stride, name, ref = ITEMS[kind]
                words = struct.unpack_from(
                    f"<{(len(extra) - TYPE.size) // 4}I", extra, TYPE.size
                )
                if name is not None and any(w >= strings for w in words[name::stride]):
                    raise BtfError(f"type {type_id}: a name is outside the strings")
                if ref is not None:
                    refs += words[ref::stride]
            if any(ref >= count for ref in refs):
                raise BtfError(f"type {type_id} refers to a type outside the table")

    def _string(self, offset: int) -> str:
        end = self.strings.find(b"\0", offset)
        return self.strings[offset:end].decode("ascii", "replace")

    def info(self, type_id: int) -> int:
        """The `info` word of a type: kind (bits 24-28), vlen (bits 0-15) and kind_flag (bit 31)."""
        return TYPE.unpack_from(self.extra[type_id])[1]

    def resolve(self, type_id: int) -> int:
        """Strips typedefs and qualifiers."""
        while self.kinds[type_id] in MODIFIERS:
            type_id = self.sizes[type_id]
        return type_id

    def array(self, type_id: int) -> Tuple[int, int]:
        """(element type, element count) of an array type."""
        elem, _index, count = struct.unpack_from("<III", self.extra[type_id], TYPE.size)
        return elem, count

    def members(self, type_id: int) -> List[Tuple[str, int, int, int]]:
        """(name, bit offset, type, bitfield size or 0) of each member of a struct or union."""
        info = self.info(type_id)
        found = []
        for i in range(info & 0xFFFF):
            name_off, member_type, offset = struct.unpack_from(
                "<III", self.extra[type_id], TYPE.size + 12 * i
            )
            if info >> 31:  # kind_flag: bitfield size in the top 8 bits
                found.append(
                    (
                        self._string(name_off),
                        offset & 0xFFFFFF,
                        member_type,
                        offset >> 24,
                    )
                )
            else:
                found.append((self._string(name_off), offset, member_type, 0))
        return found

    def enumerators(self, type_id: int) -> Dict[str, int]:
        """The constants of an ENUM or ENUM64 type."""
        info, found = self.info(type_id), {}
        signed = bool(info >> 31)
        for i in range(info & 0xFFFF):
            if self.kinds[type_id] == ENUM:
                name_off, value = struct.unpack_from(
                    "<Ii" if signed else "<II", self.extra[type_id], TYPE.size + 8 * i
                )
            else:
                name_off, lo, hi = struct.unpack_from(
                    "<III", self.extra[type_id], TYPE.size + 12 * i
                )
                value = hi << 32 | lo
                if signed and value >> 63:
                    value -= 1 << 64
            found[self._string(name_off)] = value
        return found

    def variables(self) -> Tuple[Dict[Tuple[str, int], int], Dict[str, List[int]]]:
        """The variables of vmlinux's BTF and their types: ({(name, address): type ID}, {name: [type ID]}).

        The first comes from the DATASEC records, where a variable's offset is its link-time address. For a per-cpu
        variable it is the offset in `.data..percpu`, the small number that kallsyms gives. The second comes from
        the VAR records, for kernels whose DATASECs carry no addresses.
        """
        located, by_name = {}, collections.defaultdict(list)
        for type_id, kind in enumerate(self.kinds):
            if kind == VAR:
                by_name[self.names[type_id]].append(self.sizes[type_id])
            elif kind == DATASEC:
                for var, offset, _size in struct.iter_unpack(
                    "<III", self.extra[type_id][TYPE.size :]
                ):
                    located[self.names[var], offset] = self.sizes[var]
        return located, by_name


class IsfBuilder:
    """Turns BTF into an ISF (format 6.2.0) dictionary: a module's split BTF, or all of vmlinux's.

    Module mode (`kernel_table` given): every struct, union and enum of the module's split BTF is defined, with
    everything it refers to. Every enum of the vmlinux BTF is defined too, and so is each named vmlinux struct or
    union that the kernel's symbol table lacks or has with another size. A vmlinux struct or union that the kernel's
    symbol table has with the same size is not defined but referred to as `kernel_symbols!<name>` (see
    `KERNEL_TABLE`). Typedefs and qualifiers are resolved away, because ISF has none.

    Standalone mode (no `kernel_table`, no context needed): every named struct, union and enum is defined, so the
    table stands alone. A typedef gives its name to the struct or union it refers to, as dwarf2json does:
    `typedef struct { ... } pgd_t` is the type `pgd_t`. Of a chain of typedefs the last one names the type
    (`atomic_long_t` is `atomic64_t`). An anonymous type that no typedef names is `unnamed_struct_<ID>` and so on,
    as in btf2json.

    In both modes an anonymous struct or union member is marked `anonymous`, so its members read as members of the
    parent. Of several types that share a name, the last one in the BTF keeps the plain name and the others get
    their type ID appended (dwarf2json and btf2json agree on the last one). `symbols` is filled by the caller.
    """

    def __init__(
        self,
        context: Optional[interfaces.context.ContextInterface],
        btf: Btf,
        kernel_table: Optional[str] = None,
    ):
        self.context, self.btf, self.kernel_table = context, btf, kernel_table
        self.kernel_types = (
            set(context.symbol_space[kernel_table].types) if kernel_table else set()
        )
        self.user_types: Dict[str, Any] = {}
        self.enums: Dict[str, Any] = {}
        self.symbols: Dict[str, Any] = {}
        self.base_types: Dict[str, Any] = {
            "void": {"kind": "void", "size": 0, "signed": False, "endian": "little"},
            "pointer": {"kind": "int", "size": 8, "signed": False, "endian": "little"},
        }
        # (type ID, typedef that names it or "") -> the name in the ISF
        self._names: Dict[Tuple[int, str], str] = {}
        self._todo: collections.deque = collections.deque()
        # (kind, name) -> the IDs of the complete definitions, in type ID order
        self._complete: Dict[Tuple[int, str], List[int]] = {}
        # anonymous enum -> the first typedef that names it
        self._typedefs: Dict[int, str] = {}
        # enum name (or its typedef's) -> the IDs of the enums that have it, in type ID order
        self._enum_ids: Dict[str, List[int]] = {}
        for type_id, kind in enumerate(btf.kinds):
            name = btf.names[type_id]
            if kind in (STRUCT, UNION) and name:
                self._complete.setdefault((kind, name), []).append(type_id)
            elif kind == TYPEDEF and not kernel_table:
                target = btf.resolve(type_id)
                if btf.kinds[target] in (STRUCT, UNION):
                    ids = self._complete.setdefault((btf.kinds[target], name), [])
                    if target not in ids and name != btf.names[target]:
                        ids.append(target)
                elif btf.kinds[target] in (ENUM, ENUM64) and not btf.names[target]:
                    self._typedefs.setdefault(target, name)
        for type_id, kind in enumerate(btf.kinds):
            if kind in (ENUM, ENUM64):
                label = btf.names[type_id] or self._typedefs.get(type_id, "")
                if label:
                    self._enum_ids.setdefault(label, []).append(type_id)

    def named(self, name: str) -> Optional[Tuple[Dict[str, Any], int]]:
        """(type descriptor, size) of a struct, union, typedef'd struct or base type by name, or None.

        Examples are `pgd_t`, `task_struct` and `int`. `{seq,timekeeper}` stands for the anonymous struct with exactly
        those members. The definition itself is left to `build`.
        """
        btf = self.btf
        if name.startswith("{"):
            members = tuple(name.strip("{}").split(","))
            for type_id, kind in enumerate(btf.kinds):
                if kind == STRUCT and not btf.names[type_id]:
                    if tuple(m[0] for m in btf.members(type_id)) == members:
                        return self.descriptor(type_id), btf.sizes[type_id]
            return None
        found = self._complete.get((STRUCT, name)) or self._complete.get((UNION, name))
        if found:
            kind = btf.kinds[found[-1]]
            local = self._struct_name(found[-1], name)
            return {
                "kind": "union" if kind == UNION else "struct",
                "name": local,
            }, btf.sizes[found[-1]]
        for type_id, kind in enumerate(btf.kinds):
            if kind in (INT, FLOAT) and btf.names[type_id] == name:
                return self.descriptor(type_id), btf.sizes[type_id]
        return None

    def enumerator(self, name: str) -> Optional[int]:
        """The value of an enumerator such as `TIMEKEEPERS_MAX`, searched in all enums, or None."""
        btf = self.btf
        for type_id, kind in enumerate(btf.kinds):
            if kind in (ENUM, ENUM64) and name in btf.enumerators(type_id):
                return btf.enumerators(type_id)[name]
        return None

    def build(self) -> Dict[str, Any]:
        """The ISF dictionary: the structs, unions and enums, every type they refer to, and `symbols`."""
        btf = self.btf
        for type_id in range(1, len(btf.kinds)):
            kind = btf.kinds[type_id]
            if kind in (ENUM, ENUM64):
                self._enum_name(type_id)
            elif kind in (STRUCT, UNION) and (
                btf.names[type_id] or type_id > btf.vmlinux_types
            ):
                self._struct_name(type_id)
            elif kind == TYPEDEF and not self.kernel_table:
                if btf.kinds[btf.sizes[type_id]] in (STRUCT, UNION):
                    self._struct_name(btf.sizes[type_id], btf.names[type_id])
        while self._todo:
            self._define(self._todo.popleft())
        return {
            "metadata": {
                "format": "6.2.0",
                "producer": {
                    "name": "volatility3-kernel_btf",
                    "version": ".".join(map(str, KernelBtf.version)),
                },
            },
            "base_types": self.base_types,
            "user_types": self.user_types,
            "enums": self.enums,
            "symbols": self.symbols,
        }

    # --- type references ------------------------------------------------------------------------

    def _resolve(self, type_id: int) -> Tuple[int, str]:
        """Strips typedefs and qualifiers: the type and, in standalone mode, the last typedef on the way."""
        btf, typedef = self.btf, ""
        while btf.kinds[type_id] in MODIFIERS:
            if btf.kinds[type_id] == TYPEDEF and not self.kernel_table:
                typedef = btf.names[type_id]
            type_id = btf.sizes[type_id]
        return type_id, typedef

    def descriptor(self, type_id: int) -> Dict[str, Any]:
        """The ISF type descriptor of a BTF type. What it refers to is defined by `build`."""
        btf = self.btf
        type_id, typedef = self._resolve(type_id)
        kind = btf.kinds[type_id]
        if kind == 0:
            return {"kind": "base", "name": "void"}
        if kind in (INT, FLOAT):
            return {"kind": "base", "name": self._base(type_id)}
        if kind == PTR:
            return {"kind": "pointer", "subtype": self.descriptor(btf.sizes[type_id])}
        if kind == ARRAY:
            elem, count = btf.array(type_id)
            return {"kind": "array", "count": count, "subtype": self.descriptor(elem)}
        if kind in (STRUCT, UNION, FWD):
            union = kind == UNION or (kind == FWD and btf.info(type_id) >> 31)
            return {
                "kind": "union" if union else "struct",
                "name": self._struct_name(type_id, typedef),
            }
        if kind in (ENUM, ENUM64):
            return {"kind": "enum", "name": self._enum_name(type_id)}
        return {"kind": "function"}  # FUNC_PROTO: only ever behind a pointer

    def _base(self, type_id: int) -> str:
        btf = self.btf
        name, size = btf.names[type_id], btf.sizes[type_id]
        if btf.kinds[type_id] == FLOAT:
            entry = {"kind": "float", "size": size, "signed": True}
        else:
            # BTF_INT_ENCODING: bits 24-27 of the word after struct btf_type
            data = struct.unpack_from("<I", btf.extra[type_id], TYPE.size)[0]
            encoding = data >> 24 & 0x0F
            kind = (
                "bool"
                if encoding & INT_BOOL
                else "char"
                if encoding & INT_CHAR
                else "int"
            )
            entry = {"kind": kind, "size": size, "signed": bool(encoding & INT_SIGNED)}
        self.base_types.setdefault(name, dict(entry, endian="little"))
        return name

    def _int_base(self, size: int, signed: bool) -> str:
        """The base type name for an enum of that size, such as 'u32'."""
        name = f"{'s' if signed else 'u'}{size * 8}"
        self.base_types.setdefault(
            name, {"kind": "int", "size": size, "signed": signed, "endian": "little"}
        )
        return name

    @staticmethod
    def _unique_name(label: str, type_id: int, ids: List[int], anonymous: str) -> str:
        """The name of one of the types `ids` that share `label`: the last keeps it, the others get their ID
        appended."""
        if not label:
            return anonymous
        return label if ids[-1:] == [type_id] else f"{label}_{type_id}"

    def _kernel_name(self, name: str) -> str:
        """How the ISF refers to a type of the kernel's own symbol table."""
        return KERNEL_TABLE + constants.BANG + name

    def _struct_name(self, type_id: int, typedef: str = "") -> str:
        btf = self.btf
        name, kind = btf.names[type_id], btf.kinds[type_id]
        typedef = "" if typedef == name else typedef
        if (type_id, typedef) in self._names:
            return self._names[type_id, typedef]
        if kind == FWD:
            union = btf.info(type_id) >> 31
            complete = self._complete.get((UNION if union else STRUCT, name))
            if complete:
                local = self._struct_name(complete[-1])
            elif name in self.kernel_types:
                local = self._kernel_name(name)
            else:
                local = name  # opaque: a pointer to it cannot be followed
            self._names[type_id, typedef] = local
            return local
        if (
            name
            and type_id <= btf.vmlinux_types
            and name in self.kernel_types
            and self.context.symbol_space.get_type(
                self.kernel_table + constants.BANG + name
            ).size
            == btf.sizes[type_id]
        ):
            local = self._kernel_name(name)
        else:
            label = typedef or name
            if self.kernel_table:
                anonymous = f"anon_{type_id}"
            else:
                anonymous = (
                    f"unnamed_{'union' if kind == UNION else 'struct'}_{type_id}"
                )
            local = self._unique_name(
                label, type_id, self._complete.get((kind, label), []), anonymous
            )
            self._todo.append((type_id, typedef))
        self._names[type_id, typedef] = local
        return local

    def _enum_name(self, type_id: int) -> str:
        if (type_id, "") in self._names:
            return self._names[type_id, ""]
        btf = self.btf
        name = btf.names[type_id] or self._typedefs.get(type_id, "")
        if self.kernel_table:
            anonymous = f"enum_{type_id}"
        else:
            anonymous = (
                f"unnamed_enum{'64' if btf.kinds[type_id] == ENUM64 else ''}_{type_id}"
            )
        local = self._unique_name(
            name, type_id, self._enum_ids.get(name, []), anonymous
        )
        self._names[type_id, ""] = local
        choices = btf.enumerators(type_id)
        size = btf.sizes[type_id]
        self.enums[local] = {
            "size": size,
            "base": self._int_base(size, bool(btf.info(type_id) >> 31)),
            "constants": choices,
        }
        return local

    def _define(self, key: Tuple[int, str]) -> None:
        btf, (type_id, _typedef) = self.btf, key
        fields: Dict[str, Any] = {}
        for i, (name, bits, member_type, bitfield) in enumerate(btf.members(type_id)):
            resolved = btf.resolve(member_type)
            if not name:
                if btf.kinds[resolved] not in (STRUCT, UNION):
                    continue  # unnamed padding bitfield
                fields[f"unnamed_field_{i}"] = {
                    "offset": bits // 8,
                    "anonymous": True,
                    "type": self.descriptor(member_type),
                }
            elif bitfield:
                unit = btf.sizes[resolved]  # an INT or ENUM: its size in bytes
                # Volatility reads a bitfield from one storage unit of the declared type, aligned to its size, as
                # dwarf2json writes it. A bitfield of a packed struct that straddles two units would be cut off.
                # None of the ~4400 bitfields of kernels 5.10, 5.15 and 6.8 does.
                offset = bits // (unit * 8) * unit
                fields[name] = {
                    "offset": offset,
                    "type": {
                        "kind": "bitfield",
                        "bit_position": bits - offset * 8,
                        "bit_length": bitfield,
                        "type": self.descriptor(resolved),
                    },
                }
            else:
                fields[name] = {
                    "offset": bits // 8,
                    "type": self.descriptor(member_type),
                }
        self.user_types[self._names[key]] = {
            "kind": "union" if btf.kinds[type_id] == UNION else "struct",
            "size": btf.sizes[type_id],
            "fields": fields,
        }


def _btf_bytes(context, kernel, btf_address: int) -> bytes:
    """The raw BTF (header, types, strings) of the kernel `struct btf` at `btf_address`.

    Raises `BtfError` if it is unreadable.
    """
    try:
        btf = kernel.object("btf", offset=btf_address, absolute=True)
        size = int(btf.data_size)
        if not 0 < size < BTF_MAX:
            raise BtfError(f"implausible BTF size {size}")
        return context.layers[kernel.layer_name].read(int(btf.data), size)
    except exceptions.InvalidAddressException as excp:
        raise BtfError(f"BTF at {btf_address:#x} is not readable: {excp}") from excp


# --- the versioned interface ----------------------------------------------------------------------


class KernelImage(NamedTuple):
    """What `KernelBtf.kernel_image` found in a memory image of an x86-64 kernel."""

    btf: Btf
    btf_address: int  # physical address of the BTF blob
    kallsyms: kallsyms_scan.Kallsyms
    shift: int  # KASLR shift: runtime address - link-time address of the kernel image
    phys_delta: int  # runtime address - physical address, inside the kernel image
    banner: bytes  # `linux_banner`, with its newline and NUL
    # kernel memory: (runtime address, length) -> data
    read: Callable[[int, int], bytes]
    timings: Dict[str, float]  # seconds per step

    @property
    def banner_text(self) -> str:
        """The banner as text, without its newline and NUL."""
        return self.banner.rstrip(b"\0\n").decode("latin-1")

    @property
    def release(self) -> str:
        """The kernel release, the third word of the banner (`6.1.0-54-cloud-amd64`)."""
        return self.banner_text.split(" ")[2]


class _CountingWriter:
    """Passes the bytes written on to a binary file object and counts them."""

    def __init__(self, handle: BinaryIO):
        self._handle = handle
        self.size = 0

    def write(self, data: bytes) -> int:
        self.size += len(data)
        return self._handle.write(data)


class KernelBtf(interfaces.configuration.VersionableInterface):
    """Symbol tables from the BTF the kernel keeps in memory.

    They are built for loaded modules (used by linux.kvm) and, with `isf_from_memory`, for the whole kernel. The version
    covers the whole module, including `Btf`, `IsfBuilder` and `BtfError`: a plugin that uses any of them requires this
    class.
    """

    _required_framework_version = (2, 24, 0)
    _version = (1, 5, 2)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.VersionRequirement(
                name="vmcoreinfo", component=linux_symbols.VMCoreInfo, version=(1, 0, 0)
            ),
            requirements.VersionRequirement(
                name="kallsyms_scan",
                component=kallsyms_scan.KallsymsScan,
                version=(2, 0, 0),
            ),
        ]

    @classmethod
    def module_btf(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        module_name: str,
    ) -> Btf:
        """The BTF of vmlinux plus the split BTF of a loaded module, both read from the image (vmlinux's types first).

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the kernel module on which to operate
            module_name: The loaded module whose BTF is read, e.g. "kvm_amd"

        Raises:
            BtfError: The kernel keeps no module BTF, the module is not loaded, or its BTF is not readable
        """
        kernel = context.modules[kernel_module_name]
        if not kernel.has_symbol("btf_vmlinux") or not kernel.has_symbol("btf_modules"):
            raise BtfError(
                "kernel without BTF (needs CONFIG_DEBUG_INFO_BTF and CONFIG_DEBUG_INFO_BTF_MODULES)"
            )
        try:
            base = _btf_bytes(
                context, kernel, int(kernel.object_from_symbol("btf_vmlinux"))
            )
            head = kernel.object_from_symbol("btf_modules")
            for entry in head.to_list(
                kernel.symbol_table_name + constants.BANG + "btf_module", "list"
            ):
                try:
                    name = entry.module.get_name()
                except exceptions.InvalidAddressException:
                    continue
                if name == module_name:
                    return Btf(base, _btf_bytes(context, kernel, int(entry.btf)))
        except exceptions.InvalidAddressException as excp:
            raise BtfError(f"kernel BTF is not readable: {excp}") from excp
        raise BtfError(f"no BTF for module {module_name} (module not loaded?)")

    @classmethod
    def module_symbol_table(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        module_name: str,
    ) -> str:
        """Adds a symbol table with the types of a loaded module to the context and returns its name.

        A struct of the module is `<table>!<name>`. A vmlinux struct is not copied into the table when the kernel's
        symbol table has it (`type_name` finds it in either).

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the kernel module on which to operate
            module_name: The loaded module whose BTF is read, e.g. "kvm_amd"

        Raises:
            BtfError: The kernel keeps no module BTF, the module is not loaded, or its ISF is not valid
        """
        kernel = context.modules[kernel_module_name]
        btf = cls.module_btf(context, kernel_module_name, module_name)
        isf = IsfBuilder(context, btf, kernel.symbol_table_name).build()
        table_name = context.symbol_space.free_table_name(f"btf_{module_name}")
        config_path = interfaces.configuration.path_join("kernel_btf", table_name)
        # `IntermediateSymbolTable` reads its ISF from a URL, so the dictionary goes to a file. The table has read it
        # in full when it is made, so the directory is removed right after. The ISF is our own, so it is not
        # validated: validation records every ISF it accepts (valid_isf.hashcache) in the user's cache directory.
        with tempfile.TemporaryDirectory(prefix="kernel_btf_") as directory:
            path = pathlib.Path(directory, f"{table_name}.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(isf, handle, separators=(",", ":"))
            try:
                table = intermed.IntermediateSymbolTable(
                    context,
                    config_path,
                    table_name,
                    path.as_uri(),
                    table_mapping={KERNEL_TABLE: kernel.symbol_table_name},
                    validate=False,
                )
            except (exceptions.SymbolSpaceError, KeyError, ValueError) as excp:
                raise BtfError(
                    f"the BTF of module {module_name} gives no valid symbol table: {excp}"
                ) from excp
        context.symbol_space.append(table)
        vollog.debug(
            "%s: %d types, %d enums from the BTF of %s",
            table_name,
            len(isf["user_types"]),
            len(isf["enums"]),
            module_name,
        )
        return table_name

    @classmethod
    def type_name(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        table_name: str,
        name: str,
    ) -> str:
        """The full name `<table>!<name>` of a struct, from the module's table or else the kernel's (a vmlinux type).

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the kernel module on which to operate
            table_name: The module's symbol table, as `module_symbol_table` returned it
            name: The struct's name, e.g. "kvm_vcpu"

        Raises:
            BtfError: Neither symbol table has the struct
        """
        for table in (
            table_name,
            context.modules[kernel_module_name].symbol_table_name,
        ):
            if context.symbol_space.has_type(table + constants.BANG + name):
                return table + constants.BANG + name
        raise BtfError(f"no struct {name}")

    @classmethod
    def enumerators(
        cls, context: interfaces.context.ContextInterface, table_name: str
    ) -> Dict[str, int]:
        """Every enum constant of a module's table, such as VCPU_REGS_RIP, with its value.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            table_name: The module's symbol table, as `module_symbol_table` returned it
        """
        table = context.symbol_space[table_name]
        found: Dict[str, int] = {}
        for name in table.enumerations:
            found.update(table.get_enumeration(name).vol.choices)
        return found

    @classmethod
    def module_symbol(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        module_name: str,
        symbol: str,
    ) -> Optional[int]:
        """The canonical kernel address of a symbol of a loaded module, or None if the module or symbol is not found.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the kernel module on which to operate
            module_name: The loaded module, e.g. "kvm"
            symbol: The symbol's name, e.g. "vm_list"
        """
        kernel = context.modules[kernel_module_name]
        head = kernel.object_from_symbol("modules")
        for mod in head.to_list(
            kernel.symbol_table_name + constants.BANG + "module", "list"
        ):
            try:
                if mod.get_name() != module_name:
                    continue
                for name, address in mod.get_symbols_names_and_addresses(
                    max_symbols=1 << 20
                ):
                    if name == symbol:  # vol3 masks module symbol addresses to 48 bits
                        return context.layers[kernel.layer_name].canonicalize(address)
            except exceptions.InvalidAddressException:
                continue
        return None

    # --- the whole kernel, from memory ----------------------------------------------------------

    @classmethod
    def find_vmlinux_btf(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Iterator[Tuple[int, Btf]]:
        """Finds vmlinux's own BTF in a physical layer, the largest blob first.

        The kernel's BTF starts with a fixed header (version 1, flags 0, header length 24, types first, strings straight
        after). A candidate must pass the header checks and then parse on its own, with every ID and string offset
        inside the blob. A module's split BTF does not, because it refers to vmlinux's, and neither does a stale copy
        that the kernel has partly overwritten. The x86-64 kernel image is physically contiguous, so the blob is read
        straight from the layer.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The physical layer to scan
            progress_callback: A function that takes a percentage and an optional description, called periodically

        Yields:
            The physical address of the blob and its parsed BTF
        """
        layer = context.layers[layer_name]
        found = []
        for offset in layer.scan(
            scanner=scanners.BytesScanner(HEADER_START),
            context=context,
            progress_callback=progress_callback,
        ):
            try:
                _, _, _, hdr_len, _, type_len, str_off, str_len = HEADER.unpack(
                    layer.read(offset, HEADER.size)
                )
                strings = offset + hdr_len + str_off
                if (
                    str_off != type_len
                    or type_len % 4
                    or not 0 < str_len
                    or hdr_len + type_len + str_len > BTF_MAX
                    or layer.read(strings, 1) != b"\0"
                    or layer.read(strings + str_len - 1, 1) != b"\0"
                ):
                    continue
            except exceptions.InvalidAddressException:
                continue
            found.append((hdr_len + type_len + str_len, offset))
        for size, offset in sorted(found, key=lambda item: (-item[0], item[1])):
            try:
                btf = Btf(layer.read(offset, size))
                btf.check()
            except (BtfError, struct.error, exceptions.InvalidAddressException) as excp:
                vollog.debug("BTF candidate at %#x rejected: %s", offset, excp)
                continue
            yield offset, btf

    @classmethod
    def _vmcoreinfo(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Dict[str, Any]:
        """The first VMCOREINFO note of the image, or {}. It is a cross-check and the source of KERNELOFFSET."""
        try:
            for _offset, table in linux_symbols.VMCoreInfo.search_vmcoreinfo_elf_note(
                context, layer_name, progress_callback
            ):
                return table
        except (exceptions.VolatilityException, ValueError) as excp:
            vollog.debug("no usable VMCOREINFO: %s", excp)
        return {}

    @classmethod
    def kernel_image(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
        release: Optional[str] = None,
    ) -> KernelImage:
        """Finds the kernel's BTF and kallsyms in a physical layer and relates them to each other.

        The layer should hold one kernel. A host image whose guests use huge pages can hold several, each guest's kernel
        image with its own BTF in contiguous memory. Then the kernel with the largest BTF is used, unless `release`
        names the one wanted.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The physical layer of an x86-64 Linux image
            progress_callback: A function that takes a percentage and an optional description, called periodically
            release: Only accept the kernel of this release (`6.1.0-54-cloud-amd64`, the banner's third word)

        Raises:
            BtfError: No vmlinux BTF, no kallsyms tables, no data symbols (CONFIG_KALLSYMS_ALL is off), not x86-64, or
                no kernel of the requested release
        """
        timings: Dict[str, float] = collections.defaultdict(float)
        clock, reason, vmcoreinfo = time.perf_counter, None, None
        candidates = cls.find_vmlinux_btf(context, layer_name, progress_callback)
        while True:
            start = clock()
            candidate = next(candidates, None)
            timings["BTF scan"] += clock() - start
            if candidate is None:
                raise BtfError(
                    reason
                    or "no vmlinux BTF in the image (needs CONFIG_DEBUG_INFO_BTF)"
                )
            if vmcoreinfo is None:
                start = clock()
                vmcoreinfo = cls._vmcoreinfo(context, layer_name, progress_callback)
                timings["VMCOREINFO"] = clock() - start
            try:
                image = cls._locate(
                    context, layer_name, *candidate, vmcoreinfo, timings
                )
            except BtfError as excp:
                vollog.debug("BTF at %#x not usable: %s", candidate[0], excp)
                reason = str(excp)
                continue
            if release is not None and image.release != release:
                vollog.debug("BTF at %#x is of kernel %s", candidate[0], image.release)
                reason = f"no kernel of release {release} in the image (found {image.release})"
                continue
            vollog.info(
                "kernel_btf: %s",
                ", ".join(f"{step} {secs:.2f} s" for step, secs in timings.items()),
            )
            return image

    @classmethod
    def _locate(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        address: int,
        btf: Btf,
        vmcoreinfo: Dict[str, Any],
        timings: Dict[str, float],
    ) -> KernelImage:
        """Reads the kallsyms around a BTF blob and checks that both belong to the same kernel image."""
        layer = context.layers[layer_name]
        began = time.perf_counter()
        ks = cls._scan_kallsyms(layer, address, vmcoreinfo)
        timings["kallsyms"] += time.perf_counter() - began
        cls._check_kernel(ks)
        delta = cls._physical_delta(ks, address)
        banner = cls._banner(ks, layer, delta)

        def read(where: int, length: int) -> bytes:
            return layer.read(where - delta, length, pad=True)

        image = KernelImage(btf, address, ks, 0, delta, banner, read, timings)
        # The shift needs the release, which the image takes from the banner.
        return image._replace(shift=cls._kaslr_shift(ks, image.release, vmcoreinfo))

    @classmethod
    def _scan_kallsyms(
        cls,
        layer: interfaces.layers.DataLayerInterface,
        address: int,
        vmcoreinfo: Dict[str, Any],
    ) -> kallsyms_scan.Kallsyms:
        """The kallsyms tables in the window around the BTF blob at `address`.

        The symbol addresses of the VMCOREINFO note serve as a cross-check. If the tables do not fit them, they are
        decoded again without. A host image also holds its guests' notes, and the first note found need not be this
        kernel's.
        """
        start = max(0, address - KALLSYMS_WINDOW[0]) & ~0xFFF
        end = min(address + KALLSYMS_WINDOW[1], layer.maximum_address + 1)
        data = layer.read(start, end - start, pad=True)
        hints = {
            key: value for key, value in vmcoreinfo.items() if key.startswith("SYMBOL(")
        }
        error: Optional[kallsyms_scan.KallsymsError] = None
        for attempt in [hints, None] if hints else [None]:
            try:
                return kallsyms_scan.KallsymsScan.decode(data, start, attempt)
            except kallsyms_scan.KallsymsError as excp:
                error = excp
                vollog.debug(
                    "kallsyms not decoded%s: %s",
                    " with the VMCOREINFO note" if attempt else "",
                    excp,
                )
        raise BtfError(
            f"kallsyms not found near the BTF at {address:#x}: {error}"
        ) from error

    @classmethod
    def _check_kernel(cls, ks: kallsyms_scan.Kallsyms) -> None:
        """Raises `BtfError` unless the kallsyms are an x86-64 kernel's and have its data symbols."""
        text = ks.address("_text")
        if text is None or text < KERNEL_MAP:
            raise BtfError(
                f"not an x86-64 kernel (kallsyms has `_text` at {text and hex(text)})"
            )
        if ks.address("init_task") is None or not any(
            letter in DATA_LETTERS for _, letter, _ in ks.symbols
        ):
            raise BtfError("kallsyms has no data symbols (CONFIG_KALLSYMS_ALL is off)")

    @classmethod
    def _physical_delta(cls, ks: kallsyms_scan.Kallsyms, btf_address: int) -> int:
        """Runtime address - physical address inside the kernel image.

        It is computed from the BTF and from each kallsyms table, and all results must agree. Otherwise the BTF
        belongs to another kernel and `BtfError` is raised.
        """
        anchors = {"__start_BTF": btf_address}
        anchors.update(
            {
                f"{kallsyms_scan.SYMBOL_PREFIX}{table}": ks.layout[table]
                for table in KALLSYMS_ANCHORS
            }
        )
        deltas = {
            name: ks.address(name) - phys
            for name, phys in anchors.items()
            if ks.address(name) is not None
        }
        if not deltas or len(set(deltas.values())) > 1:
            raise BtfError(
                f"the BTF at {btf_address:#x} is not in the kernel image of the kallsyms tables"
                f" ({', '.join(f'{k} {v:#x}' for k, v in deltas.items())})"
            )
        return deltas.get("__start_BTF", next(iter(deltas.values())))

    @classmethod
    def _banner(
        cls,
        ks: kallsyms_scan.Kallsyms,
        layer: interfaces.layers.DataLayerInterface,
        delta: int,
    ) -> bytes:
        """The kernel's `linux_banner` with its NUL, read at the address kallsyms gives."""
        banner_at = ks.address("linux_banner")
        raw = layer.read(banner_at - delta, 1024, pad=True) if banner_at else b""
        banner = raw.split(b"\0")[0] + b"\0"
        if not banner.startswith(b"Linux version "):
            raise BtfError("no Linux banner where kallsyms puts `linux_banner`")
        return banner

    @classmethod
    def _kaslr_shift(
        cls, ks: kallsyms_scan.Kallsyms, release: str, vmcoreinfo: Dict[str, Any]
    ) -> int:
        """Runtime address - link-time address of the kernel image (the KASLR shift).

        It is KERNELOFFSET from the VMCOREINFO note if the note is this kernel's, else the position of `_text`. The
        note is this kernel's if its OSRELEASE is `release` and its `SYMBOL(init_uts_ns)`, a runtime address like
        the ones of the kallsyms tables, is where kallsyms puts `init_uts_ns`. A guest that runs the same distro
        kernel has the same release but its own addresses.
        """
        shift = ks.address("_text") - KERNEL_TEXT
        if vmcoreinfo.get("OSRELEASE", release) != release:
            # A host image holds the VMCOREINFO of its guests' kernels too.
            vollog.debug(
                "VMCOREINFO of kernel %s, not %s: ignored",
                vmcoreinfo["OSRELEASE"],
                release,
            )
            vmcoreinfo = {}
        uts = vmcoreinfo.get("SYMBOL(init_uts_ns)")
        if uts is not None and ks.address("init_uts_ns") not in (None, uts):
            vollog.debug(
                "VMCOREINFO has init_uts_ns at %#x, kallsyms at %#x: the note is of another kernel, ignored",
                uts,
                ks.address("init_uts_ns"),
            )
            vmcoreinfo = {}
        offset = vmcoreinfo.get("KERNELOFFSET")
        if offset is not None:
            if offset != shift:
                vollog.warning(
                    "KERNELOFFSET %#x from VMCOREINFO differs from _text - %#x = %#x; using KERNELOFFSET",
                    offset,
                    KERNEL_TEXT,
                    shift,
                )
            shift = offset
        vollog.info(
            "kernel_btf: KASLR shift %#x (%s)",
            shift,
            "KERNELOFFSET" if offset is not None else "_text",
        )
        return shift

    @classmethod
    def isf_from_image(cls, image: KernelImage) -> Dict[str, Any]:
        """The ISF of a kernel image: all types of its BTF, all symbols of its kallsyms.

        A symbol's address is the link-time one (runtime address - KASLR shift), as both of the framework's Linux
        stackers expect: the VMCOREINFO stacker adds KERNELOFFSET itself and the Intel stacker finds the shift
        itself. The per-cpu symbols of a CONFIG_KALLSYMS_ABSOLUTE_PERCPU kernel are small absolute numbers and stay
        as they are. A symbol's type is its variable's in the BTF (DATASEC, else VAR), or else its `TYPED_SYMBOLS`
        entry. Other symbols are `void`, as dwarf2json writes them.

        Args:
            image: The result of `kernel_image`
        """
        began = time.perf_counter()
        builder = IsfBuilder(None, image.btf)
        chosen = cls._link_addresses(image)
        cls._add_symbols(builder, image, chosen)
        isf = builder.build()
        isf["metadata"]["linux"] = cls._linux_metadata(image, chosen)
        image.timings["build"] = time.perf_counter() - began
        vollog.info(
            "kernel_btf: %d types, %d enums, %d symbols built in %.2f s",
            len(isf["user_types"]),
            len(isf["enums"]),
            len(isf["symbols"]),
            image.timings["build"],
        )
        return isf

    @classmethod
    def _link_addresses(cls, image: KernelImage) -> Dict[str, Tuple[int, str]]:
        """{symbol name: (link-time address, kallsyms type letter)} with the kallsyms tables added; the first global
        symbol of a name wins, else the first.
        """
        ks = image.kallsyms
        chosen: Dict[str, Tuple[int, str]] = {}
        for address, letter, name in ks.symbols:
            link = address - image.shift if address >= KERNEL_MAP else address
            old = chosen.get(name)
            if old is None or (old[1].islower() and letter.isupper()):
                chosen[name] = (link, letter)
        # The kallsyms tables are not always listed as symbols, but the scan knows where they are.
        for key in kallsyms_scan.TABLES:
            link = ks.layout[key] + image.phys_delta - image.shift
            chosen.setdefault(f"{kallsyms_scan.SYMBOL_PREFIX}{key}", (link, "r"))
        return chosen

    @classmethod
    def _add_symbols(
        cls,
        builder: IsfBuilder,
        image: KernelImage,
        chosen: Dict[str, Tuple[int, str]],
    ) -> None:
        """Fills `builder.symbols` from `chosen`, typed from the BTF where possible, and sets `linux_banner`'s data."""
        btf = image.btf
        located, by_name = btf.variables()
        for name, (link, letter) in chosen.items():
            type_id = located.get((name, link))
            if type_id is None and letter in DATA_LETTERS and len(by_name[name]) == 1:
                type_id = by_name[name][0]
            symbol: Dict[str, Any] = {"address": link}
            symbol["type"] = (
                builder.descriptor(type_id)
                if type_id is not None
                else cls._fixed_type(builder, image, name) or VOID
            )
            builder.symbols[name] = symbol
        char = next(
            i for i, n in enumerate(btf.names) if n == "char" and btf.kinds[i] == INT
        )
        builder.symbols["linux_banner"].update(
            {
                "type": {
                    "kind": "array",
                    "count": 0,
                    "subtype": builder.descriptor(char),
                },
                "constant_data": base64.b64encode(image.banner).decode(),
            }
        )

    @classmethod
    def _linux_metadata(
        cls, image: KernelImage, chosen: Dict[str, Tuple[int, str]]
    ) -> Dict[str, Any]:
        """The `metadata.linux` part of the ISF: where the symbols and types come from, with hashes."""
        listing = "".join(
            f"{link:016x} {letter} {name}\n"
            for name, (link, letter) in sorted(chosen.items(), key=lambda i: i[1])
        )
        # The ISF schema (6.2.0) allows only `dwarf`, `symtab` and `system-map` as `kind` here, and Volatility rejects
        # a validated file with another value. kallsyms is a system map. BTF has no kind of its own, so it is
        # labelled `dwarf`, the debug format it carries types of. `name` says what it really is.
        return {
            "symbols": [
                {
                    "kind": "system-map",
                    "name": f"in-memory kallsyms of {image.release}",
                    "hash_type": "sha256",
                    "hash_value": hashlib.sha256(listing.encode()).hexdigest(),
                }
            ],
            "types": [
                {
                    "kind": "dwarf",
                    "name": f"in-memory BTF of {image.release}",
                    "hash_type": "sha256",
                    "hash_value": hashlib.sha256(image.btf.raw).hexdigest(),
                }
            ],
        }

    @classmethod
    def _fixed_type(
        cls, builder: IsfBuilder, image: KernelImage, name: str
    ) -> Optional[Dict[str, Any]]:
        """The type descriptor of a symbol in `TYPED_SYMBOLS`, if the kernel has that type."""
        if name not in TYPED_SYMBOLS:
            return None
        base, stars, count = TYPE_SPEC.match(TYPED_SYMBOLS[name]).groups()
        if base == "function":
            found = ({"kind": "function"}, 8)
        else:
            found = builder.named(base)
        if found is None:
            return None
        descriptor, size = found
        for _ in stars:
            descriptor, size = {"kind": "pointer", "subtype": descriptor}, 8
        if count is None:
            return descriptor
        if count.isdigit():
            number = int(count)
        else:
            number = builder.enumerator(count) if count else None
            if number is None:
                # As many elements as fit before the next symbol, less the zero padding after the array.
                number = (image.kallsyms.size(name) or 0) // max(size, 1)
                data = image.read(image.kallsyms.address(name), number * size)
                while number > 1 and not any(data[(number - 1) * size : number * size]):
                    number -= 1
        return {"kind": "array", "count": number, "subtype": descriptor}

    @classmethod
    def isf_from_memory(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Tuple[Dict[str, Any], str]:
        """Builds the ISF of the kernel in a physical memory image, with no symbol file.

        The types come from the in-memory BTF, the symbols from the kallsyms.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The physical layer of an x86-64 Linux image (not a layer on top of its page tables)
            progress_callback: A function that takes a percentage and an optional description, called periodically

        Returns:
            The ISF dictionary and the kernel's banner (the `Linux version ...` line)

        Raises:
            BtfError: No vmlinux BTF, no kallsyms tables, no data symbols (CONFIG_KALLSYMS_ALL is off) or not x86-64
        """
        image = cls.kernel_image(context, layer_name, progress_callback)
        isf = cls.isf_from_image(image)
        return isf, image.banner_text

    @classmethod
    def isf_file_name(cls, banner: str) -> str:
        """The file name `<release>.json.xz` for the symbol table of the kernel with this banner.

        The release is the third word of the banner (`Linux version 6.1.0-54-cloud-amd64 ...`). Every character that is
        not a word character, `.`, `+`, `~` or `-` is replaced by `_`. `banner` is as `isf_from_memory` returns it.
        """
        release = re.sub(r"[^\w.+~-]", "_", banner.split()[2])
        return f"{release}.json.xz"

    @classmethod
    def write_isf(
        cls, isf: Dict[str, Any], handle: BinaryIO, preset: int = ISF_XZ_PRESET
    ) -> int:
        """Writes a symbol table as compact, xz-compressed JSON to a binary file object; returns the compressed size.

        Args:
            isf: The ISF dictionary
            handle: A file object open for binary writing; it stays open
            preset: The xz preset (`ISF_XZ_PRESET`, or `ISF_XZ_PRESET_TEMPORARY` for a file that is not kept)
        """
        counter = _CountingWriter(handle)
        with lzma.open(counter, "wt", encoding="utf-8", preset=preset) as text:
            json.dump(isf, text, separators=(",", ":"))
        return counter.size


# Syntax of the `TYPED_SYMBOLS` types: a name as in `IsfBuilder.named` or `function`, then `*` for each pointer level,
# then an optional array: `[n]` for n elements (0 where the kernel gives no length, as dwarf2json does), `[NAME]` for
# the value of the kernel's enumerator NAME, or `[]` for as many as fit before the next symbol.
TYPE_SPEC = re.compile(
    r"^(\{[a-z_,]+\}|[A-Za-z_][A-Za-z0-9_ ]*?)(\**)(?:\[([A-Za-z0-9_]*)\])?$"
)
# Types of symbols that the framework or these plugins read (`object_from_symbol`, `get_symbol(...).type`), for
# kernels whose BTF has no variable for them. Some BTF has VARs for per-cpu variables only (Debian, Ubuntu) or lacks
# static variables; newer kernels may have more, and the BTF's own type is used first. The types are those that
# dwarf2json and btf2json write. `tk_core` is an anonymous struct, so it is given by its member names.
TYPED_SYMBOLS: Dict[str, str] = {
    "init_task": "task_struct",
    "init_mm": "mm_struct",
    "init_files": "files_struct",
    "init_pid_ns": "pid_namespace",
    "init_top_pgt": "pgd_t[0]",
    "init_level4_pgt": "pgd_t[0]",
    "swapper_pg_dir": "pgd_t[0]",
    "socket_file_ops": "file_operations",
    "sockfs_dentry_operations": "dentry_operations",
    "io_uring_fops": "file_operations",
    "net_namespace_list": "list_head",
    "modules": "list_head",
    "tty_drivers": "list_head",
    "bpf_kallsyms": "list_head",
    "ftrace_mod_maps": "list_head",
    "ftrace_ops_trampoline_list": "list_head",
    "btf_modules": "list_head",
    "mod_tree": "mod_tree_root",
    "ftrace_list_end": "ftrace_ops",
    "ftrace_ops_list": "ftrace_ops*",
    "keyboard_notifier_list": "atomic_notifier_head",
    "prog_idr": "idr",
    "iomem_resource": "resource",
    "module_kset": "kset*",
    "btf_vmlinux": "btf*",
    "console_driver": "tty_driver*",
    "prb": "printk_ringbuffer*",
    "printk_rb_static": "printk_ringbuffer",
    "log_buf": "char*",
    "log_buf_len": "unsigned int",
    "log_first_idx": "unsigned int",
    "log_next_idx": "unsigned int",
    "kallsyms_num_syms": "unsigned int",
    "cap_last_cap": "int",
    "fg_console": "int",
    "num_registered_fb": "int",
    "vmemmap_base": "long unsigned int",
    "module_addr_min": "long unsigned int",
    "module_addr_max": "long unsigned int",
    "mem_map": "page*",
    "mem_section": "mem_section**",
    "node_data": "pg_data_t*[0]",
    "registered_fb": "fb_info*[32]",
    "vc_cons": "vc[63]",
    "idt_table": "gate_desc[256]",
    "taint_flags": "taint_flag[]",
    "sys_call_table": "function*[0]",
    "ia32_sys_call_table": "function*[0]",
    "x32_sys_call_table": "function*[0]",
    "_text": "char[0]",
    "_etext": "char[0]",
    "__start___tracepoints_ptrs": "int[0]",
    "tk_core": "{seq,timekeeper}",
    "timekeeper": "timekeeper",
    "timekeeper_data": "tk_data[TIMEKEEPERS_MAX]",
}
