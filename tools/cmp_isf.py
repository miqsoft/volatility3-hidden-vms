#!/usr/bin/env python3
# This file is Copyright 2026 Michael Külper and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
#
"""Compares two Volatility symbol tables (ISF, .json or .json.xz) of the same Linux kernel.

    cmp_isf.py built.json.xz reference.json.xz [type ...]

Made to check an ISF that `linux.btf_isf.Build` wrote from a kernel's own BTF and kallsyms against one made from
the kernel's debug package (dwarf2json, btf2json). It compares

- the types that Volatility's Linux code and our plugins use (or the ones named on the command line): size and
  every field's offset and type, where an anonymous struct is told by its shape, not its generated name;
- all other types in both files, summarised;
- the symbols: address of each, and the type of each that Volatility reads through (`init_task`, `tk_core`, ...);
  a type that B lacks (void) or an array length that differs is noted, not counted;
- the `linux_banner` that the symbol cache matches an ISF to an image by.

The output is short. The exit status is 1 if anything that matters differs (a listed type or symbol, or the
banner), 0 otherwise.
"""

import argparse
import base64
import json
import lzma
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

# types that volatility3's Linux code (framework, symbols/linux, plugins/linux) and our plugins look up by name
TYPES = (
    "task_struct mm_struct file socket sock inet_sock unix_sock list_head files_struct "
    "address_space atomic_notifier_head bin_attribute bio_vec bpf_binary_header bpf_ksym bpf_prog bpf_prog_aux "
    "btf cred dentry file_operations fs_struct ftrace_mod_func ftrace_mod_map ftrace_ops hlist_head idr in_device "
    "in_ifaddr inet6_dev inet6_ifaddr inode io_file_table io_ring_ctx io_uring_task kernel_cap_t kernel_param "
    "kernel_symbol kobject kthread kvm kvm_memory_slot kvm_vcpu latch_tree_node latch_tree_root maple_tree "
    "mnt_namespace mod_tree_root module module_kobject module_memory module_sect_attr mount n_tty_data net "
    "net_device netlink_sock netns_nf nf_hook_entry node ns_common nsproxy packet_sock page perf_event pid "
    "pid_namespace prb_desc printk_info printk_ringbuffer qstr rb_node rb_root resource scatterlist "
    "seq_operations signal_struct super_block tcp_seq_afinfo timekeeper timespec64 tk_data tracepoint "
    "tty_audit_buf tty_file_private tty_struct uni_pagedict unix_sock upid vfsmount vm_area_struct xdp_sock "
    "pgd_t atomic_t gate_desc kernel_cap_struct"
).split()
# symbols that those read, and the kernel locates itself by
SYMBOLS = (
    "linux_banner init_task init_mm init_files init_top_pgt swapper_pg_dir init_pid_ns socket_file_ops "
    "sockfs_dentry_operations net_namespace_list modules tk_core timekeeper_data prb log_buf log_buf_len "
    "idt_table sys_call_table vmemmap_base mem_section node_data taint_flags tty_drivers mod_tree module_kset "
    "prog_idr iomem_resource kallsyms_num_syms _text _etext cap_last_cap console_driver fg_console vc_cons "
    "io_uring_fops btf_vmlinux btf_modules keyboard_notifier_list bpf_kallsyms ftrace_ops_list "
    "ftrace_list_end registered_fb num_registered_fb nf_hooks"
).split()
# a name a tool generated for an anonymous type (and the ones we add for duplicate names), which is not comparable
ANONYMOUS = re.compile(
    r"^(anon|enum)_\d+$|^unnamed_[0-9a-f]{16}$|^unnamed_(struct|union|enum|enum64)_\d+$"
)


def load(path: str) -> Dict[str, Any]:
    with lzma.open(path, "rt") if path.endswith(".xz") else open(path) as handle:
        return json.load(handle)


def shape(descriptor: Optional[Dict[str, Any]]) -> str:
    """A type descriptor as one comparable string."""
    if not descriptor:
        return "void"
    kind = descriptor["kind"]
    if kind == "base":
        return descriptor["name"]
    if kind == "pointer":
        return "*" + shape(descriptor["subtype"])
    if kind == "array":
        return f"[{descriptor['count']}]" + shape(descriptor["subtype"])
    if kind == "bitfield":
        return f"bits {descriptor['bit_length']} " + shape(descriptor["type"])
    if kind in ("struct", "union", "enum"):
        return f"{kind} {descriptor['name']}"
    return kind


def fields(user_type: Dict[str, Any]) -> Dict[str, Tuple[int, str]]:
    """name -> (bit offset, type) of a struct's fields; anonymous members are keyed by position. A bitfield's
    offset is its absolute bit position, so that "byte 2416, bit 15" and "byte 2417, bit 7" are the same."""
    found = {}
    for name, field in user_type["fields"].items():
        bit = field["offset"] * 8 + field["type"].get("bit_position", 0)
        if field.get("anonymous"):
            name = f"<anonymous at {field['offset']}>"
        found[name] = (bit, shape(field["type"]))
    return found


def same_layout(a: Dict[str, Any], b: Dict[str, Any], name_a: str, name_b: str) -> bool:
    """Whether struct `name_a` of ISF a and `name_b` of b have the same size and members (a typedef alias or a
    generated name for an anonymous type is no difference)."""
    one, two = a["user_types"].get(name_a), b["user_types"].get(name_b)
    if one is None or two is None:
        return False
    key = lambda t: (t["size"], sorted((n, o) for n, (o, _) in fields(t).items()))  # noqa: E731
    return key(one) == key(two)


def aliases(a: Dict[str, Any], b: Dict[str, Any], one: str, two: str) -> bool:
    """Whether two type strings differ only in the names of structs, unions or enums of the same layout."""
    named = r"(struct|union|enum) (\S+)"
    bare = lambda text: re.sub(named, r"\1", text)  # noqa: E731
    return bare(one) == bare(two) and all(
        a["enums"].get(x, {}).get("constants") == b["enums"].get(y, {}).get("constants")
        if kind == "enum"
        else same_layout(a, b, x, y)
        for (kind, x), (_, y) in zip(re.findall(named, one), re.findall(named, two))
    )


def compare_type(a: Dict[str, Any], b: Dict[str, Any], name: str) -> List[str]:
    """What differs in one type, as short sentences (empty if nothing)."""
    one, two = a["user_types"].get(name), b["user_types"].get(name)
    if one is None and two is None:
        return [f"{name}: in neither file"]
    if one is None or two is None:
        return [f"{name}: only in {'B' if one is None else 'A'}"]
    problems = []
    if one["kind"] != two["kind"]:
        problems.append(f"kind {one['kind']} vs {two['kind']}")
    if one["size"] != two["size"]:
        problems.append(f"size {one['size']} vs {two['size']}")
    fa, fb = fields(one), fields(two)
    for field in sorted(set(fa) | set(fb), key=lambda f: (fa.get(f) or fb[f])[0]):
        if fa.get(field) != fb.get(field):
            x, y = fa.get(field), fb.get(field)
            if x and y and x[0] == y[0] and aliases(a, b, x[1], y[1]):
                continue
            problems.append(f".{field} {x or 'missing'} vs {y or 'missing'}")
    if problems:
        more = f" (+{len(problems) - 3} more)" if len(problems) > 3 else ""
        return [f"{name}: " + "; ".join(problems[:3]) + more]
    return []


def banner(isf: Dict[str, Any]) -> Optional[bytes]:
    data = isf["symbols"].get("linux_banner", {}).get("constant_data")
    return base64.b64decode(data) if data else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("a", help="ISF A (e.g. the built one)")
    parser.add_argument("b", help="ISF B (e.g. the reference)")
    parser.add_argument(
        "types", nargs="*", help="types to compare instead of the usual ones"
    )
    args = parser.parse_args()
    a, b = load(args.a), load(args.b)
    bad = 0
    for label, isf in (("A", a), ("B", b)):
        producer = isf["metadata"].get("producer", {})
        print(
            f"{label}: {producer.get('name')} {producer.get('version')}, {len(isf['user_types'])} types, "
            f"{len(isf['enums'])} enums, {len(isf['symbols'])} symbols"
        )

    # listed types
    problems = []
    names = args.types or [
        t for t in TYPES if t in a["user_types"] or t in b["user_types"]
    ]
    for name in names:
        problems += compare_type(a, b, name)
    print(f"listed types: {len(names)} compared, {len(problems)} differ")
    for line in problems:
        print("  " + line)
    bad += len(problems)

    # every other type
    # generated names of anonymous types do not correspond between tools: those are compared where a named type
    # refers to them
    common = {
        n for n in set(a["user_types"]) & set(b["user_types"]) if not ANONYMOUS.match(n)
    }
    differ = [n for n in common if compare_type(a, b, n)]
    only_a = sorted(
        n
        for n in set(a["user_types"]) - common
        if not ANONYMOUS.match(n) and not re.search(r"_\d+$", n)
    )
    only_b = sorted(n for n in set(b["user_types"]) - common if not ANONYMOUS.match(n))
    print(
        f"all types: {len(common)} in both, {len(common) - len(differ)} identical, {len(differ)} differ; "
        f"only in A {len(only_a)}, only in B {len(only_b)}"
    )
    for label, only in (("A", only_a), ("B", only_b)):
        if only:
            print(
                f"  only in {label}: "
                + " ".join(only[:8])
                + (" ..." if len(only) > 8 else "")
            )
    enums = set(a["enums"]) & set(b["enums"])
    edit = [
        n for n in enums if a["enums"][n]["constants"] != b["enums"][n]["constants"]
    ]
    print(
        f"enums: {len(enums)} in both, {len(edit)} with other constants; only in A {len(set(a['enums']) - enums)}, only in B {len(set(b['enums']) - enums)}"
    )

    # symbols
    sa, sb = a["symbols"], b["symbols"]
    both = set(sa) & set(sb)
    moved = sorted(n for n in both if sa[n]["address"] != sb[n]["address"])
    typed = sorted(
        n for n in both if shape(sa[n].get("type")) != shape(sb[n].get("type"))
    )
    print(
        f"symbols: {len(both) - len(moved)} at the same address, {len(moved)} at another, "
        f"only in A {len(set(sa) - both)}, only in B {len(set(sb) - both)}; type differs for {len(typed)}"
    )
    if moved:
        print(
            "  moved: "
            + ", ".join(
                f"{n} {sa[n]['address']:#x} vs {sb[n]['address']:#x}" for n in moved[:3]
            )
        )
    listed, notes = [], []
    for name in SYMBOLS:
        if name in sa and name in sb:
            if sa[name]["address"] != sb[name]["address"]:
                listed.append(
                    f"{name}: address {sa[name]['address']:#x} vs {sb[name]['address']:#x}"
                )
            x, y = shape(sa[name].get("type")), shape(sb[name].get("type"))
            if x == y:
                continue
            # the reference knows no type (A knows more), or only an array length differs
            if y == "void" or re.sub(r"\[\d+\]", "[]", x) == re.sub(
                r"\[\d+\]", "[]", y
            ):
                notes.append(f"{name}: type {x} vs {y}")
            else:
                listed.append(f"{name}: type {x} vs {y}")
        elif name in sa or name in sb:
            listed.append(f"{name}: only in {'A' if name in sa else 'B'}")
    print(
        f"listed symbols: {len(SYMBOLS)} checked, {len(listed)} differ, {len(notes)} noted"
    )
    for line in listed:
        print("  " + line)
    for line in notes:
        print("  (note) " + line)
    bad += len(listed)

    # the banner
    ba, bb = banner(a), banner(b)
    if ba == bb:
        print("banner: identical")
    elif ba is not None and bb is not None and ba.rstrip(b"\0") == bb.rstrip(b"\0"):
        print(
            "banner: identical except for a trailing NUL (the symbol cache matches both)"
        )
    else:
        print("banner: DIFFERENT")
        bad += 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
