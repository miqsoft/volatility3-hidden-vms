# This file is Copyright 2026 Michael Külper and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
#
"""What a QEMU command line says: whether it is QEMU, the machine type, accelerator, confidential-computing setup,
memory devices (NUMA nodes, pc-dimm, virtio-mem) and the columns that describe the VM (name, network, control channels).

This is plain text processing on a list of arguments; it needs no memory image. `QemuCmdline` is the versioned
interface, and its version covers the whole module.
"""

import json
import re
from typing import Dict, List, Optional, Tuple

from volatility3.framework import interfaces, renderers

# Options that QEMU takes and few other programs do. Two of them on a command line make a VMM very likely.
QEMU_OPTIONS = frozenset(
    """-machine -M -m -accel -enable-kvm -drive -blockdev -netdev -cdrom -bios -device -object -readconfig
    -nographic -display -serial -monitor -qmp -smp -cpu -kernel -initrd -append -boot -hda -nic -L -pflash
    -chardev -vnc -smbios -rtc -vga -daemonize""".split()
)


# --- command line ------------------------------------------------------------------------------------


def _parse_size(text: str, bare_unit: int = 1 << 20) -> Optional[int]:
    """QEMU size such as '256', '256M', '2G' or 'size=2G,slots=..' in bytes.

    A bare number counts `bare_unit` bytes: MiB for `-m`, bytes for properties like `memory-backend-ram,size=`.
    """
    m = re.match(r"(?:size=)?(\d+(?:\.\d+)?)([kKmMgGtT]?)", text)
    if not m:
        return None
    unit = {"": bare_unit, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40}[
        m.group(2).lower()
    ]
    return int(float(m.group(1)) * unit)


def _option_name(arg: str) -> str:
    """The option an argument spells, with a single dash: QEMU takes `--machine` like `-machine`."""
    return arg[1:] if arg.startswith("--") else arg


def _has_option(args: List[str], name: str) -> bool:
    """Whether the flag `name` ('-enable-kvm', '-s', ...) is on the command line, with one or two dashes."""
    return any(_option_name(arg) == name for arg in args)


def _options(args: List[str], *names: str) -> List[str]:
    """The values of the given options ('-m', '-object', ...), in command-line order."""
    return [
        args[i + 1] for i, arg in enumerate(args[:-1]) if _option_name(arg) in names
    ]


def _qemu_option(args: List[str], *names: str) -> Optional[str]:
    """Value of the last occurrence of any of the given options."""
    values = _options(args, *names)
    return values[-1] if values else None


def _kv(text: str) -> dict:
    """QEMU option string 'word,key=value,...' (or JSON '{...}') as a dict; a bare first word has the key ''."""
    if text.startswith("{"):
        try:
            return {k: str(v) for k, v in json.loads(text).items()}
        except ValueError:
            return {}
    out = {}
    for i, part in enumerate(text.split(",")):
        key, eq, value = part.partition("=")
        if eq:
            out[key] = value
        elif i == 0:
            out[""] = key
    return out


def _machine_opts(args: List[str]) -> dict:
    """The `-machine` / `-M` option as a dict."""
    return _kv(_qemu_option(args, "-machine", "-M") or "")


def _backend_sizes(args: List[str]) -> Dict[str, Optional[int]]:
    """{object id: size} of the `-object memory-backend-*,id=..,size=..` options."""
    objects = [_kv(text) for text in _options(args, "-object")]
    return {
        o["id"]: _parse_size(o["size"], 1)
        for o in objects
        if o.get("id") and "size" in o
    }


def _memory_devices(
    args: List[str],
) -> Tuple[List[Tuple[str, Optional[int]]], List[Tuple[str, Optional[int], int]]]:
    """(pc-dimms, virtio-mem devices) from one walk over `-device`, in command-line (= plug) order.

    A pc-dimm is (memdev id, backend size). Proxmox adds these for memory hotplug. One with an `addr=` is placed by
    the user and left out. DIMMs hot-added at run time (QMP `device_add`) are not on the command line.

    A virtio-mem device (QEMU 5.2+) is (memdev id, backend size, number of pc-dimms plugged before it). Its memory is
    not rebuilt. It reserves its whole backend size in the device memory region, which moves the start of any
    pc-dimm plugged after it.
    """
    sizes = _backend_sizes(args)
    dimms: List[Tuple[str, Optional[int]]] = []
    vmem: List[Tuple[str, Optional[int], int]] = []
    for dev in map(_kv, _options(args, "-device")):
        memdev = dev.get("memdev")
        if not memdev:
            continue
        driver = dev.get("", dev.get("driver", ""))
        if driver == "pc-dimm":
            if "addr" not in dev:
                dimms.append((memdev, sizes.get(memdev)))
        elif driver.startswith("virtio-mem"):
            vmem.append((memdev, sizes.get(memdev), len(dimms)))
    return dimms, vmem


def _numa_memdevs(args: List[str]) -> List[Tuple[str, Optional[int]]]:
    """(memdev id, backend size) per NUMA node in node order, from `-numa node,memdev=` and `-object`."""
    sizes = _backend_sizes(args)
    nodes, implicit = [], 0
    for opt in map(_kv, _options(args, "-numa")):
        if opt.get("", opt.get("type", "node")) != "node":
            continue  # `-numa dist`, `cpu` and `hmat-lb` describe no memory
        nodeid = int(opt["nodeid"]) if opt.get("nodeid", "").isdigit() else implicit
        implicit = nodeid + 1
        if opt.get("memdev"):
            nodes.append((nodeid, opt["memdev"]))
    return [(memdev, sizes.get(memdev)) for _nodeid, memdev in sorted(nodes)]


def _vm_id(argv: List[str]) -> Optional[str]:
    """Proxmox VM ID: from pve-qemu's `-id 100` option, else from `-pidfile /var/run/qemu-server/100.pid`."""
    value = _qemu_option(argv, "-id")
    if value and value.isdigit():
        return value
    match = re.search(r"/qemu-server/(\d+)\.pid$", _qemu_option(argv, "-pidfile") or "")
    return match.group(1) if match else None


def _vm_name(argv: List[str]) -> Optional[str]:
    """`-name` without its sub-options (Proxmox: 'plain,debug-threads=on')."""
    name = _kv(_qemu_option(argv, "-name") or "")
    return name.get("", name.get("guest", "")) or None


# Confidential guests: the guest's RAM is encrypted with a key that the host cannot read (AMD SEV family: held by the
# security processor; Intel TDX: never leaves the CPU). A host image holds only ciphertext of the private memory.
CONFIDENTIAL_OBJECTS = {
    "sev-guest": "SEV",
    "sev-snp-guest": "SEV-SNP",
    "tdx-guest": "TDX",
}
# SEV guest policy bit 2: SEV-ES required (AMD SEV API specification).
SEV_POLICY_ES = 0x4


def _forwards_and_images(argv: List[str]) -> Tuple[List[str], List[str]]:
    """The user-mode network port forwards and the disk / kernel images of the command line."""
    joined = " ".join(argv)
    forwards = re.findall(r"(?:hostfwd|guestfwd)=([^,\s]+)", joined)
    disks = re.findall(r"(?:file|filename)=([^,\s]+)", joined)
    disks += _options(argv, "-hda", "-hdb", "-cdrom", "-kernel", "-initrd")
    return forwards, disks


# Per network backend type, the options that say where its traffic goes. For user mode, `smb=` shares a host
# directory and the port forwards are in the Forwards column. The `stream` and `dgram` types need QEMU 7.2.
NETDEV_KEYS = {
    "user": ("smb",),
    "tap": ("ifname", "fd", "fds", "br"),
    "bridge": ("br",),
    "socket": ("listen", "connect", "mcast", "udp", "localaddr"),
    "stream": ("server", "addr.type", "addr.host", "addr.port", "addr.path"),
    "dgram": ("local.host", "local.port", "remote.host", "remote.port", "local.path"),
    "vde": ("sock",),
    "vhost-user": ("chardev",),
    "l2tpv3": ("src", "dst", "srcport", "dstport"),
}


def _network(argv: List[str]) -> List[str]:
    """The network backends, as type and destination: 'user', 'tap ifname=tap100i0', 'socket connect=10.0.0.5:9000'.

    Read from `-netdev`, `-nic` and the legacy `-net`, whose `nic` entries are guest devices, not backends.
    """
    found = []
    for opt in map(_kv, _options(argv, "-netdev", "-nic", "-net")):
        kind = opt.get("type", opt.get("", ""))
        if kind in ("", "nic", "none"):
            continue
        details = [
            f"{key}={opt[key]}" for key in NETDEV_KEYS.get(kind, ()) if key in opt
        ]
        found.append(" ".join([kind] + details))
    return found


def _server_flag(opt: dict, legacy_parts: List[str]) -> bool:
    """Whether a socket character device listens: `server=on`, or a bare `server` in the legacy syntax."""
    value = opt.get("server", "on" if "server" in legacy_parts else "off")
    return value in ("on", "yes", "true", "")


def _legacy_endpoint(text: str) -> Optional[str]:
    """A `-monitor`, `-serial`, `-qmp` or `-gdb` value as 'unix:/p (listen)', 'tcp:host:port (connect)' or 'stdio'.

    None for none, null and vc, and for 'chardev:ID', whose `-chardev` is listed itself.
    """
    parts = text.split(",")
    head = parts[0]
    if head in ("none", "null", "vc", "") or head.startswith(("chardev:", "vc:")):
        return None
    if head.startswith("mon:"):
        head = head[4:]
    if head.startswith(("unix:", "tcp:", "telnet:", "websocket:")):
        mode = "listen" if _server_flag(_kv(text), parts[1:]) else "connect"
        return f"{head} ({mode})"
    return head


def _chardev_endpoint(opt: dict) -> Optional[str]:
    """A `-chardev socket` as 'unix:/p (listen)' or 'tcp:host:port (connect)'; None for other backends."""
    if opt.get("", opt.get("backend")) != "socket":
        return None
    mode = "listen" if _server_flag(opt, []) else "connect"
    if opt.get("path"):
        return f"unix:{opt['path']} ({mode})"
    scheme = "telnet" if opt.get("telnet") == "on" else "tcp"
    return f"{scheme}:{opt.get('host', '')}:{opt.get('port', '')} ({mode})"


def _control(argv: List[str]) -> List[str]:
    """The channels that control the VM or reach into it, as 'role endpoint'.

    These are the HMP monitor and QMP, serial ports, the gdb stub (full access to guest memory), the guest agent
    channel, other socket character devices and the remote displays (`-vnc`, `-spice`).
    """
    found = []
    for option, role in (
        ("-monitor", "monitor"),
        ("-qmp", "qmp"),
        ("-qmp-pretty", "qmp"),
        ("-serial", "serial"),
        ("-gdb", "gdb"),
    ):
        for value in _options(argv, option):
            # The gdb stub always listens.
            endpoint = _legacy_endpoint(value + (",server=on" if role == "gdb" else ""))
            if endpoint:
                found.append(f"{role} {endpoint}")
    if _has_option(argv, "-s"):  # shorthand for `-gdb tcp::1234`
        found.append("gdb tcp::1234 (listen)")
    # A `-chardev` gets its role from whatever uses it.
    roles = {}
    for opt in map(_kv, _options(argv, "-mon")):
        roles[opt.get("chardev", "")] = (
            "qmp" if opt.get("mode") == "control" else "monitor"
        )
    # `-object monitor-qmp,chardev=` (Proxmox VE 9, QEMU 10+) is the same as `-mon mode=control`.
    for opt in map(_kv, _options(argv, "-object")):
        kind = opt.get("", opt.get("qom-type", ""))
        if kind.startswith("monitor-") and opt.get("chardev"):
            roles[opt["chardev"]] = "qmp" if kind == "monitor-qmp" else "monitor"
    for value in _options(argv, "-serial"):
        if value.startswith("chardev:"):
            roles[value[8:]] = "serial"
    for opt in map(_kv, _options(argv, "-device")):
        if opt.get("chardev"):
            driver = opt.get("", opt.get("driver", "chardev"))
            if opt.get("name", "").startswith("org.qemu.guest_agent"):
                driver = "guest-agent"
            elif driver in ("isa-serial", "pci-serial", "virtconsole"):
                driver = "serial"
            roles.setdefault(opt["chardev"], driver)
    for opt in map(_kv, _options(argv, "-chardev")):
        endpoint = _chardev_endpoint(opt)
        if endpoint:
            found.append(f"{roles.get(opt.get('id', ''), 'chardev')} {endpoint}")
    for value in _options(argv, "-vnc"):
        if value.split(",")[0] != "none":
            found.append(f"vnc {value.split(',')[0]}")
    for opt in map(_kv, _options(argv, "-spice")):
        if opt.get("unix") == "on" or opt.get("") == "unix":
            found.append(f"spice unix:{opt.get('addr', '')}")
        else:
            port = opt.get("port") or opt.get("tls-port", "")
            found.append(f"spice tcp:{opt.get('addr', '')}:{port}")
    # each once: `-s` and `-gdb tcp::1234` are the same
    return list(dict.fromkeys(found))


# --- the versioned interface ----------------------------------------------------------------------


class QemuCmdline(interfaces.configuration.VersionableInterface):
    """What the QEMU plugins ask of a VMM's command line.

    Its version covers the whole module, including `QEMU_OPTIONS`, `CONFIDENTIAL_OBJECTS` and `NETDEV_KEYS`.
    """

    _required_framework_version = (2, 13, 0)
    _version = (1, 0, 0)

    @classmethod
    def looks_like_qemu(cls, argv: List[str]) -> bool:
        """Whether the command line has at least two of QEMU's own options, which works for a renamed binary."""
        return cls.argv_reason(argv) is not None

    @classmethod
    def argv_reason(cls, argv: List[str]) -> Optional[str]:
        """A sentence naming the QEMU options of a command line if there are at least two, else None."""
        names = [_option_name(arg) for arg in argv]
        options = [name for name in names if name in QEMU_OPTIONS]
        if len(options) < 2:
            return None
        return f"command line has QEMU options {' '.join(options)}"

    @classmethod
    def split_command_line(cls, text: str) -> List[str]:
        """Splits a Windows command line (one string from the PEB) into arguments.

        Blanks separate and double quotes group. Backslash-quote escapes are not handled, QEMU does not need them.

        Args:
            text: The command line string from the process's PEB
        """
        return [arg.replace('"', "") for arg in re.findall(r'(?:"[^"]*"|\S)+', text)]

    @classmethod
    def named_machine(cls, args: List[str]) -> Optional[str]:
        """The machine type that the command line names: 'q35', 'pc' or the name as given; None if it names none."""
        opts = _machine_opts(args)
        # Forms seen: 'q35', 'pc-q35-9.2', 'type=q35+pve0,...', 'smm=off,type=...'.
        name = opts.get("type", opts.get("", ""))
        if not name:
            return None
        return "q35" if "q35" in name else ("pc" if name.startswith("pc") else name)

    @classmethod
    def machine_type(cls, args: List[str]) -> str:
        """The machine type of the command line: 'q35', 'pc' or the name as given; 'pc' (the QEMU default) if none.

        Args:
            args: The VMM's command line
        """
        return cls.named_machine(args) or "pc"

    @classmethod
    def accelerator(cls, args: List[str]) -> Optional[str]:
        """The accelerator named on the command line ('kvm', 'whpx', 'hax', 'tcg', ...) as written, or None.

        Args:
            args: The VMM's command line
        """
        if _has_option(args, "-enable-kvm"):
            return "kvm"
        value = _qemu_option(args, "-accel")
        if value:
            return _kv(value).get("", "").split(":")[0] or None
        return _machine_opts(args).get("accel", "").split(":")[0] or None

    @classmethod
    def confidential(cls, argv: List[str]) -> Optional[str]:
        """'SEV', 'SEV-ES', 'SEV-SNP' or 'TDX' if the command line makes the guest a confidential VM, else None.

        QEMU needs `-object sev-guest|sev-snp-guest|tdx-guest,id=X` (libvirt writes it as JSON) and
        `-machine ...,confidential-guest-support=X` (`memory-encryption=X` before QEMU 6). Proxmox `amd-sev` writes
        the same options. An object that the machine does not reference has no effect, so the reference wins.

        Args:
            argv: The VMM's command line
        """
        objects = {}
        for obj in map(_kv, _options(argv, "-object")):
            kind = CONFIDENTIAL_OBJECTS.get(obj.get("", obj.get("qom-type", "")))
            if kind:
                if kind == "SEV":
                    try:
                        kind = (
                            "SEV-ES"
                            if int(obj.get("policy", "0"), 0) & SEV_POLICY_ES
                            else kind
                        )
                    except ValueError:
                        pass
                objects[obj.get("id", "")] = kind
        if not objects:
            return None
        machine = _machine_opts(argv)
        ref = machine.get("confidential-guest-support") or machine.get(
            "memory-encryption"
        )
        if ref:
            return objects.get(ref)
        return next(iter(objects.values()))

    @classmethod
    def ram_size(cls, argv: List[str]) -> Optional[int]:
        """The guest RAM size of `-m` ('2G', '2048', 'size=2G,slots=..') in bytes; a bare number counts MiB."""
        return _parse_size(_qemu_option(argv, "-m") or "")

    @classmethod
    def numa_memdevs(cls, argv: List[str]) -> List[Tuple[str, Optional[int]]]:
        """(memdev id, backend size or None) per NUMA node in node order, from `-numa` and `-object`."""
        return _numa_memdevs(argv)

    @classmethod
    def memory_devices(
        cls, argv: List[str]
    ) -> Tuple[List[Tuple[str, Optional[int]]], List[Tuple[str, Optional[int], int]]]:
        """The memory devices that the command line plugs into the guest, as for `_memory_devices`."""
        return _memory_devices(argv)

    @classmethod
    def argv_values(cls, argv: List[str]) -> Dict[str, object]:
        """The table columns that come from the command line (Name, VMID, Forwards, Network, Control, Images)."""
        forwards, images = _forwards_and_images(argv)
        vmid = _vm_id(argv)
        return {
            "Name": _vm_name(argv) or renderers.NotAvailableValue(),
            "VMID": int(vmid) if vmid else renderers.NotAvailableValue(),
            "Forwards": ", ".join(forwards),
            "Network": ", ".join(_network(argv)),
            "Control": ", ".join(_control(argv)),
            "Images": ", ".join(images),
        }
