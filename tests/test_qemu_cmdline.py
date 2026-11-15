"""Unit tests for qemu_cmdline: what a QEMU command line says, table-driven, without any memory image."""

import pytest
from volatility3.framework import renderers
from volatility3.plugins import qemu_cmdline

Cmd = qemu_cmdline.QemuCmdline
MIB, GIB = 1 << 20, 1 << 30


# --- options ---------------------------------------------------------------------------------------------


def test_options_take_both_spellings():
    argv = ["qemu", "--numa", "node,memdev=a", "-m", "1G", "--m", "2G", "-numa", "x"]
    assert qemu_cmdline._options(argv, "-numa", "-m") == [
        "node,memdev=a",
        "1G",
        "2G",
        "x",
    ]
    assert qemu_cmdline._qemu_option(argv, "-m") == "2G"
    assert qemu_cmdline._options(["--nic"], "-nic") == []  # no value
    assert qemu_cmdline._qemu_option(["qemu"], "-m") is None


@pytest.mark.parametrize(
    "text, expected",
    [
        ("word,a=1,b=2", {"": "word", "a": "1", "b": "2"}),
        ("a=1,flag,b=2", {"a": "1", "b": "2"}),
        ("", {"": ""}),  # no option at all
        (
            '{"qom-type": "sev-guest", "policy": 5}',
            {"qom-type": "sev-guest", "policy": "5"},
        ),
        ("{not json", {}),
    ],
)
def test_kv(text, expected):
    assert qemu_cmdline._kv(text) == expected


# --- _parse_size -----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text, bare_unit, expected",
    [
        ("256", MIB, 256 * MIB),  # `-m` counts MiB
        ("256M", MIB, 256 * MIB),
        ("2G", MIB, 2 * GIB),
        ("2g", MIB, 2 * GIB),
        ("1.5G", MIB, 3 * GIB // 2),
        ("512k", MIB, 512 << 10),
        ("1T", MIB, 1 << 40),
        ("size=2G,slots=2,maxmem=4G", MIB, 2 * GIB),
        ("4096", 1, 4096),  # `-object memory-backend-ram,size=`: bytes
        ("16M", 1, 16 * MIB),
        ("", MIB, None),
        ("abc", MIB, None),
        ("G", MIB, None),
    ],
)
def test_parse_size(text, bare_unit, expected):
    assert qemu_cmdline._parse_size(text, bare_unit) == expected


@pytest.mark.parametrize(
    "argv, expected",
    [
        (["qemu", "-m", "2G"], 2 * GIB),
        (["qemu", "-m", "size=1G,slots=4,maxmem=8G"], GIB),
        (["qemu", "-m", "512"], 512 * MIB),
        (["qemu", "-m", "512", "--m", "1G"], GIB),  # the last one counts
        (["qemu"], None),
        (["qemu", "-m", "lots"], None),
    ],
)
def test_ram_size(argv, expected):
    assert Cmd.ram_size(argv) == expected


# --- machine type, accelerator, "looks like QEMU" ----------------------------------------------------------


@pytest.mark.parametrize(
    "argv, named, machine",
    [
        ([], None, "pc"),
        (["-machine", "q35"], "q35", "q35"),
        (["--machine", "q35"], "q35", "q35"),
        (["-M", "pc-q35-9.2"], "q35", "q35"),
        (["-machine", "type=q35+pve0,smm=off"], "q35", "q35"),
        (["-machine", "smm=off,type=q35"], "q35", "q35"),
        (["-machine", "type=pc-i440fx-8.0,accel=kvm"], "pc", "pc"),
        (["-machine", "pc"], "pc", "pc"),
        (["-machine", "accel=kvm"], None, "pc"),  # names no type
        (["-machine", "virt"], "virt", "virt"),
        (["-machine", "microvm,rtc=on"], "microvm", "microvm"),
    ],
)
def test_named_machine_and_machine_type(argv, named, machine):
    assert Cmd.named_machine(argv) == named
    assert Cmd.machine_type(argv) == machine


@pytest.mark.parametrize(
    "argv, expected",
    [
        (["qemu", "-m", "1G"], False),  # one QEMU option is not enough
        (["python", "-m", "pip"], False),
        (["x", "-m", "1G", "-machine", "q35"], True),
        (["x", "--m", "1G", "--machine", "q35"], True),  # QEMU takes both spellings
        (["x", "-enable-kvm", "-nographic"], True),
        (["ls", "-l", "-a"], False),
        ([], False),
    ],
)
def test_looks_like_qemu(argv, expected):
    assert Cmd.looks_like_qemu(argv) is expected
    assert (Cmd.argv_reason(argv) is not None) is expected


def test_argv_reason_names_the_options():
    assert "-m -machine" in Cmd.argv_reason(["x", "-m", "1G", "--machine", "q35"])


@pytest.mark.parametrize(
    "argv, expected",
    [
        (["-enable-kvm"], "kvm"),
        (["--enable-kvm"], "kvm"),
        (["-accel", "kvm,thread=multi"], "kvm"),
        (["-accel", "tcg"], "tcg"),
        (["-machine", "q35,accel=whpx:tcg"], "whpx"),
        (["-machine", "q35"], None),
        ([], None),
    ],
)
def test_accelerator(argv, expected):
    assert Cmd.accelerator(argv) == expected


def test_split_command_line():
    line = (
        r'C:\q\qemu.exe -m 256 -drive "file=C:\Program Files\d.img,if=ide"  -accel tcg'
    )
    assert Cmd.split_command_line(line) == [
        r"C:\q\qemu.exe",
        "-m",
        "256",
        "-drive",
        r"file=C:\Program Files\d.img,if=ide",
        "-accel",
        "tcg",
    ]
    assert Cmd.split_command_line("") == []


# --- confidential guests -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv, expected",
    [
        ([], None),
        (["-object", "memory-backend-ram,id=m,size=1G"], None),
        (
            [
                "-object",
                "sev-guest,id=s0,cbitpos=51",
                "-machine",
                "q35,confidential-guest-support=s0",
            ],
            "SEV",
        ),
        (
            [
                "-object",
                "sev-guest,id=s0,policy=0x5",
                "-machine",
                "q35,confidential-guest-support=s0",
            ],
            "SEV-ES",
        ),
        (["-object", "sev-guest,id=s0,policy=0x1"], "SEV"),
        (["-object", "sev-guest,id=s0,policy=zz"], "SEV"),
        (
            [
                "-object",
                "sev-snp-guest,id=s0",
                "-machine",
                "q35,confidential-guest-support=s0",
            ],
            "SEV-SNP",
        ),
        (
            [
                "-object",
                "tdx-guest,id=t0",
                "-machine",
                "q35,confidential-guest-support=t0",
            ],
            "TDX",
        ),
        (
            ["-object", "sev-guest,id=s0", "-machine", "pc,memory-encryption=s0"],
            "SEV",
        ),  # before QEMU 6
        (["-object", '{"qom-type": "sev-guest", "id": "s0", "policy": 5}'], "SEV-ES"),
        # an object the machine does not reference has no effect
        (
            [
                "-object",
                "tdx-guest,id=t0",
                "-machine",
                "q35,confidential-guest-support=other",
            ],
            None,
        ),
        # no reference: the object counts
        (["-object", "sev-snp-guest,id=s0", "-machine", "q35"], "SEV-SNP"),
    ],
)
def test_confidential(argv, expected):
    assert Cmd.confidential(argv) == expected


# --- memory devices ------------------------------------------------------------------------------------------


def test_numa_memdevs_in_node_order():
    argv = [
        "-numa", "node,nodeid=1,memdev=m1",
        "-numa", "node,nodeid=0,memdev=m0",
        "-numa", "dist,src=0,dst=1,val=20",
        "-numa", "node,nodeid=2",  # no memdev: not a backend
        "-numa", "node,memdev=m3",  # the next free node id
        "-object", "memory-backend-ram,id=m0,size=1G",
        "-object", "memory-backend-file,id=m1,size=2G,mem-path=/dev/hugepages",
    ]  # fmt: skip
    assert Cmd.numa_memdevs(argv) == [("m0", GIB), ("m1", 2 * GIB), ("m3", None)]


def test_memory_devices_come_from_one_walk_in_plug_order():
    argv = [
        "-object", "memory-backend-ram,id=d0,size=512M",
        "-object", "memory-backend-ram,id=v0,size=1G",
        "-object", "memory-backend-ram,id=d1,size=256M",
        "-object", "memory-backend-ram,id=d2,size=256M",
        "-device", "pc-dimm,id=dimm0,memdev=d0",
        "-device", "virtio-net-pci,netdev=n0",
        "-device", "virtio-mem-pci,id=vm0,memdev=v0",
        "-device", "pc-dimm,id=dimm1,memdev=d1",
        "-device", "pc-dimm,memdev=d2,addr=0x100000000",  # placed by the user
        "-device", "pc-dimm,id=dimm3",  # no memdev
    ]  # fmt: skip
    dimms, vmem = Cmd.memory_devices(argv)
    assert dimms == [("d0", 512 * MIB), ("d1", 256 * MIB)]
    assert vmem == [("v0", GIB, 1)]  # one pc-dimm before it
    assert Cmd.memory_devices([]) == ([], [])


def test_memory_devices_without_a_size_have_none():
    dimms, vmem = Cmd.memory_devices(["-device", "pc-dimm,memdev=gone"])
    assert dimms == [("gone", None)] and vmem == []


# --- the table columns -----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv, expected",
    [
        (
            ["-netdev", "user,id=n0,hostfwd=tcp::2222-:22,smb=/srv/share"],
            ["user smb=/srv/share"],
        ),
        (["-netdev", "tap,id=n1,ifname=tap100i0,script=no"], ["tap ifname=tap100i0"]),
        (["-netdev", "bridge,id=n2,br=virbr0"], ["bridge br=virbr0"]),
        (
            ["-netdev", "socket,id=n3,connect=10.0.0.5:9000"],
            ["socket connect=10.0.0.5:9000"],
        ),
        (["-netdev", "vhost-user,id=n4,chardev=c0"], ["vhost-user chardev=c0"]),
        (
            ["-netdev", '{"type": "tap", "id": "n5", "ifname": "tap7"}'],
            ["tap ifname=tap7"],
        ),
        (["-nic", "user"], ["user"]),
        (["-nic", "none"], []),
        (
            ["-net", "nic,model=virtio", "-net", "socket,connect=10.0.0.5:9000"],
            ["socket connect=10.0.0.5:9000"],
        ),
        (["-device", "virtio-net-pci,netdev=n0"], []),
        (["-netdev", "hubport,id=h0,hubid=0"], ["hubport"]),
        ([], []),
    ],
)
def test_network(argv, expected):
    assert qemu_cmdline._network(argv) == expected


@pytest.mark.parametrize(
    "argv, forwards, images",
    [
        (
            ["-netdev", "user,id=n,hostfwd=tcp::2222-:22,hostfwd=udp::53-:53"],
            ["tcp::2222-:22", "udp::53-:53"],
            [],
        ),
        (
            ["-netdev", "user,id=n,guestfwd=tcp:10.0.2.100:1234-cmd:nc"],
            ["tcp:10.0.2.100:1234-cmd:nc"],
            [],
        ),
        (
            [
                "-drive",
                "file=/d/root.qcow2,if=virtio",
                "-drive",
                "if=none,filename=/d/b.img",
            ],
            [],
            ["/d/root.qcow2", "/d/b.img"],
        ),
        (
            [
                "-hda",
                "/d/a.img",
                "-cdrom",
                "/iso/x.iso",
                "-kernel",
                "/k/vmlinuz",
                "-initrd",
                "/k/initrd",
            ],
            [],
            ["/d/a.img", "/iso/x.iso", "/k/vmlinuz", "/k/initrd"],
        ),
        (["-m", "1G"], [], []),
    ],
)
def test_forwards_and_images(argv, forwards, images):
    assert qemu_cmdline._forwards_and_images(argv) == (forwards, images)


@pytest.mark.parametrize(
    "argv, expected",
    [
        (
            ["-monitor", "unix:/tmp/m.sock,server=on,wait=off"],
            ["monitor unix:/tmp/m.sock (listen)"],
        ),
        (["-monitor", "tcp:1.2.3.4:5"], ["monitor tcp:1.2.3.4:5 (connect)"]),
        (
            ["-qmp", "tcp:127.0.0.1:4444,server,nowait"],
            ["qmp tcp:127.0.0.1:4444 (listen)"],
        ),
        (
            ["-monitor", "telnet:127.0.0.1:55,server"],
            ["monitor telnet:127.0.0.1:55 (listen)"],
        ),
        (["-monitor", "mon:stdio"], ["monitor stdio"]),
        (["-serial", "stdio"], ["serial stdio"]),
        (["-serial", "none", "-monitor", "null", "-qmp", "chardev:c"], []),
        (["-s"], ["gdb tcp::1234 (listen)"]),
        (["--s"], ["gdb tcp::1234 (listen)"]),
        (["-s", "-gdb", "tcp::1234"], ["gdb tcp::1234 (listen)"]),  # each once
        (["-gdb", "tcp::9000"], ["gdb tcp::9000 (listen)"]),
        (
            [
                "-chardev",
                "socket,id=qga0,path=/run/qga.sock,server=on,wait=off",
                "-device",
                "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
            ],
            ["guest-agent unix:/run/qga.sock (listen)"],
        ),
        (
            ["-chardev", "socket,id=c1,host=10.0.0.1,port=99"],
            ["chardev tcp:10.0.0.1:99 (connect)"],
        ),
        (
            ["-chardev", "socket,id=c1,host=10.0.0.1,port=99,server=on,telnet=on"],
            ["chardev telnet:10.0.0.1:99 (listen)"],
        ),
        (["-chardev", "stdio,id=c1"], []),  # not a socket
        (
            [
                "-mon",
                "chardev=c2,mode=control",
                "-chardev",
                "socket,id=c2,path=/q,server=on",
            ],
            ["qmp unix:/q (listen)"],
        ),
        (
            ["-mon", "chardev=c2", "-chardev", "socket,id=c2,path=/q,server=on"],
            ["monitor unix:/q (listen)"],
        ),
        (
            [
                "-object",
                "monitor-qmp,id=m,chardev=c3",
                "-chardev",
                "socket,id=c3,path=/q3,server=on",
            ],
            ["qmp unix:/q3 (listen)"],
        ),
        (
            ["-serial", "chardev:s0", "-chardev", "socket,id=s0,path=/s,server=on"],
            ["serial unix:/s (listen)"],
        ),
        (["-vnc", "127.0.0.1:1,password=on"], ["vnc 127.0.0.1:1"]),
        (["-vnc", "none"], []),
        (["-spice", "port=5900,addr=127.0.0.1"], ["spice tcp:127.0.0.1:5900"]),
        (["-spice", "unix=on,addr=/run/spice.sock"], ["spice unix:/run/spice.sock"]),
        ([], []),
    ],
)
def test_control(argv, expected):
    assert qemu_cmdline._control(argv) == expected


def test_argv_values_are_the_command_line_columns():
    argv = [
        "qemu-system-x86_64", "-id", "100", "-name", "web,debug-threads=on",
        "-netdev", "user,id=n,hostfwd=tcp::2222-:22", "-hda", "/d.img", "-vnc", "none",
    ]  # fmt: skip
    values = Cmd.argv_values(argv)
    assert values == {
        "Name": "web",
        "VMID": 100,
        "Forwards": "tcp::2222-:22",
        "Network": "user",
        "Control": "",
        "Images": "/d.img",
    }
    empty = Cmd.argv_values(["qemu"])
    assert isinstance(empty["Name"], renderers.NotAvailableValue)
    assert isinstance(empty["VMID"], renderers.NotAvailableValue)


@pytest.mark.parametrize(
    "argv, expected",
    [
        (["-id", "100"], "100"),
        (["-pidfile", "/var/run/qemu-server/101.pid"], "101"),
        (["-id", "x", "-pidfile", "/run/other.pid"], None),
        ([], None),
    ],
)
def test_vm_id(argv, expected):
    assert qemu_cmdline._vm_id(argv) == expected


def test_the_component_is_versioned():
    assert Cmd.version == (1, 0, 0)
