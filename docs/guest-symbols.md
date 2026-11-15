# Guest symbols: when `Run` needs a file from you

Volatility reads a kernel through its symbol file (ISF). `linux.qemu_guest.Run` and `windows.qemu_guest.Run` need one
for the guest's kernel, and for the host's kernel too. This page is about the guest. The host's ISF is in the
[main guide](../README.md#setup).

The `Guest banner` column of the `VMs` plugins names the guest kernel: a Linux banner
(`Linux version 6.18.58-0-virt ...`) or, for a Windows guest, `Windows kernel ntkrnlmp.pdb <GUID>-<age>`. An ISF belongs
to exactly one kernel build, and Volatility matches it to the image by this banner.

| Guest | What to do |
|---|---|
| Linux, kernel with BTF and kallsyms (most distributions) | Nothing. [`Run` builds the ISF from the guest's memory](#linux-with-btf-and-kallsyms-nothing-to-do). |
| Windows | Nothing. Volatility downloads the PDB that the banner names (network access once). |
| Linux with a debug package | [dwarf2json](#linux-with-a-debug-package) |
| Linux without debug package, BTF in the kernel file | [btf2json](#linux-without-debug-package-btf-in-the-kernel-file) |
| Linux with neither (Tiny Core) | [rebuild the kernel](#linux-with-neither-btf-nor-debug-package-tiny-core) |

Put every guest ISF in a directory of its own and pass it with `--guest-symbol-dirs`, not `-s`. A host image holds the
guest kernels too, and with a guest ISF in `-s` Volatility may pick the guest kernel for the host. An ISF in
`--guest-symbol-dirs` that matches the banner is used and nothing is built.

## Linux with BTF and kallsyms: nothing to do
The kernel needs `CONFIG_DEBUG_INFO_BTF` and `CONFIG_KALLSYMS_ALL`, on x86-64. The Debian, Ubuntu and Alpine kernels
tested have both. If no ISF that Volatility knows matches the guest's banner, `Run` builds one from the guest's own
memory and logs:
```
guest symbols built from in-memory BTF + kallsyms (9703 types, 141272 symbols, 1.4 s)
```
- `--save-guest-symbols` writes it to the `-o` directory as `<release>.json.xz`. Give that directory to
  `--guest-symbol-dirs` next time, and nothing is built.
- `linux.btf_isf.Build` writes the same file for any Linux image, also a guest ELF written by `--dump` or a host whose
  kernel has no ISF: `mkdir -p isf/linux && vol -o isf/linux -p plugins -f guest.elf linux.btf_isf.Build`. If the image
  holds several kernels, `--release` picks one.
- The ISF has every named struct, union and enum, every kallsyms symbol and the exact `linux_banner`. It validates
  against schema 6.2.0. The guest plugins gave the same output with it as with the dwarf2json or btf2json ISF of the
  same kernel (Debian 5.10 and 6.1, Ubuntu 5.15 and 6.8, Alpine 6.18).
- BTF has no global variables on most kernels. A symbol gets a type only if Volatility or these plugins read it as an
  object, or BTF has it (per-cpu variables). A third-party plugin that reads another global with `object_from_symbol`
  needs a dwarf2json ISF.

Without BTF or kallsyms, `Run` says so in one error line and stops:
```
No symbol table for the guest kernel (<banner>) in --guest-symbol-dirs, and none could be built from its memory: no vmlinux BTF in the image (needs CONFIG_DEBUG_INFO_BTF)
```
Use one of the next sections.

## Linux with a debug package
Make the ISF with [dwarf2json](https://github.com/volatilityfoundation/dwarf2json) from the debug package of exactly
that kernel version (Debian `linux-image-<release>-dbg`, Ubuntu `-dbgsym` from ddebs.ubuntu.com):
```
dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-<release> --system-map /boot/System.map-<release> | xz > guest-isf/<release>.json.xz
```

## Linux without debug package, BTF in the kernel file
Use the kernel's own BTF with [btf2json](https://github.com/vobst/btf2json). This is how the ISF of the Alpine 6.18.58
kernel in the tests was made.
1. Unpack the kernel file (`vmlinuz-virt`, a compressed bzImage) to an ELF `vmlinux`, which has the BTF:
   `python3 tools/extract_vmlinux.py vmlinuz-virt vmlinux`. A zstd-compressed kernel needs Python 3.14.
2. Take the `System.map` of the same kernel (the Alpine ISO has `boot/System.map-6.18.58-0-virt`). btf2json aborts on
   lines of kind `?` (`__nosave_begin`, `__nosave_end`), so delete them.
3. Run `btf2json --btf vmlinux --map System.map --banner "<banner>" > isf.json`. Use the guest's full Linux banner line
   as the `Guest banner` column shows it.
4. Fix the kinds. btf2json 0.1.0 marks the sources in the file's metadata as `symdb` and `btf`, which the schema does
   not allow. With `jsonschema` installed, Volatility then silently finds no symbol table. Set
   `metadata.linux.symbols[].kind` to `system-map` and `metadata.linux.types[].kind` to `dwarf`. A short script that
   edits the JSON does it. Then compress with `xz` and copy the file into the guest symbol directory.

## Linux with neither BTF nor debug package (Tiny Core)
CRON#TRAP's guest ran Tiny Core Linux. Its kernel has no BTF, no kallsyms and no KASLR, and there is no debug package.
Tiny Core does publish the kernel's source, configuration and `System.map`. That is enough, because struct layouts
follow source, configuration and compiler, not the debug options. A rebuild with DWARF added has the shipped kernel's
types.

The steps below were used for CorePure64 16.2 (`6.12.11-tinycore64`):
1. On any x86-64 Linux with docker, build the published source with the published configuration plus
   `CONFIG_DEBUG_INFO_DWARF4`, in the `gcc:14.2.0` image, the kernel's own compiler. Check that the configuration
   differs from the published one only in the debug options and the binutils version, and compare the rebuilt
   `System.map` with the published one (150,368 of 150,398 lines were equal; 30 read-only data symbols lie elsewhere
   with the older binutils).
2. Run `dwarf2json linux --elf vmlinux --system-map System.map` with the published map, so its addresses
   win. Then `tools/isf_from_map.py RAW.json System.map KERNEL OUT.json.xz` keeps only the symbols the published map
   names. The others would carry the rebuild's addresses. It also puts in the shipped kernel's `linux_banner`, read from
   `KERNEL` (the ELF or the bzImage). The rebuild's own banner names the build container and date, so Volatility would
   never match it to the image.
3. `tools/cmp_isf.py A.json.xz B.json.xz` compares two ISFs of one kernel: the types and symbols Volatility reads,
   and the banner.

Without KASLR the map's addresses are the running kernel's. With KASLR, Volatility finds the shift itself, as for any
Linux image with a System.map-based ISF. `isf_from_map.py` works for every kernel whose vendor publishes source,
configuration and `System.map`.

## Where the kernel files are
The `Images` column of the `VMs` plugins lists the VM's disk, kernel and initrd files (`-hda`, `-cdrom`, `-kernel`,
`-initrd`, ...). If the host has them, take them from there. If not, the host image may still hold them as far as they
were cached: `linux.pagecache.Files` lists them and `linux.pagecache.InodePages --inode <InodeAddr> --dump` writes them.
The initrd of a test guest came back byte for byte.

## The banner column
The `Guest banner` column shows the first complete Linux banner in guest RAM. Since Linux 6.1 a kernel image holds a
second, weak `linux_banner` without build number and date (`... # SMP `). It can come first. The column skips it, and
`Run` takes a guest ISF that matches any banner of the guest, as Volatility's own stackers do.
