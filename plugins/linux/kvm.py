# This file is Copyright 2026 Michael Külper and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
#
"""Finds every KVM virtual machine in a Linux host memory image through the host kernel's own KVM structures.

KVM keeps one `struct kvm` per VM, on the global list `vm_list` of kvm.ko and behind the `kvm-vm` file of the process
that created it. It holds the exact guest-physical memory map (memslots: guest address -> address in the creating
process) and every vCPU. The VMM does not matter (QEMU, Firecracker, cloud-hypervisor, crosvm), and a renamed or
hidden VMM process is found as well. Volatility's ISFs have no kvm.ko types, so the structure layouts are read from
the BTF of the loaded kvm_amd or kvm_intel module (plugins/kernel_btf.py).
"""

import datetime
import functools
import logging
from typing import Dict, Iterator, List, NamedTuple, Optional, Tuple

from volatility3.framework import exceptions, interfaces, objects, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import linux
from volatility3.plugins import kernel_btf, qemu_common
from volatility3.plugins.linux import pslist, qemu

vollog = logging.getLogger(__name__)

KVM_MEM_LOG_DIRTY_PAGES, KVM_MEM_READONLY = 1, 2  # include/uapi/linux/kvm.h
# Memslots that KVM creates for itself have the highest ids: on Intel the APIC access page, and the TSS and identity
# map without unrestricted guest. The VMM can use KVM_MEM_SLOTS_NUM - KVM_INTERNAL_MEM_SLOTS ids
# (include/linux/kvm_host.h).
KVM_INTERNAL_MEM_SLOTS = 3  # arch/x86/include/asm/kvm_host.h
# SHRT_MAX (include/linux/kvm_host.h). If `kvm_memslots.id_to_index[]` exists, its size is used instead.
KVM_MEM_SLOTS_NUM = 32767
# The `Vm.confidential` labels whose vCPU state the host cannot read: SEV-ES and SEV-SNP keep the registers in the
# encrypted VMSA, TDX in the TD's private state (its vCPU struct is `vcpu_tdx`, not `vcpu_vmx`). Plain SEV
# encrypts only the guest's RAM, so its VMCB is readable.
ENCRYPTED_VCPU_STATE = ("SEV-ES", "SEV-SNP", "TDX")
# enum kvm_vcpu_mode
MODES = ["outside guest", "in guest", "exiting guest", "reading page tables"]
# KVM's register cache: `kvm_vcpu.arch.regs_avail` says which cached values are current, indexed by these enum
# constants (arch/x86/include/asm/kvm_host.h, kvm_vcpu_regs.h). The Intel VMCS has no layout that can be read.
CACHED_REGS = {
    "rip": "VCPU_REGS_RIP",
    "rsp": "VCPU_REGS_RSP",
    "cr0": "VCPU_EXREG_CR0",
    "cr3": "VCPU_EXREG_CR3",
    "cr4": "VCPU_EXREG_CR4",
}
# The basic exit reason is the low 16 bits of `vcpu_vmx.exit_reason` (arch/x86/include/asm/vmx.h).
VMX_EXIT_REASON_MASK = 0xFFFF
# The common exits only, from arch/x86/include/uapi/asm/svm.h (exit codes) and vmx.h (basic exit reasons).
SVM_EXITS = {
    0x60: "INTR",
    0x72: "CPUID",
    0x78: "HLT",
    0x7B: "IOIO",
    0x7C: "MSR",
    0x7F: "SHUTDOWN",
    0x400: "NPF",
}
VMX_EXITS = {
    0: "EXCEPTION_NMI",
    1: "EXTERNAL_INTERRUPT",
    2: "TRIPLE_FAULT",
    7: "INTERRUPT_WINDOW",
    10: "CPUID",
    12: "HLT",
    18: "VMCALL",
    28: "CR_ACCESS",
    30: "IO_INSTRUCTION",
    31: "MSR_READ",
    32: "MSR_WRITE",
    33: "INVALID_STATE",
    36: "MWAIT",
    40: "PAUSE",
    44: "APIC_ACCESS",
    48: "EPT_VIOLATION",
    49: "EPT_MISCONFIG",
    52: "PREEMPTION_TIMER",
}


class Slot(NamedTuple):
    as_id: int  # address space: 0 normal, 1 SMM (x86)
    id: int
    gfn: int  # first guest page frame
    npages: int
    hva: int  # address in the creating process
    flags: int
    internal: bool  # created by KVM itself, not by the VMM: no guest RAM

    @property
    def gpa(self) -> int:
        return self.gfn * qemu_common.PAGE

    @property
    def size(self) -> int:
        return self.npages * qemu_common.PAGE

    @property
    def readonly(self) -> bool:
        return bool(self.flags & KVM_MEM_READONLY)


class Vcpu(NamedTuple):
    id: int
    tid: Optional[int]  # thread that runs it (set at the first KVM_RUN)
    mode: str
    regs: Dict[str, Optional[int]]  # rip, rsp, cr0, cr3, cr4, efer, (AMD) cpl, cs
    # of the last VM exit: SVM exit code, or VMX basic exit reason
    exit_code: Optional[int]
    source: str  # "VMCB", "cached" or "encrypted"
    stale: List[str]  # cached registers that are not current


class SlotBlock(qemu_common.RamBlock):
    """The host memory of one memslot: `npages` pages at `hva` of the VMM's address space.

    A slot can span several VMAs, because QEMU splits them with madvise. A file-backed VMA (memfd, hugetlbfs) may
    have pages that are in the page cache but not in the page tables. They are the fallback, as in linux.qemu.
    `file_backed` tells whether any VMA of the slot is file-backed.
    """

    def __init__(self, layer, slot: Slot, vmas: List[qemu.LinuxRamBlock]):
        self.vmas = [
            v
            for v in vmas
            if v.start < slot.hva + slot.size and v.start + v.size > slot.hva
        ]
        self.file_backed = any(v.file_backed for v in self.vmas)
        names = sorted({v.backing for v in self.vmas}) or ["unmapped"]
        super().__init__(
            layer,
            slot.hva,
            slot.size,
            ", ".join(names),
            self._cached_page if self.file_backed else None,
        )

    def load_page_cache(self) -> None:
        """Reads the page-cache index of each file-backed VMA of the slot (see `LinuxRamBlock.load_page_cache`)."""
        for vma in self.vmas:
            vma.load_page_cache()

    def _reason(self, entry: int, bits: int) -> str:
        return qemu.linux_pte_reason(entry, bits) or super()._reason(entry, bits)

    def _cached_page(self, offset: int):
        va = self.start + offset
        for vma in self.vmas:
            if vma.start <= va < vma.start + vma.size:
                return vma.cached_page(va - vma.start)
        return None


class Vm:
    """One `struct kvm`, read through the symbol table built from the KVM module's BTF."""

    def __init__(
        self,
        host: "Host",
        addr: int,
        in_list: bool,
        fd_holders: List[interfaces.objects.ObjectInterface],
        tasks_by_mm: Dict[int, interfaces.objects.ObjectInterface],
    ):
        """`addr` is the `struct kvm`, `in_list` tells whether it is on vm_list, `fd_holders` are the tasks that hold a
        kvm-vm file for it and `tasks_by_mm` maps each listed task's mm_struct address to the task.
        """
        self.host = host
        self.addr = addr
        self.in_list = in_list
        self.fd_holders = fd_holders
        self.kvm = host.object("kvm", addr)
        self.mm = host.layer.canonicalize(int(self.kvm.mm))
        self.userspace_pid = int(self.kvm.userspace_pid)
        # The process whose mm this VM uses; None if it is hidden from the task list.
        self.task = tasks_by_mm.get(self.mm)
        # The name of the process layer once `process_layer` made it; None if it cannot be made.
        self._layer_name: Optional[str] = None
        self._layer_made = False

    @property
    def pid(self) -> int:
        return int(self.task.pid) if self.task else self.userspace_pid

    @property
    def online_vcpus(self) -> int:
        return int(self.kvm.online_vcpus.counter)

    def confidential(self) -> Optional[str]:
        """'SEV', 'TDX', ... as for linux.qemu, from the owner's command line and guest_memfd files.

        Returns:
            The label, or None for a guest that is not confidential or whose owner is hidden (no command line)
        """
        layer_name = self.process_layer()
        if self.task is None or layer_name is None:
            return None
        context, symbol_table = self.host.context, self.host.kernel.symbol_table_name
        names = [n for n, _ in qemu.VMs.kvm_files(context, symbol_table, self.task)]
        return qemu.VMs.confidential_label(
            qemu.VMs.read_argv(context, self.task, layer_name), names
        )

    # --- memory map -----------------------------------------------------------------------------------

    @functools.cached_property
    def slots(self) -> List[Slot]:
        """All memslots of all address spaces (include/linux/kvm_host.h), sorted by address space and guest address."""
        found = []
        for as_id, memslots in enumerate(self.kvm.memslots):
            if not memslots:
                continue
            ms = memslots.dereference()
            slots_num = (
                len(ms.id_to_index)
                if ms.has_member("id_to_index")
                else KVM_MEM_SLOTS_NUM
            )
            for s in self._memory_slots(ms):
                slot_id = int(s.id)
                found.append(
                    Slot(
                        as_id,
                        slot_id,
                        int(s.base_gfn),
                        int(s.npages),
                        int(s.userspace_addr),
                        int(s.flags),
                        slot_id >= slots_num - KVM_INTERNAL_MEM_SLOTS,
                    )
                )
        return sorted((f for f in found if f.npages), key=lambda f: (f.as_id, f.gfn))

    def _memory_slots(
        self, ms: interfaces.objects.ObjectInterface
    ) -> Iterator[interfaces.objects.ObjectInterface]:
        host = self.host
        slot_type = host.context.symbol_space.get_type(
            host.type_name("kvm_memory_slot")
        )
        # Before Linux 5.17 the slots are an array and the first `used_slots` are in use. `memslots` is a flexible
        # array member there, which BTF gives no element, so each slot is built at its offset instead of indexed.
        if not ms.has_member("gfn_tree"):
            first = ms.memslots.vol.offset
            for i in range(int(ms.used_slots)):
                yield host.object("kvm_memory_slot", first + i * slot_type.size)
            return
        # From 5.17 they are an rb-tree linked through `gfn_node[node_idx]`, so the node's slot is a container_of.
        node_offset = (
            slot_type.relative_child_offset("gfn_node")
            + int(ms.node_idx) * host.kernel.get_type("rb_node").size
        )
        for node in ms.gfn_tree.get_nodes():
            try:
                yield host.object("kvm_memory_slot", int(node) - node_offset)
            except exceptions.InvalidAddressException:
                continue

    def process_layer(self) -> Optional[str]:
        """The layer with the page tables of the creating process, built from `kvm->mm`; None if unreadable.

        This works when the task is hidden. It repeats the steps of `task.add_process_layer`, which needs a
        task_struct: a copy of the kernel layer's configuration with the process's page table base. The layer is made
        once per VM.
        """
        if self._layer_made:
            return self._layer_name
        self._layer_made = True
        context = self.host.context
        name = context.layers.free_layer_name(f"kvm_{self.addr:x}")
        try:
            mm = self.host.kernel.object("mm_struct", offset=self.mm, absolute=True)
            dtb, _layer = self.host.layer.translate(int(mm.pgd))
        except exceptions.InvalidAddressException:
            return None
        parent = self.host.layer
        config = parent.build_configuration()
        config["memory_layer"] = parent.config["memory_layer"]
        config["page_map_offset"] = dtb
        config_path = interfaces.configuration.path_join("linux_kvm", name)
        context.config.splice(config_path, config)
        context.layers.add_layer(
            parent.__class__(context, config_path=config_path, name=name)
        )
        self._layer_name = name
        return name

    @functools.cached_property
    def blocks(self) -> Dict[Slot, SlotBlock]:
        """The host memory of every memslot, read through the page tables of kvm->mm."""
        layer_name = self.process_layer()
        if layer_name is None:
            return {}
        mm = self.host.kernel.object("mm_struct", offset=self.mm, absolute=True)
        vmas = []
        for vma in qemu_common.QemuCommon.vmas(mm):
            try:
                name = (
                    vma.vm_file.get_dentry().d_name.name_as_str()
                    if vma.vm_file
                    else "anonymous"
                )
            except exceptions.InvalidAddressException:
                name = "file"
            vmas.append(qemu.LinuxRamBlock(self.host.context, layer_name, vma, name))
        layer = self.host.context.layers[layer_name]
        return {s: SlotBlock(layer, s, vmas) for s in self.slots}

    def ram(
        self, as_id: int = 0
    ) -> Optional[Tuple[qemu_common.GuestRam, List[qemu_common.Segment]]]:
        """The guest-physical memory of an address space as `GuestRam` and segments, one block per memslot."""
        slots = [s for s in self.slots if s.as_id == as_id and not s.internal]
        if not slots or not self.blocks:
            return None
        segments, offset = [], 0
        for s in slots:
            segments.append(qemu_common.Segment(s.gpa, offset, s.size))
            offset += s.size
        return qemu_common.GuestRam([self.blocks[s] for s in slots]), segments

    def smram_pages(self) -> int:
        """Pages of the SMM address space (SMRAM) that address space 0 does not map the same way.

        These have the same guest address but different host memory, or none.
        """
        total = 0
        for s in (s for s in self.slots if s.as_id == 1 and not s.internal):
            free = [(s.gfn, s.gfn + s.npages)]
            for o in (
                o for o in self.slots if o.as_id == 0 and o.hva - o.gpa == s.hva - s.gpa
            ):
                # Cut out what address space 0 maps identically.
                lo, hi = o.gfn, o.gfn + o.npages
                free = [
                    p
                    for a, b in free
                    for p in ((a, min(b, lo)), (max(a, hi), b))
                    if p[0] < p[1]
                ]
            total += sum(b - a for a, b in free)
        return total

    def guest(self, as_id: int = 0) -> Optional[qemu_common.GuestVM]:
        """The VM as a `GuestVM`, which linux.qemu_guest.Run can open and the ELF dump can write.

        Args:
            as_id: The address space: 0 normal, 1 SMM (x86)

        Returns:
            The guest, or None if the address space has no guest RAM or the owner's memory is unreadable
        """
        ram = self.ram(as_id)
        return (
            qemu_common.GuestVM(self.pid, ram[0], ram[1], "KVM memslots")
            if ram
            else None
        )

    # --- vCPUs ----------------------------------------------------------------------------------------

    def vcpus(self, encrypted: bool = False) -> Iterator[Vcpu]:
        """Every vCPU of the VM with its thread, mode, registers and last exit.

        Args:
            encrypted: The VM's vCPU state is encrypted (see `ENCRYPTED_VCPU_STATE`): no registers and no exit, and
                the source is "encrypted"
        """
        host = self.host
        # an xarray of `struct kvm_vcpu *` from Linux 5.16
        if self.kvm.has_member("vcpu_array"):
            xarray = linux.XArray(host.context, host.kernel_name)
            addrs = list(xarray.get_entries(self.kvm.vcpu_array))
        else:  # before that `kvm.vcpus[]`, of which `online_vcpus` are used
            addrs = [int(p) for p in self.kvm.vcpus[: self.online_vcpus] if p]
        for addr in addrs:
            cpu = host.object("kvm_vcpu", addr)
            # The thread that runs it is `pid->numbers[0].nr`. `numbers` is a flexible array member, so its first
            # element is read as a `upid` of its own.
            tid = None
            if cpu.pid:
                numbers = cpu.pid.dereference().numbers.vol.offset
                tid = int(host.kernel.object("upid", offset=numbers, absolute=True).nr)
            mode = int(cpu.mode)
            if encrypted:
                regs, exit_code, source, stale = {}, None, "encrypted", []
            else:
                regs, exit_code, source, stale = self._registers(cpu)
            yield Vcpu(
                int(cpu.vcpu_id),
                tid,
                MODES[mode] if 0 <= mode < len(MODES) else str(mode),
                regs,
                exit_code,
                source,
                stale,
            )

    def _registers(
        self, cpu: interfaces.objects.ObjectInterface
    ) -> Tuple[Dict[str, Optional[int]], Optional[int], str, List[str]]:
        """(registers, last exit code, source, stale registers).

        AMD: the VMCB, which the CPU wrote at the last #VMEXIT, so the values are exact (arch/x86/kvm/svm/svm.h).
        Intel: the registers that KVM caches in `kvm_vcpu.arch`, and `vcpu_vmx.exit_reason`. KVM reads RIP, RSP and
        CR0/3/4 from the VMCS only when it needs them, and `regs_avail` says which are current. Most are for a VM
        that its VMM has stopped. The others are the stale ones.
        Any other vendor (the fallback `kvm` module, whose BTF has no vcpu_vmx): the cached registers, no exit code.
        """
        host = self.host
        if host.vendor == "kvm_amd":
            # `kvm_vcpu` is the first member of `vcpu_svm`.
            svm = host.object("vcpu_svm", cpu.vol.offset)
            if not svm.vmcb:
                return {}, None, "VMCB", []
            vmcb = svm.vmcb.dereference()
            save, code = vmcb.save, int(vmcb.control.exit_code)
            regs = {
                k: int(getattr(save, k))
                for k in ("rip", "rsp", "cr0", "cr3", "cr4", "efer", "cpl")
            }
            return {**regs, "cs": int(save.cs.selector)}, code, "VMCB", []
        arch = cpu.arch
        # EFER is KVM's own copy and never stale.
        avail, regs = int(arch.regs_avail), {"efer": int(arch.efer)}
        stale = []
        for name, constant in CACHED_REGS.items():
            bit = host.enumerators.get(constant)
            # Not in this kernel's BTF: where it is and whether it is current are unknown.
            if bit is None:
                continue
            regs[name] = int(
                arch.regs[bit] if name in ("rip", "rsp") else getattr(arch, name)
            )
            if not avail >> bit & 1:
                stale.append(name.upper())
        return regs, self._vmx_exit_reason(cpu), "cached", stale

    def _vmx_exit_reason(
        self, cpu: interfaces.objects.ObjectInterface
    ) -> Optional[int]:
        """The basic exit reason of the vCPU's last VM exit from `vcpu_vmx` (Intel), or None."""
        if self.host.vendor != "kvm_intel":
            return None
        try:
            # `kvm_vcpu` is the first member of `vcpu_vmx`. `exit_reason` is a union from Linux 5.11, else a u32.
            reason = self.host.object("vcpu_vmx", cpu.vol.offset).exit_reason
        except (exceptions.SymbolError, kernel_btf.BtfError, AttributeError) as excp:
            vollog.debug("vcpu_vmx: %s", excp)
            return None
        if isinstance(reason, objects.AggregateType):
            reason = reason.full
        return int(reason) & VMX_EXIT_REASON_MASK


class Host:
    """The kernel's KVM: a symbol table built from the BTF of the loaded KVM module, and the VMs found with it."""

    def __init__(self, context: interfaces.context.ContextInterface, kernel_name: str):
        self.context, self.kernel_name = context, kernel_name
        self.kernel = context.modules[kernel_name]
        self.layer = context.layers[self.kernel.layer_name]
        # The vendor module's BTF has the kvm types too.
        for vendor in ("kvm_amd", "kvm_intel", "kvm"):
            try:
                self.table = kernel_btf.KernelBtf.module_symbol_table(
                    context, kernel_name, vendor
                )
                self.vendor = vendor
                break
            except kernel_btf.BtfError as excp:
                vollog.debug("%s: %s", vendor, excp)
        else:
            raise kernel_btf.BtfError(
                "No KVM module BTF in this image (KVM not loaded, or no CONFIG_DEBUG_INFO_BTF_MODULES)"
            )

    def type_name(self, name: str) -> str:
        """The full name of a struct, from the KVM module's table or else the kernel's (a vmlinux type)."""
        return kernel_btf.KernelBtf.type_name(
            self.context, self.kernel_name, self.table, name
        )

    def object(self, type_name: str, offset: int) -> interfaces.objects.ObjectInterface:
        """A KVM structure at a kernel address."""
        return self.context.object(
            self.type_name(type_name), layer_name=self.kernel.layer_name, offset=offset
        )

    @functools.cached_property
    def enumerators(self) -> Dict[str, int]:
        """Every enum constant of the KVM module's BTF, such as VCPU_REGS_RIP, with its value."""
        return kernel_btf.KernelBtf.enumerators(self.context, self.table)

    def list_vms(self) -> Iterator[int]:
        """The `struct kvm` addresses on kvm.ko's `vm_list` (`kvm.vm_list` in include/linux/kvm_host.h)."""
        head = kernel_btf.KernelBtf.module_symbol(
            self.context, self.kernel_name, "kvm", "vm_list"
        )
        if head is None:
            vollog.warning("kvm.ko has no vm_list symbol")
            return
        vm_list = self.kernel.object("list_head", offset=head, absolute=True)
        for vm in vm_list.to_list(self.type_name("kvm"), "vm_list"):
            yield self.layer.canonicalize(vm.vol.offset)

    def fd_vms(
        self, tasks: List[interfaces.objects.ObjectInterface]
    ) -> Dict[int, List[interfaces.objects.ObjectInterface]]:
        """`struct kvm` address -> tasks holding a `kvm-vm` file for it (`file->private_data`, virt/kvm/kvm_main.c)."""
        found: Dict[int, List[interfaces.objects.ObjectInterface]] = {}
        for task in tasks:
            for name, filp in qemu.VMs.kvm_files(
                self.context, self.kernel.symbol_table_name, task
            ):
                if name == "kvm-vm":
                    found.setdefault(
                        self.layer.canonicalize(int(filp.private_data)), []
                    ).append(task)
        return found


class _Table:
    """What the KVM plugins share, not a plugin itself: one table with the rows of each VM by column name."""

    # `kernel_btf` needs `max_symbols` from this framework version. Each plugin that inherits this has its own
    # `_version`.
    _required_framework_version = (2, 24, 0)
    COLUMNS: List[Tuple[str, type]] = []

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel", architectures=["Intel64"]
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.VersionRequirement(
                name="linuxutils", component=linux.LinuxUtilities, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="qemu", component=qemu.VMs, version=(1, 5, 0)
            ),
            requirements.VersionRequirement(
                name="qemu_common", component=qemu_common.QemuCommon, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="kernel_btf", component=kernel_btf.KernelBtf, version=(1, 4, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Only VMs of these PIDs",
                optional=True,
            ),
        ]

    @classmethod
    def find_vms(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        pids: Optional[List[int]] = None,
    ) -> List[Vm]:
        """Every VM seen through `vm_list` or through a process's kvm-vm file.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the host kernel module
            pids: Only VMs whose owner has one of these process IDs (all if None or empty)

        Returns:
            One `Vm` per `struct kvm`, with its owner task and the views it was seen in. Empty, with an error
            logged, if the image has no KVM module BTF
        """
        try:
            host = Host(context, kernel_module_name)
        except kernel_btf.BtfError as excp:
            vollog.error(str(excp))
            return []
        tasks = [
            t for t in pslist.PsList.list_tasks(context, kernel_module_name) if t.mm
        ]
        by_mm = {host.layer.canonicalize(int(t.mm)): t for t in tasks}
        in_list, by_fd = set(host.list_vms()), host.fd_vms(tasks)
        vms = []
        for addr in sorted(in_list | set(by_fd)):
            try:
                vm = Vm(host, addr, addr in in_list, by_fd.get(addr, []), by_mm)
            except exceptions.InvalidAddressException:
                vollog.debug(f"{addr:#x}: not a readable struct kvm")
                continue
            if not pids or vm.pid in pids or vm.userspace_pid in pids:
                vms.append(vm)
        return vms

    def rows(self, vm: Vm) -> Iterator[Dict[str, object]]:
        """The values of the rows of one VM, by column name."""
        raise NotImplementedError

    def _generator(self):
        for vm in self.find_vms(
            self.context, self.config["kernel"], self.config.get("pid")
        ):
            try:
                for values in self.rows(vm):
                    yield 0, qemu_common.QemuCommon.row(self.COLUMNS, values)
            except exceptions.InvalidAddressException as excp:
                vollog.warning(
                    f"KVM {vm.addr:#x} (PID {vm.pid}): rows left out, its memory is unreadable: {excp}"
                )

    def run(self):
        return renderers.TreeGrid(self.COLUMNS, self._generator())


class VMs(_Table, interfaces.plugins.PluginInterface):
    """Lists KVM virtual machines found through the host kernel's KVM structures and dumps their guest memory."""

    _version = (1, 2, 1)
    COLUMNS = [
        ("KVM", format_hints.Hex),
        ("PID", int),
        ("COMM", str),
        ("PPID", int),
        ("UID", int),
        ("Started", datetime.datetime),
        ("Executable", str),
        # The two views of the VM, and whether its owner is in the task list (False: hidden).
        ("On vm_list", bool),
        ("kvm-vm file", bool),
        ("Owner listed", bool),
        ("vCPUs", int),
        ("Slots", int),
        ("RAM MiB", int),
        ("SMRAM KiB", int),
        ("Resident %", float),
        ("Encrypted", str),
        ("Guest banner", str),
        ("File output", str),
        ("SMM file output", str),
    ]

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return super().get_requirements() + [
            requirements.BooleanRequirement(
                name="dump",
                description="Write each guest's memory as an ELF core (kvm.<pid>.<kvm address>.elf)",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="smm",
                description="With --dump: also write the SMM address space (kvm.<pid>.<kvm address>.smm.elf)",
                default=False,
                optional=True,
            ),
        ]

    def _dump(self, vm: Vm, as_id: int) -> object:
        """Writes one address space of the VM as an ELF core and returns the File output value."""
        guest = vm.guest(as_id)
        if guest is None:
            vollog.warning(
                f"KVM {vm.addr:#x}: address space {as_id} not written (no memslots, or the owner's memory is unreadable)"
            )
            return renderers.NotAvailableValue()
        return qemu_common.QemuCommon.dump_elf(
            self.open,
            f"kvm.{vm.pid}.{vm.addr:#x}" + (".smm.elf" if as_id else ".elf"),
            guest,
        )

    def rows(self, vm: Vm) -> Iterator[Dict[str, object]]:
        """One row per struct kvm, with owner, slots, vCPUs and the optional ELF dumps."""
        user_slots = [s for s in vm.slots if not s.internal]
        guest = vm.guest()
        values = {
            "KVM": format_hints.Hex(vm.addr),
            "PID": vm.pid,
            "On vm_list": vm.in_list,
            "kvm-vm file": bool(vm.fd_holders),
            "Owner listed": vm.task is not None,
            "vCPUs": vm.online_vcpus,
            "Slots": len(user_slots),
            "RAM MiB": sum(
                s.size for s in user_slots if s.as_id == 0 and not s.readonly
            )
            >> 20,
            "SMRAM KiB": (vm.smram_pages() * qemu_common.PAGE) >> 10,
            "File output": "Disabled",
            "SMM file output": "Disabled",
        }
        if vm.task:
            values["COMM"] = utility.array_to_string(vm.task.comm)
            values.update(qemu.VMs.owner_values(self.context, vm.task))
        label = vm.confidential()
        if guest:
            values["Resident %"] = guest.ram.resident_percent
            qemu_common.QemuCommon.log_residency(
                f"KVM {vm.addr:#x} (PID {vm.pid})", guest.ram
            )
            # A confidential guest's RAM is ciphertext, so there is no banner to find.
            if not label:
                values["Guest banner"] = qemu_common.QemuCommon.guest_banner(guest.ram)
        if label:
            values["Encrypted"] = label
        if self.config.get("dump"):
            if label:
                values["File output"] = renderers.NotAvailableValue()
            else:
                values["File output"] = self._dump(vm, 0)
                if self.config.get("smm"):
                    values["SMM file output"] = self._dump(vm, 1)
        yield values


class Slots(_Table, interfaces.plugins.PluginInterface):
    """Lists the memory slots (guest-physical range -> address in the VMM process) of every KVM VM."""

    _version = (1, 2, 1)
    COLUMNS = [
        ("PID", int),
        ("Space", int),
        ("Slot", int),
        ("GPA", format_hints.Hex),
        ("Size", format_hints.Hex),
        ("Host VA", format_hints.Hex),
        ("Read-only", bool),
        ("Dirty log", bool),
        ("KVM internal", bool),
        ("Backing", str),
        ("Pages", int),
        ("Resident pages", int),
    ]

    def rows(self, vm: Vm) -> Iterator[Dict[str, object]]:
        """One row per memslot, both address spaces, KVM's own slots included."""
        for s in vm.slots:
            block = vm.blocks.get(s)
            values = {
                "PID": vm.pid,
                "Space": s.as_id,
                "Slot": s.id,
                "GPA": format_hints.Hex(s.gpa),
                "Size": format_hints.Hex(s.size),
                "Host VA": format_hints.Hex(s.hva),
                "Read-only": s.readonly,
                "Dirty log": bool(s.flags & KVM_MEM_LOG_DIRTY_PAGES),
                "KVM internal": s.internal,
                "Pages": s.npages,
            }
            if block:
                values["Backing"] = block.backing
                values["Resident pages"] = block.resident_pages()
            yield values


class VCPUs(_Table, interfaces.plugins.PluginInterface):
    """Lists the virtual CPUs of every KVM VM with the guest registers KVM holds for them."""

    _version = (1, 3, 0)
    COLUMNS = [
        ("PID", int),
        ("vCPU", int),
        ("TID", int),
        ("Mode", str),
        ("RIP", format_hints.Hex),
        ("RSP", format_hints.Hex),
        ("CR3", format_hints.Hex),
        ("CR0", format_hints.Hex),
        ("CR4", format_hints.Hex),
        ("EFER", format_hints.Hex),
        ("CPL", int),
        ("CS", format_hints.Hex),
        # The last VM exit: SVM exit code (AMD) or VMX basic exit reason (Intel), and its name.
        ("Exit code", format_hints.Hex),
        ("Exit reason", str),
        # VMCB (AMD), cached (Intel: `kvm_vcpu.arch`) or encrypted. "Not current" lists the cached registers that may be old.
        ("Source", str),
        ("Not current", str),
    ]

    def rows(self, vm: Vm) -> Iterator[Dict[str, object]]:
        """One row per vCPU, with the registers KVM holds and where each value came from.

        Of a VM with encrypted vCPU state (SEV-ES, SEV-SNP, TDX) the registers and the exit are N/A.
        """
        for cpu in vm.vcpus(vm.confidential() in ENCRYPTED_VCPU_STATE):
            values = {
                "PID": vm.pid,
                "vCPU": cpu.id,
                "Mode": cpu.mode,
                "Source": cpu.source,
                "Not current": ",".join(cpu.stale),
            }
            if cpu.exit_code is not None:
                names = SVM_EXITS if vm.host.vendor == "kvm_amd" else VMX_EXITS
                values["Exit code"] = format_hints.Hex(cpu.exit_code)
                if cpu.exit_code in names:
                    values["Exit reason"] = names[cpu.exit_code]
            if cpu.tid:
                values["TID"] = cpu.tid
            for column in ("RIP", "RSP", "CR3", "CR0", "CR4", "EFER", "CS"):
                if cpu.regs.get(column.lower()) is not None:
                    values[column] = format_hints.Hex(cpu.regs[column.lower()])
            if cpu.regs.get("cpl") is not None:
                values["CPL"] = cpu.regs["cpl"]
            yield values
