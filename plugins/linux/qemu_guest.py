# This file is Copyright 2026 Michael Külper and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
#
"""Run any Volatility plugin on a QEMU guest found in a Linux host memory image, in place.

linux.qemu.VMs finds the guest's RAM blocks in the QEMU process and the guest-physical memory map. This plugin lays a
layer over them (`QemuGuestLayer`), builds the guest's kernel on it and runs the requested plugin there, in a copy of
the context (see qemu_guest_run) so that the image's own context is left as it is. The guest plugin's rows are
produced as they are rendered.

    vol -s symbols-host -p plugins -f host.raw linux.qemu_guest.Run --pid 1306 \\
        --guest-plugin linux.pslist.PsList

A Linux guest needs no symbol table of its own if its kernel was built with CONFIG_DEBUG_INFO_BTF and
CONFIG_KALLSYMS_ALL (x86-64, the default of most distributions): unless Volatility knows a table that matches the
guest's banner, one is built from the BTF and kallsyms in the guest's memory (see linux.btf_isf.Build), which takes a
few seconds. `--save-guest-symbols` writes it to the output directory (`-o DIR`) as `<release>.json.xz`, to be used
again with `--guest-symbol-dirs DIR` or `-s DIR`. For any other guest, or a kernel without BTF or kallsyms, give the
guest's table with `--guest-symbol-dirs symbols-guest`.

Keep the guest's symbol table out of `-s`: a VM host image holds the guests' kernels too, and with their tables in the
symbol path the automagic may pick a guest kernel for the host. `--guest-symbol-dirs` takes one or more directories
(separated by spaces) and uses them for the guest only. Options of the guest plugin are set with
`-e plugins.Run.<PluginClass>.<option>=<JSON value>`, e.g. `-e 'plugins.Run.PsList.pid=[1]'`.
"""

import logging
from typing import List

from volatility3.framework import interfaces
from volatility3.framework.configuration import requirements
from volatility3.plugins import kernel_btf, qemu_common, qemu_guest_run
from volatility3.plugins.linux import kvm, qemu

vollog = logging.getLogger(__name__)


class Run(interfaces.plugins.PluginInterface):
    """Runs a plugin on a QEMU guest inside the image, without dumping the guest's memory first."""

    # what `QemuGuestRun` requires of the framework
    _required_framework_version = (2, 24, 0)
    _version = (2, 1, 1)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel of the host",
                architectures=["Intel64"],
            ),
            requirements.VersionRequirement(
                name="qemu", component=qemu.VMs, version=(1, 4, 0)
            ),
            requirements.VersionRequirement(
                name="kvm_vms", component=kvm.VMs, version=(1, 1, 0)
            ),
            requirements.VersionRequirement(
                name="qemu_common", component=qemu_common.QemuCommon, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="kernel_btf", component=kernel_btf.KernelBtf, version=(1, 4, 0)
            ),
            requirements.VersionRequirement(
                name="qemu_guest_run",
                component=qemu_guest_run.QemuGuestRun,
                version=(1, 0, 0),
            ),
            requirements.IntRequirement(
                name="ram_at",
                description="Guest RAM address in the QEMU process ('RAM at' of linux.qemu.VMs), if a process "
                "holds several guests",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="kvm",
                description="Find the guest through the kernel's KVM memslots (linux.kvm) instead of the QEMU "
                "process: any VMM, exact memory map",
                default=False,
                optional=True,
            ),
        ] + qemu_guest_run.QemuGuestRun.guest_requirements()

    def _guest(
        self, context: interfaces.context.ContextInterface
    ) -> qemu_common.GuestVM:
        """The one guest selected by --pid / --ram-at (or, with --kvm, found through KVM's memslots), found in
        `context`, which is the copy that the guest runs in."""
        ram_at = self.config.get("ram_at")
        # guests whose RAM is encrypted cannot be read: they are left out, and named if no single guest remains
        vms, encrypted = [], []
        if self.config.get("kvm"):
            if ram_at is not None:
                vollog.warning(
                    "--ram-at is ignored with --kvm: the guest is selected by --pid only"
                )
            for kvm_vm in kvm.VMs.find_vms(
                context, self.config["kernel"], self.config.get("pid")
            ):
                label = kvm_vm.confidential()
                if label:
                    encrypted.append(f"PID {kvm_vm.pid}: encrypted ({label})")
                    continue
                guest = kvm_vm.guest()
                if guest:
                    vms.append(guest)
        else:
            for task, vm, info in qemu.VMs.find_vms(
                context, self.config["kernel"], self.config.get("pid")
            ):
                if info.encrypted:
                    encrypted.append(f"PID {task.pid}: encrypted ({info.encrypted})")
                # `--ram-at` tells a process's guests apart
                elif vm and ram_at in (None, vm.ram.start):
                    vms.append(vm)
        return qemu_guest_run.QemuGuestRun.only_guest(
            vms,
            "--pid" if self.config.get("kvm") else "--pid / --ram-at",
            encrypted,
        )

    def run(self):
        """Build the guest layer and symbols in a copy of the context, then run the chosen plugin on the guest; the
        result is the guest plugin's own table."""
        return qemu_guest_run.QemuGuestRun.run(self, "linux", self._guest)
