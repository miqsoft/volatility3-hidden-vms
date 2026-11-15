# This file is Copyright 2026 Michael Külper and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
#
"""Run any Volatility plugin on a QEMU guest found in a Windows host memory image, in place.

The Windows counterpart of linux.qemu_guest.Run: windows.qemu.VMs finds the guest's RAM in the QEMU process
(VirtualAlloc) and the guest's kernel is built on a layer over it (`QemuGuestLayer`). Everything after finding the
guest is qemu_guest_run's, shared with linux.qemu_guest.Run, including the symbol table that is built from the BTF and
kallsyms of a Linux guest, which makes `--guest-symbol-dirs` optional for it.

    vol -p plugins -f host.raw windows.qemu_guest.Run --pid 4000 --guest-plugin linux.pslist.PsList
"""

import logging
from typing import List

from volatility3.framework import interfaces
from volatility3.framework.configuration import requirements
from volatility3.plugins import kernel_btf, qemu_common, qemu_guest_run
from volatility3.plugins.windows import qemu

vollog = logging.getLogger(__name__)


class Run(interfaces.plugins.PluginInterface):
    """Runs a plugin on a QEMU guest inside a Windows image, without dumping the guest's memory first."""

    # what `QemuGuestRun` requires of the framework
    _required_framework_version = (2, 24, 0)
    _version = (2, 1, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel of the host",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="qemu", component=qemu.VMs, version=(1, 3, 0)
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
                description="Guest RAM address in the QEMU process ('RAM at' of windows.qemu.VMs), if a "
                "process holds several guests",
                optional=True,
            ),
        ] + qemu_guest_run.QemuGuestRun.guest_requirements()

    def _guest(
        self, context: interfaces.context.ContextInterface
    ) -> qemu_common.GuestVM:
        """The one guest selected by --pid / --ram-at, found in `context`, which is the copy that the guest runs in."""
        ram_at = self.config.get("ram_at")
        vms = [
            vm
            for _proc, vm, _info in qemu.VMs.find_vms(
                context, self.config["kernel"], self.config.get("pid")
            )
            if vm and ram_at in (None, vm.ram.start)
        ]
        return qemu_guest_run.QemuGuestRun.only_guest(vms, "--pid / --ram-at")

    def run(self):
        """Build the guest layer and symbols in a copy of the context, then run the chosen plugin on the guest; the
        result is the guest plugin's own table."""
        return qemu_guest_run.QemuGuestRun.run(self, "windows", self._guest)
