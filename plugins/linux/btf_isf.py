# This file is Copyright 2026 Michael Külper and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
#
"""Builds the symbol table (ISF) of a Linux kernel from the kernel's own memory, with no debug package.

The kernel keeps its types in BTF (CONFIG_DEBUG_INFO_BTF) and the addresses of its symbols in kallsyms
(CONFIG_KALLSYMS_ALL). The plugin finds both in a physical memory image of an x86-64 kernel and writes the ISF. It
needs no `-s`, because it runs before any kernel is stacked:

    vol -o out -f image.raw linux.btf_isf.Build
    vol -s out -f image.raw linux.pslist.PsList

If the image holds several kernels (a host with guests on huge pages), the one with the largest BTF is used;
`--release 6.1.0-54-cloud-amd64` picks another.
"""

import logging
import time
from typing import List

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import intel
from volatility3.framework.renderers import format_hints
from volatility3.plugins import kallsyms_scan, kernel_btf

vollog = logging.getLogger(__name__)


class Build(interfaces.plugins.PluginInterface):
    """Builds a symbol table (ISF) of the kernel in a Linux x86-64 image from its in-memory BTF and kallsyms."""

    # `kernel_btf.KernelBtf` declares 2.24.0 for its module functions. Reading VMCOREINFO, the one other framework
    # call needed, requires 2.11.0.
    _required_framework_version = (2, 24, 0)
    _version = (1, 1, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary", description="Memory layer of the Linux image"
            ),
            requirements.VersionRequirement(
                name="kernel_btf", component=kernel_btf.KernelBtf, version=(1, 5, 0)
            ),
            requirements.VersionRequirement(
                name="kallsyms_scan",
                component=kallsyms_scan.KallsymsScan,
                version=(2, 0, 0),
            ),
            requirements.StringRequirement(
                name="release",
                description="Kernel release to build for (e.g. 6.1.0-54-cloud-amd64), if the image holds several kernels",
                optional=True,
            ),
        ]

    def _physical_layer(self) -> str:
        """The layer to scan: the one below the page tables if a kernel was already stacked on it.

        `memory_layer` is the framework's own name for an Intel layer's lower layer, as used in `banners.Banners`.
        """
        layer = self.context.layers[self.config["primary"]]
        while isinstance(layer, intel.Intel):
            layer = self.context.layers[layer.config["memory_layer"]]
        return layer.name

    def _generator(self):
        # `BtfError`, like every error of the build, propagates: Volatility shows it as the plugin's error.
        image = kernel_btf.KernelBtf.kernel_image(
            self.context,
            self._physical_layer(),
            self._progress_callback,
            self.config.get("release"),
        )
        isf = kernel_btf.KernelBtf.isf_from_image(image)
        banner = image.banner_text
        started = time.perf_counter()
        name = kernel_btf.KernelBtf.isf_file_name(banner)
        with self.open(name) as handle:
            size = kernel_btf.KernelBtf.write_isf(isf, handle)
        vollog.info(
            "btf_isf: %s written, %.1f MiB, compressed in %.2f s",
            name,
            size / (1 << 20),
            time.perf_counter() - started,
        )
        yield (
            0,
            (
                name,
                banner,
                len(isf["user_types"]),
                len(isf["symbols"]),
                format_hints.Hex(image.btf_address),
                image.kallsyms.layout["num_syms_value"],
                format_hints.Hex(image.shift),
            ),
        )

    def run(self):
        return renderers.TreeGrid(
            [
                ("File", str),
                ("Banner", str),
                ("Types", int),
                ("Symbols", int),
                ("BTF at", format_hints.Hex),
                ("kallsyms symbols", int),
                ("KASLR shift", format_hints.Hex),
            ],
            self._generator(),
        )
