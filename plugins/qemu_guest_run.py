# This file is Copyright 2026 Michael Külper and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
#
"""What linux.qemu_guest.Run and windows.qemu_guest.Run share: the guest-physical layer of a QEMU guest and the
steps that run a Volatility plugin on it.

`QemuGuestLayer` maps guest-physical addresses onto the QEMU process's layer. `QemuGuestRun.run` builds the guest's
layer and kernel on a copy of the plugin's context (`context.clone()`), constructs the guest plugin there and returns
its table. The host plugin's context is never changed: no layer, module, symbol table or configuration key is added or
removed, `volatility3.symbols.__path__` stays as it is and the identifier cache is not written.

A Linux guest's kernel is built here, not found by the stackers: its symbol table comes from `--guest-symbol-dirs`,
from a table that Volatility knows for one of the guest's banners, or from the BTF and kallsyms in the guest's memory
(`KernelBtf.isf_from_memory`). The Intel layer is made as `LinuxIntelStacker` makes it, and the guest plugin's `kernel`
requirement is preset, so that the automagics find nothing left to do. A Windows guest's kernel is found by the
stackers and the PDB automagic, on the copy.
"""

import bisect
import codecs
import collections
import difflib
import functools
import json
import logging
import os
import pathlib
import tempfile
import time
import weakref
from typing import (
    Callable,
    Dict,
    Iterator,
    List,
    NamedTuple,
    Optional,
    OrderedDict,
    Tuple,
    Type,
)

from volatility3 import framework
from volatility3.framework import (
    automagic,
    constants,
    exceptions,
    interfaces,
    plugins,
    renderers,
)
from volatility3.framework.automagic import linux as linux_automagic
from volatility3.framework.automagic import pdbscan, stacker, symbol_cache
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import intel, resources, segmented
from volatility3.framework.symbols import intermed, linux
from volatility3.plugins import kernel_btf, qemu_common
from volatility3.plugins.linux import qemu
from volatility3.plugins.windows import qemu as windows_qemu

vollog = logging.getLogger(__name__)

PAGE = qemu_common.PAGE
# Reasons (`RamBlock._classify`) of a page that the host never backed, which is then the guest's page of zeros since an
# anonymous page exists only once it is written. Any other reason (swapped out, migration or marker entry, prototype or
# transition PTE, a frame that the image lacks) means the guest page existed and is lost.
ZERO_REASONS = frozenset({"never present", "demand-zero"})
# page-cache pages kept between a validity check and the read that follows it
CACHED_PAGES = 4096
# reads up to this length are cached: a plugin reads the same small structures again and again
SMALL_READ = PAGE
# how many of them each layer keeps
SMALL_CACHE = 4096


class GuestSelectionError(exceptions.VolatilityException):
    """The options name no plugin to run or no (or no single) guest to run it on; `QemuGuestRun.run` logs it and
    returns an empty table, as plugins do for input that selects nothing."""


class GuestSymbolsError(exceptions.SymbolSpaceError):
    """The guest exists but its plugin cannot run for want of a symbol table.

    A `SymbolSpaceError`, because `vol` prints the message of that and of no plain `VolatilityException`."""


# the kinds of `_Run`
MAPPED, ZERO, CACHE = "mapped", "zero", "cache"


class _Run(NamedTuple):
    """One run of guest-physical addresses with the same fate."""

    gpa: int
    size: int
    address: int  # in the process layer
    kind: str  # MAPPED: the process page tables translate it; ZERO: never backed; CACHE: in the file's page cache
    mapped: int = 0  # for MAPPED: the place in the layer below the process layer
    mapped_size: int = 0
    mapped_layer: str = ""


class _HostInode:
    """The inode behind a RAM file, walking its page cache through the host's kernel module by name.

    `inode.get_pages` looks the kernel up as the module named "kernel" (volatility3 issue #2084, fix proposed in
    volatility3 PR #2085), which in the context of a guest is the guest's."""

    def __init__(self, inode, context, module_name: str):
        self._inode, self._context, self._module = inode, context, module_name

    def __getattr__(self, name: str):
        return getattr(self._inode, name)

    def get_pages(self):
        """The cached pages of the inode: `inode.get_pages` with the module named explicitly."""
        inode = self._inode
        if not inode.i_size:
            return
        mapping = inode.i_mapping
        if not (mapping and mapping.is_readable() and mapping.nrpages > 0):
            return
        yield from linux.PageCache(
            context=self._context,
            kernel_module_name=self._module,
            page_cache=mapping.dereference(),
        ).get_cached_pages()


class _HostFile:
    """A `file` of the host whose inode is a `_HostInode`."""

    def __init__(self, file, context, module_name: str):
        self._file, self._context, self._module = file, context, module_name

    def get_inode(self):
        """The file's inode, wrapped."""
        inode = self._file.get_inode()
        return _HostInode(inode, self._context, self._module) if inode else None


class _HostVma:
    """A `vm_area_struct` of the host whose file leads to a `_HostInode`."""

    def __init__(self, vma, context, module_name: str):
        self._vma, self._context, self._module = vma, context, module_name

    def __getattr__(self, name: str):
        return getattr(self._vma, name)

    @property
    def vm_file(self):
        """The mapped file, wrapped; None for an anonymous mapping."""
        file = self._vma.vm_file
        return _HostFile(file, self._context, self._module) if file else file


class _PageCache:
    """The page cache of the files that back a guest's RAM (memfd, hugetlbfs): which guest pages it holds and what
    they hold.

    The index of the host's `struct page`s is built on first use, for each file-backed mapping of the QEMU process."""

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        module_name: str,
        vmas: List[Tuple[int, int, int]],
        known: Optional[Dict[int, qemu.LinuxRamBlock]] = None,
    ):
        """`vmas` are (start, size, address of the `vm_area_struct`) of the file-backed mappings of the process;
        `known` has the blocks that exist already, by that address, so that their index is not made again."""
        self._context, self._layer, self._module = context, layer_name, module_name
        self._vmas = sorted(vmas)
        self._starts = [start for start, _size, _address in self._vmas]
        self._known = known or {}
        self._blocks: Dict[int, Optional[qemu.LinuxRamBlock]] = {}
        self._content: OrderedDict[int, Optional[bytes]] = collections.OrderedDict()

    def overlaps(self, start: int, end: int) -> bool:
        """Whether a file-backed mapping covers part of the process addresses [start, end)."""
        # either the last mapping that starts at or before `start` reaches into the range, or the next one starts in it
        index = bisect.bisect_right(self._starts, start) - 1
        if index >= 0 and start < self._vmas[index][0] + self._vmas[index][1]:
            return True
        return index + 1 < len(self._vmas) and self._vmas[index + 1][0] < end

    def _block(self, address: int) -> Optional[qemu.LinuxRamBlock]:
        """The block of the mapping that holds a process address, made on first use; None if there is none."""
        index = bisect.bisect_right(self._starts, address) - 1
        if index < 0 or address >= self._vmas[index][0] + self._vmas[index][1]:
            return None
        if index not in self._blocks:
            self._blocks[index] = self._make_block(self._vmas[index])
        return self._blocks[index]

    def uncached_reason(self, address: int) -> Optional[str]:
        """Why a page at a process address that the page cache lacks may exist elsewhere; None if the file's page there
        was never written (zeros) or the address is in no file mapping. See `LinuxRamBlock.uncached_reason`."""
        block = self._block(address)
        if block is None:
            return qemu.NOT_CACHED if self.overlaps(address, address + PAGE) else None
        return block.uncached_reason

    def _make_block(
        self, vma_entry: Tuple[int, int, int]
    ) -> Optional[qemu.LinuxRamBlock]:
        """The host's `LinuxRamBlock` for a mapping, made again from the host's kernel memory."""
        _start, _size, address = vma_entry
        if address in self._known:
            return self._known[address]
        try:
            module = self._context.modules[self._module]
            vma = module.object("vm_area_struct", offset=address, absolute=True)
            return qemu.LinuxRamBlock(
                self._context,
                self._layer,
                _HostVma(vma, self._context, self._module),
                "page cache",
            )
        except (exceptions.VolatilityException, KeyError) as excp:
            vollog.debug(f"No page cache for the mapping at {address:#x}: {excp}")
            return None

    def content(self, address: int) -> Optional[bytes]:
        """The data of the page-cache page that backs the page at a process address, None if there is none or its data
        is not in the image."""
        if address in self._content:
            self._content.move_to_end(address)
            return self._content[address]
        block = self._block(address)
        data = None
        if block is not None:
            try:
                page = block.cached_page(address - block.start)
                data = page.get_content() if page is not None else None
            except exceptions.InvalidAddressException as excp:
                vollog.debug(f"Page cache page at {address:#x} unreadable: {excp}")
        # None is kept too: asking again for a page that the cache lacks would walk the cache again
        self._content[address] = data
        if len(self._content) > CACHED_PAGES:
            self._content.popitem(last=False)
        return data


class _HostPages(qemu_common.RamBlock):
    """Explains the pages of the QEMU process that its page tables do not translate, with the host's PTE formats.

    The process's whole address space is one `RamBlock` that has nothing to read, only to classify."""

    def __init__(
        self,
        layer: interfaces.layers.DataLayerInterface,
        reason: Callable[[int, int], Optional[str]],
    ):
        super().__init__(layer, 0, 1 << 64, "host")
        self._host_reason = reason

    def _reason(self, entry: int, bits: int) -> str:
        # the host's own formats first; the generic ones cover what they do not name
        return self._host_reason(entry, bits) or super()._reason(entry, bits)

    def classify(self, address: int) -> Tuple[str, int]:
        """(reason, end of the run of pages that the same entry explains) for the page at a process address.

        That is `RamBlock._classify`, which has no public name; `log_residency` and the residency column use it too."""
        return self._classify(address)


class QemuGuestLayer(segmented.SegmentedLayer):
    """Guest-physical memory of a QEMU guest, read from the QEMU process that holds the guest's RAM.

    `segments` maps guest-physical ranges onto the process layer (`base_layer`) as flat (guest-physical address,
    process address, length) triples; addresses outside them (MMIO, the VGA window) are invalid, as in an ELF core of
    the guest. A page inside a segment is one of four kinds:

    * the process page tables translate it: its data is read from below the process layer;
    * they do not, and the page's entry is empty (never touched, or demand-zero on Windows): the guest's page of
      zeros, which the host never had to back. In a file mapping that holds only if the file cannot hold the page
      elsewhere: a hugetlbfs file, or a tmpfs or memfd file with nothing swapped out, never has it. A page of a file
      that may have swapped pages or lives on disk is lost, like the next kind;
    * they do not, and the page is in the page cache of the file that backs the RAM (memfd, hugetlbfs): its data is
      read from there, as in the ELF dump;
    * otherwise the host swapped it out, migrated it, or has its frame outside the image, or the file that backs it may
      have it in swap or on disk: the page is lost, so reading it raises `InvalidAddressException` (a read with
      `pad=True` gives zeros, as in any layer).

    `mapping`, `is_valid`, `read` and the scans all see the same pages. The configuration (`host_module`, `host_os`,
    `page_cache`) describes the page cache, so that the layer can be rebuilt from it alone.
    """

    _version = (2, 1, 0)

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        name: str,
        metadata: Optional[Dict[str, object]] = None,
    ) -> None:
        super().__init__(context, config_path, name, metadata)
        self._host_pages: Optional[_HostPages] = None
        self._page_cache: Optional[_PageCache] = None
        self._page_cache_made = False
        self._adopted: Dict[int, qemu.LinuxRamBlock] = {}
        # the cache of short reads, made on first use (see `_small_reader`)
        self._small_cache: Optional[Callable[[int, int, bool], bytes]] = None

    def _small_reader(self) -> Callable[[int, int, bool], bytes]:
        """The cache of short reads of this layer.

        It holds the layer only weakly, so that dropping the layer frees it (a `lru_cache` on the method would share
        one cache between all layers and keep every one alive).
        """
        if self._small_cache is None:
            layer = weakref.ref(self)

            def read_small(offset: int, length: int, pad: bool) -> bytes:
                return layer()._read(offset, length, pad)  # type: ignore[union-attr]

            self._small_cache = functools.lru_cache(maxsize=SMALL_CACHE)(read_small)
        return self._small_cache

    def __getstate__(self) -> Dict[str, object]:
        """The state of a copy (`copy.deepcopy`, as `context.clone()` makes) or pickle, without the cache of short
        reads: it reads through the original layer, and the copy makes its own."""
        state = self.__dict__.copy()
        state["_small_cache"] = None
        return state

    def _load_segments(self) -> None:
        """Reads `segments` from the configuration, so that the layer can be rebuilt from it."""
        # SegmentedLayer segments are (offset, mapped offset, length, mapped length)
        values = self.config["segments"]
        triples = [values[i : i + 3] for i in range(0, len(values), 3)]
        self._segments = sorted((gpa, addr, size, size) for gpa, addr, size in triples)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """The guest memory map, and what is needed to explain and fill the pages that the process lacks."""
        return super().get_requirements() + [
            requirements.ListRequirement(
                name="segments",
                element_type=int,
                description="Flat (guest-physical address, process address, length) triples",
            ),
            requirements.StringRequirement(
                name="host_os",
                description="The host's operating system, 'linux' or 'windows': the page table entry formats of the "
                "QEMU process (a page that is not translated is zeros only if its entry says it was never backed)",
                optional=True,
            ),
            requirements.StringRequirement(
                name="host_module",
                description="Name of the host's kernel module in the context (the host's PTE formats and, for a "
                "Linux host, its page cache are read through it)",
                optional=True,
            ),
            requirements.ListRequirement(
                name="page_cache",
                element_type=int,
                description="Flat (start, size, address of the vm_area_struct) triples of the QEMU process's "
                "mappings of the file that backs the RAM, whose page cache may hold pages that the process page "
                "tables lack",
                optional=True,
            ),
        ]

    @property
    def dependencies(self) -> List[str]:
        """The process layer and, with a page cache to read, the host's kernel layer that it is walked in."""
        found = [self._base_layer]
        if self.config.get("page_cache"):
            module = self._host_module()
            if module is not None and module.layer_name not in found:
                found.append(module.layer_name)
        return found

    def _host_module(self) -> Optional[interfaces.context.ModuleInterface]:
        """The host's kernel module, None if the configuration names none or it is not in the context."""
        name = self.config.get("host_module")
        if name and name in self._context.modules:
            return self._context.modules[name]
        return None

    def _classifier(self) -> _HostPages:
        """The classifier of the process's untranslated pages, made on first use."""
        if self._host_pages is None:
            process = self._context.layers[self._base_layer]
            self._host_pages = _HostPages(process, self._pte_reason())
        return self._host_pages

    def _pte_reason(self) -> Callable[[int, int], Optional[str]]:
        """The host's PTE reasons; for a host of unknown kind only the generic ones apply (an empty entry is zeros)."""
        host_os = self.config.get("host_os")
        if host_os == "linux":
            return qemu.linux_pte_reason
        if host_os == "windows":
            pte = None  # made on first use: it reads the host module's symbols

            def reason(entry: int, bits: int) -> Optional[str]:
                nonlocal pte
                if pte is None:
                    pte = windows_qemu.WindowsPte(
                        self._context, self.config["host_module"]
                    )
                return pte.reason(entry, bits)

            return reason
        return lambda entry, bits: None

    def adopt_page_cache(self, blocks: Dict[int, qemu.LinuxRamBlock]) -> None:
        """Takes the page-cache index of blocks that have it already (by the address of their `vm_area_struct`) instead
        of reading the cache again; a layer without them makes its own from the configuration."""
        self._adopted = blocks
        self._page_cache, self._page_cache_made = None, False

    def _cache(self) -> Optional[_PageCache]:
        """The page cache that the configuration describes, made on first use; None if the guest has none."""
        if not self._page_cache_made:
            self._page_cache_made = True
            values = self.config.get("page_cache")
            module = self.config.get("host_module")
            if values and module and self.config.get("host_os") == "linux":
                triples = [tuple(values[i : i + 3]) for i in range(0, len(values), 3)]
                self._page_cache = _PageCache(
                    self._context, self._base_layer, module, triples, self._adopted
                )
        return self._page_cache

    def _holes(
        self, delta: int, start: int, end: int, ignore_errors: bool
    ) -> Iterator[_Run]:
        """The runs of the process addresses [start, end) that the process page tables do not translate: zeros and page
        cache pages, and without `ignore_errors` the first lost page as an `InvalidAddressException`."""
        cache = self._cache()
        classifier = self._classifier()
        position = start
        zero_until = 0  # the pages below it are explained by the entry that the last classification looked at
        while position < end:
            page = position & ~(PAGE - 1)
            stop = min(page + PAGE, end)
            kind = None
            lost = None  # why the page has no data, if it is lost
            # a page in the cache has data whatever its entry says; the entry only explains the pages that are not there
            if (
                cache is not None
                and cache.overlaps(page, page + PAGE)
                and cache.content(page) is not None
            ):
                kind = CACHE
            else:
                if page >= zero_until:
                    lost, covered = classifier.classify(page)
                    if lost in ZERO_REASONS:
                        zero_until = max(covered, page + PAGE)
                if page < zero_until:
                    # an empty entry: the guest's page of zeros, unless a file's page that the cache lacks may exist
                    # elsewhere (swapped out, on disk)
                    in_file = cache is not None and cache.overlaps(page, page + PAGE)
                    lost = cache.uncached_reason(page) if in_file else None
                    if lost is None:
                        kind = ZERO
                        # one entry may explain many pages (a missing page table); a file's page cache could still
                        # hold any of them, so those are looked at one by one
                        if cache is None or not cache.overlaps(page + PAGE, zero_until):
                            stop = min(zero_until, end)
            if kind is None and not ignore_errors:
                raise exceptions.InvalidAddressException(
                    self.name,
                    delta + max(position, page),
                    f"Guest page at {delta + page:#x} is not in the image ({lost})",
                )
            if kind is not None:
                yield _Run(delta + position, stop - position, position, kind)
            position = stop

    def _raw_runs(
        self, offset: int, length: int, ignore_errors: bool
    ) -> Iterator[_Run]:
        process = self._context.layers[self._base_layer]
        # what the process layer leaves out of a segment is a hole: zeros, page cache or lost
        for gpa, size, addr, _size, _layer in super().mapping(
            offset, length, ignore_errors
        ):
            if size <= 0:
                continue
            delta, cursor, end = gpa - addr, addr, addr + size
            for p_addr, p_size, mapped, mapped_size, mapped_layer in process.mapping(
                addr, size, ignore_errors=True
            ):
                if p_addr > cursor:
                    yield from self._holes(delta, cursor, p_addr, ignore_errors)
                yield _Run(
                    delta + p_addr,
                    p_size,
                    p_addr,
                    MAPPED,
                    mapped,
                    mapped_size,
                    mapped_layer,
                )
                cursor = p_addr + p_size
            if cursor < end:
                yield from self._holes(delta, cursor, end, ignore_errors)

    def _runs(self, offset: int, length: int, ignore_errors: bool) -> Iterator[_Run]:
        """The runs of [offset, offset + length), with neighbours of the same kind joined (not MAPPED ones, which each
        have a place in the layer below). Without `ignore_errors` an invalid address raises `InvalidAddressException`
        when the iteration gets there."""
        last: Optional[_Run] = None
        for run in self._raw_runs(offset, length, ignore_errors):
            if (
                last is not None
                and run.kind != MAPPED
                and run.kind == last.kind
                and last.gpa + last.size == run.gpa
            ):
                last = last._replace(size=last.size + run.size)
                continue
            if last is not None:
                yield last
            last = run
        if last is not None:
            yield last

    def mapping(
        self, offset: int, length: int, ignore_errors: bool = False
    ) -> Iterator[Tuple[int, int, int, int, str]]:
        """The runs that `read` returns data for, as (guest address, length, process address, length, process layer).

        A page that is only in the page cache or was never backed has the process address that it would have."""
        if length == 0:
            for run in self._runs(offset, 1, ignore_errors):
                yield run.gpa, 0, run.address, 0, self._base_layer
                return
            return
        for run in self._runs(offset, length, ignore_errors):
            yield run.gpa, run.size, run.address, run.size, self._base_layer

    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Whether `read` returns data (or zeros of a page the host never backed) for every byte of the range."""
        end = offset + max(length, 1)
        covered = offset
        try:
            for run in self._runs(offset, end - offset, False):
                covered = run.gpa + run.size
        except exceptions.InvalidAddressException:
            return False
        return covered >= end

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        # short reads go through a cache, since a plugin reads the same small structures again and again
        if 0 < length <= SMALL_READ:
            return self._small_reader()(offset, length, pad)
        return self._read(offset, length, pad)

    def _read(self, offset: int, length: int, pad: bool) -> bytes:
        """The bytes of the range: zeros where a run is ZERO (or, with `pad`, lost), data otherwise."""
        data = bytearray(length)
        covered = offset
        # with `pad`, lost pages are not runs and stay zeros
        for run in self._runs(offset, length, pad):
            if run.gpa > covered and not pad:
                break
            at = run.gpa - offset
            if run.kind == MAPPED:
                data[at : at + run.size] = self._context.layers.read(
                    run.mapped_layer, run.mapped, run.mapped_size, True
                )
            elif run.kind == CACHE:
                self._fill_from_page_cache(data, offset, run)
            covered = run.gpa + run.size
        if not pad and covered < offset + length:
            raise exceptions.InvalidAddressException(
                self.name, covered, f"No guest RAM at {covered:#x}"
            )
        return bytes(data)

    def _fill_from_page_cache(self, data: bytearray, offset: int, run: _Run) -> None:
        """Copies the page-cache data of a CACHE run into `data`, which starts at `offset`."""
        cache = self._cache()
        position = run.address
        while position < run.address + run.size:
            page = position & ~(PAGE - 1)
            stop = min(page + PAGE, run.address + run.size)
            content = cache.content(page) if cache is not None else None
            if content:
                at = run.gpa + position - run.address - offset
                data[at : at + stop - position] = content[position - page : stop - page]
            position = stop

    def _scan_iterator(
        self,
        scanner: interfaces.layers.ScannerInterface,
        sections: "Iterator[Tuple[int, int]]",
        linear: bool = False,
    ) -> Iterator[interfaces.layers.IteratorValue]:
        """Scans through `read`, as `LinearlyMappedLayer` does not: it scans the layer below, where the pages that only
        the page cache holds have no place."""
        return interfaces.layers.TranslationLayerInterface._scan_iterator(
            self, scanner, sections, False
        )


class QemuGuestRun(interfaces.configuration.VersionableInterface):
    """The functions that linux.qemu_guest.Run and windows.qemu_guest.Run call.

    Its version covers the whole module (`QemuGuestLayer` and the errors too): a plugin that uses any of it declares a
    `VersionRequirement` on this class."""

    _required_framework_version = (2, 24, 0)
    _version = (1, 1, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """The components this one calls."""
        return [
            # `LinuxRamBlock` (with `uncached_reason`) and `linux_pte_reason`
            requirements.VersionRequirement(
                name="qemu", component=qemu.VMs, version=(1, 6, 0)
            ),
            # `WindowsPte`
            requirements.VersionRequirement(
                name="windows_qemu", component=windows_qemu.VMs, version=(1, 3, 0)
            ),
            requirements.VersionRequirement(
                name="qemu_common", component=qemu_common.QemuCommon, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="kernel_btf", component=kernel_btf.KernelBtf, version=(1, 4, 0)
            ),
            requirements.VersionRequirement(
                name="symbol_cache",
                component=symbol_cache.SqliteCache,
                version=(1, 0, 0),
            ),
        ]

    @classmethod
    def guest_requirements(
        cls,
    ) -> List[interfaces.configuration.RequirementInterface]:
        """The options of both plugins that do not depend on the host."""
        return [
            # optional only so that `-h` works: argparse reports a missing required option before it prints the help;
            # `run` logs the error for a missing one
            requirements.StringRequirement(
                name="guest_plugin",
                description="Plugin to run on the guest, e.g. linux.pslist.PsList",
                optional=True,
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="QEMU process ID (needed if the image holds several guests)",
                optional=True,
            ),
            requirements.ListRequirement(
                name="guest_symbol_dirs",
                element_type=str,
                description="Directories with the guest kernel's symbol table (a Linux guest with BTF and kallsyms "
                "needs none), separated by spaces",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="save_guest_symbols",
                description="Write the symbol table to the output directory (-o) as <release>.json.xz if it has to be "
                "built from the guest's memory",
                default=False,
                optional=True,
            ),
        ]

    @classmethod
    def only_guest(
        cls,
        vms: List[qemu_common.GuestVM],
        select: str,
        skipped: Optional[List[str]] = None,
    ) -> qemu_common.GuestVM:
        """The one guest of `vms`.

        Args:
            vms: The guests that match the selection
            select: The options that select a guest, for the message
            skipped: Guests left out (encrypted), for the message

        Raises:
            GuestSelectionError: There is not exactly one guest
        """
        if len(vms) != 1:
            found = (
                ", ".join(f"PID {vm.pid} RAM at {vm.ram.start:#x}" for vm in vms)
                or "none"
            )
            others = f"; skipped {'; '.join(skipped)}" if skipped else ""
            raise GuestSelectionError(
                f"Need exactly one guest, found: {found} (select with {select}){others}"
            )
        return vms[0]

    @staticmethod
    def plugin_os(plugin: type) -> str:
        """The operating system a plugin is for: the package under `volatility3.plugins` that holds its module
        (`linux` for volatility3.plugins.linux.pslist), else the first part of the module name."""
        parts = plugin.__module__.split(".")
        if len(parts) > 3 and parts[:2] == ["volatility3", "plugins"]:
            return parts[2]
        return parts[0]

    @classmethod
    def find_plugin(cls, name: str) -> Type[interfaces.plugins.PluginInterface]:
        """The plugin called `name`: its full name (linux.pslist.PsList), or the file name that the CLI also takes
        (linux.pslist) if only one plugin has it.

        Raises:
            GuestSelectionError: There is not exactly one such plugin; the message lists the candidates
        """
        available = framework.list_plugins()
        if name in available:
            return available[name]
        matches = sorted(n for n in available if n.startswith(f"{name}."))
        if len(matches) == 1:
            return available[matches[0]]
        if matches:
            raise GuestSelectionError(
                f"{name} matches several plugins, use the full name: {', '.join(matches)}"
            )
        close = difflib.get_close_matches(name, list(available), n=3, cutoff=0.8)
        hint = f"; similar: {', '.join(close)}" if close else ""
        raise GuestSelectionError(f"Unknown plugin {name} (see vol --help){hint}")

    @classmethod
    def _file_backed_vmas(
        cls, blocks: List[qemu_common.RamBlock]
    ) -> Dict[Tuple[int, int, int], qemu.LinuxRamBlock]:
        """Every file mapping in the guest's RAM blocks, by (start, size, address of the vm_area_struct).

        A block of linux.qemu is one mapping, one of linux.kvm a memslot with its mappings (`vmas`)."""
        found: Dict[Tuple[int, int, int], qemu.LinuxRamBlock] = {}
        for block in blocks:
            # the blocks of a Windows host have neither `vmas` nor `vma`
            for part in getattr(block, "vmas", None) or [block]:
                vma = getattr(part, "vma", None)
                if vma is not None and getattr(part, "file_backed", False):
                    found[(part.start, part.size, int(vma.vol.offset))] = part
        return found

    @classmethod
    def add_guest_layer(
        cls,
        context: interfaces.context.ContextInterface,
        vm: qemu_common.GuestVM,
        host_os: str,
        host_module: str,
    ) -> str:
        """Adds a `QemuGuestLayer` for the guest on top of the VMM's process layer and returns its name.

        Args:
            context: The context to add the layer to
            vm: The guest
            host_os: 'linux' or 'windows'
            host_module: The host's kernel module in `context`
        """
        join = interfaces.configuration.path_join
        name = context.layers.free_layer_name("QemuGuestLayer")
        path = join("QemuGuest", name)
        context.config[join(path, "base_layer")] = vm.ram.blocks[0].layer.name
        # split at the ends of RAM blocks, whose process addresses need not be contiguous
        context.config[join(path, "segments")] = [
            value
            for gpa, block, offset, length in vm.ram.runs(vm.segments)
            for value in (gpa, block.start + offset, length)
        ]
        # the layer finds the host's PTE formats and page cache again from these
        context.config[join(path, "host_os")] = host_os
        context.config[join(path, "host_module")] = host_module
        vmas = cls._file_backed_vmas(vm.ram.blocks)
        if vmas:
            context.config[join(path, "page_cache")] = [
                value for vma in sorted(vmas) for value in vma
            ]
        layer = QemuGuestLayer(context, path, name)
        # the host's blocks have read the index already (see `run`)
        layer.adopt_page_cache({vma[2]: block for vma, block in vmas.items()})
        context.add_layer(layer)
        return name

    @classmethod
    def release_host_module(
        cls, context: interfaces.context.ContextInterface, name: str
    ) -> str:
        """Renames the host's kernel module in a copy of the context so that the guest's gets the name.

        The framework gives a module the name of its requirement (`kernel`) if it is free, and `inode.get_pages` walks
        a Linux page cache through the module named "kernel" whatever the object's own kernel (volatility3 issue
        #2084, fix proposed in volatility3 PR #2085).

        Args:
            context: The copy of the host's context, never the host's own
            name: The host's kernel module

        Returns:
            The host module's new name, the layer's `host_module`
        """
        modules = context.modules
        host = modules[name]
        del modules[name]
        kept = modules.free_module_name(f"{name}_host")
        modules.add_module(type(host)(context, host.config_path, kept))
        return kept

    @classmethod
    def _stripped(cls, identifiers: Dict[bytes, str]) -> Dict[bytes, str]:
        """Identifier -> location with the trailing newline and NUL stripped, so that it matches a banner as read.

        The ISF's `linux_banner` is stored with them, remote identifiers without."""
        return {i.rstrip(b"\0\n"): location for i, location in identifiers.items() if i}

    @classmethod
    def isf_known(cls, banners: List[str]) -> Optional[Tuple[str, str]]:
        """The ISF that Volatility knows (its identifier cache, local or remote, read only) for the first banner that
        has one.

        A kernel image holds several banners and a table matches only the complete one, which need not be the first.

        Args:
            banners: The guest's Linux banners, the preferred one first

        Returns:
            The ISF's location and the banner it matched, or None
        """
        path = os.path.join(constants.CACHE_PATH, constants.IDENTIFIERS_FILENAME)
        if not os.path.exists(path):
            return None
        cache = symbol_cache.SqliteCache(path)
        known = cls._stripped(cache.get_identifier_dictionary(operating_system="linux"))
        for banner in banners:
            # the identifiers are bytes, the banners text read as latin-1 (any byte maps to a character)
            location = known.get(banner.encode("latin-1"))
            if location:
                return location, banner
        return None

    @classmethod
    def isf_in_dirs(
        cls, dirs: List[str], banners: List[str]
    ) -> Optional[Tuple[str, str]]:
        """The ISF below the directories whose `linux_banner` is the first of the banners that has one.

        Args:
            dirs: The directories to search
            banners: The guest's Linux banners, the preferred one first

        Returns:
            The file's URL and the banner it matched, or None
        """
        wanted = [banner.encode("latin-1") for banner in banners]
        # identifier -> URL of the first ISF that has it
        found: Dict[bytes, str] = {}
        for directory in dirs:
            for extension in constants.ISF_EXTENSIONS:
                for path in sorted(pathlib.Path(directory).rglob("*" + extension)):
                    url = path.resolve().as_uri()
                    try:
                        with resources.ResourceAccessor().open(url) as handle:
                            identifier = symbol_cache.LinuxIdentifier.get_identifier(
                                json.load(codecs.getreader("utf-8")(handle))
                            )
                    except Exception as excp:  # not an ISF, or not a readable one
                        vollog.debug(f"{url} skipped: {excp}")
                        continue
                    if identifier:
                        found.setdefault(identifier.rstrip(b"\0\n"), url)
            # the first directory with a match ends the search; within it the preferred banner wins
            for banner, text in zip(wanted, banners):
                if banner in found:
                    return found[banner], text
        return None

    @classmethod
    def _build_symbols(
        cls,
        host: interfaces.plugins.PluginInterface,
        context: interfaces.context.ContextInterface,
        layer_name: str,
    ) -> Tuple[str, str]:
        """Builds the Linux guest's symbol table from the BTF and kallsyms in its memory, as linux.btf_isf.Build does.

        It goes to a temporary file that the caller removes once the table is loaded, and with `save_guest_symbols`
        also, through the plugin's `open`, to `<release>.json.xz`. Returns the file and the kernel's banner.

        Raises:
            kernel_btf.BtfError: The guest's kernel has no usable BTF and kallsyms
        """
        began = time.perf_counter()
        # the table is loaded from a URL, so it goes through a file, which is removed as soon as it is loaded
        isf, banner = kernel_btf.KernelBtf.isf_from_memory(
            context, layer_name, host._progress_callback
        )
        handle, path = tempfile.mkstemp(prefix="vol3-guest-symbols-", suffix=".json.xz")
        with os.fdopen(handle, "wb") as stream:
            kernel_btf.KernelBtf.write_isf(
                isf, stream, kernel_btf.ISF_XZ_PRESET_TEMPORARY
            )
        vollog.info(
            "guest symbols built from in-memory BTF + kallsyms (%d types, %d symbols, %.1f s)",
            len(isf["user_types"]),
            len(isf["symbols"]),
            time.perf_counter() - began,
        )
        if host.config.get("save_guest_symbols"):
            name = kernel_btf.KernelBtf.isf_file_name(banner)
            with host.open(name) as stream:
                kernel_btf.KernelBtf.write_isf(isf, stream)
            vollog.info("Guest symbols saved: %s (in the output directory)", name)
        return path, banner

    @classmethod
    def _linux_kernel(
        cls,
        host: interfaces.plugins.PluginInterface,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        banners: List[str],
        dirs: List[str],
    ) -> Tuple[List[str], str, bool]:
        """Loads the Linux guest's symbol table and makes its kernel's Intel layer.

        The table comes from `--guest-symbol-dirs`, else from one that Volatility knows for one of the banners, else
        from the guest's memory. Returns the layers that the guest plugin's requirements are fulfilled from (the Intel
        layer, then the guest-physical one), the table's name and whether the table was built from the guest's memory.

        Raises:
            kernel_btf.BtfError: There is no table, and none can be built from the guest's memory
        """
        # the order is what the user controls: their own directories, then what Volatility knows, then the guest itself
        found = cls.isf_in_dirs(dirs, banners) if dirs else None
        if found is None:
            found = cls.isf_known(banners)
            if found is not None:
                vollog.info(
                    "Guest symbols: an ISF for the guest's kernel is known, none built"
                    + (
                        " and nothing saved"
                        if host.config.get("save_guest_symbols")
                        else ""
                    )
                )
        temporary = None
        if found is None:
            # the temporary file is read once, below, and removed in the `finally`
            temporary, banner = cls._build_symbols(host, context, layer_name)
            found = pathlib.Path(temporary).as_uri(), banner
        url, banner = found
        symbol_space = context.symbol_space
        try:
            # as LinuxIntelStacker does: a table of its own finds the layer, and the plugin gets another whose symbol
            # addresses are masked to the layer's address size
            probe_name = symbol_space.free_table_name("QemuGuestProbe")
            probe = cls._load_table(context, probe_name, url, temporary is None, 0)
            symbol_space.append(probe)
            intel_layer = cls._kernel_layer(
                context, probe, probe_name, layer_name, banner, host
            )
            table_name = symbol_space.free_table_name("QemuGuestKernel")
            symbol_space.append(
                cls._load_table(
                    context,
                    table_name,
                    url,
                    temporary is None,
                    intel_layer.address_mask,
                )
            )
        finally:
            if temporary is not None:
                os.unlink(temporary)
        return [intel_layer.name, layer_name], table_name, temporary is not None

    @classmethod
    def _load_table(
        cls,
        context: interfaces.context.ContextInterface,
        name: str,
        url: str,
        validate: bool,
        mask: int,
    ) -> intermed.IntermediateSymbolTable:
        """A Linux symbol table from an ISF; one built here is not validated, as validation records every ISF it
        accepts in the user's cache directory."""
        config_path = "temporary." + name
        # the table reads `symbol_mask` from the configuration when its first symbol is asked for, not from the argument
        context.config[
            interfaces.configuration.path_join(config_path, "symbol_mask")
        ] = mask
        return linux.LinuxKernelIntermedSymbols(
            context,
            config_path,
            name=name,
            isf_url=url,
            validate=validate,
            symbol_mask=mask,
        )

    @classmethod
    def _kernel_layer(
        cls,
        context: interfaces.context.ContextInterface,
        table: intermed.IntermediateSymbolTable,
        table_name: str,
        layer_name: str,
        banner: str,
        host: interfaces.plugins.PluginInterface,
    ) -> interfaces.layers.TranslationLayerInterface:
        """The Intel layer of the guest's kernel, made as `LinuxIntelStacker.stack` makes it."""
        join = interfaces.configuration.path_join
        try:
            kaslr_shift, aslr_shift = linux_automagic.LinuxIntelStacker.find_aslr(
                context,
                table_name,
                layer_name,
                progress_callback=host._progress_callback,
            )
        finally:
            # find_aslr adds a module named like the table, on the physical layer; `get_module_from_volobj_type`
            # takes the first module that uses a table, so this one would be the kernel of every object
            for name in list(context.modules.get_modules_by_symbol_tables(table_name)):
                del context.modules[name]
        # the page directory symbol and the layer class, as the stacker picks them: 64-bit kernels have `init_top_pgt`
        # (4.13 on) or `init_level4_pgt`; on 32-bit a PAE kernel has a `pkmap_count` of 512 or 2048 entries
        if "init_top_pgt" in table.symbols:
            layer_class, dtb_symbol = intel.LinuxIntel32e, "init_top_pgt"
        elif "init_level4_pgt" in table.symbols:
            layer_class, dtb_symbol = intel.LinuxIntel32e, "init_level4_pgt"
        elif "pkmap_count" in table.symbols and table.get_symbol(
            "pkmap_count"
        ).type.count in (512, 2048):
            layer_class, dtb_symbol = intel.LinuxIntelPAE, "swapper_pg_dir"
        else:
            layer_class, dtb_symbol = intel.LinuxIntel, "swapper_pg_dir"
        # the symbol's address is virtual and shifted by KASLR
        dtb = linux_automagic.LinuxIntelStacker.virtual_to_physical_address(
            table.get_symbol(dtb_symbol).address + kaslr_shift
        )
        new_name = context.layers.free_layer_name("IntelLayer")
        path = join("IntelHelper", new_name)
        context.config[join(path, "memory_layer")] = layer_name
        context.config[join(path, "page_map_offset")] = dtb
        context.config[
            join(path, linux_automagic.LinuxSymbolFinder.banner_config_key)
        ] = banner
        layer = layer_class(context, path, new_name, metadata={"os": "Linux"})
        layer.config["kernel_virtual_offset"] = aslr_shift
        context.add_layer(layer)
        vollog.debug(f"Guest DTB at {dtb:#x}, KASLR {kaslr_shift:#x}/{aslr_shift:#x}")
        return layer

    @classmethod
    def _symbol_siblings(
        cls, path: str, requirement: interfaces.configuration.RequirementInterface
    ) -> Iterator[str]:
        """Configuration paths of the symbol table requirements next to a translation layer requirement: the ones that
        the kernel's table belongs to (a module's `symbol_table_name`, a plugin's own table)."""
        join = interfaces.configuration.path_join
        here = join(path, requirement.name)
        # the table sits beside the layer requirement, in the same module requirement
        children = requirement.requirements
        if any(
            isinstance(r, requirements.TranslationLayerRequirement)
            for r in children.values()
        ):
            for child in children.values():
                if isinstance(child, requirements.SymbolTableRequirement):
                    yield join(here, child.name)
        # and the same in the requirements below (a module inside the plugin)
        for child in children.values():
            yield from cls._symbol_siblings(here, child)

    @classmethod
    def _plugin_requirement(
        cls, plugin: Type[interfaces.plugins.PluginInterface]
    ) -> requirements.MultiRequirement:
        """The plugin's requirements as one `MultiRequirement`, as `automagic.run` and `construct_plugin` see them."""
        requirement = requirements.MultiRequirement(name=plugin.__name__)
        for req in plugin.get_requirements():
            requirement.add_requirement(req)
        return requirement

    @classmethod
    def _attach(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        plugin: Type[interfaces.plugins.PluginInterface],
        stacked: List[str],
    ) -> None:
        """Fulfills the plugin's layer requirement from the stacked layers.

        The top layer is built again at the requirement's own configuration path, as `ConstructionMagic` does: the
        automagics write what they find under the layer's path (the PDB scanner: `kernel_virtual_offset`) but read it,
        and the memory layer's name, under the requirement's."""
        # the plugin's translation layer requirement that the top stacked layer can fulfil
        found = stacker.LayerStacker.find_suitable_requirements(
            context, config_path, cls._plugin_requirement(plugin), stacked
        )
        if not found:
            return
        path, top = found
        top_layer = context.layers[top]
        context.config.merge(path, top_layer.build_configuration())
        for req in top_layer.get_requirements():
            if isinstance(req, requirements.TranslationLayerRequirement):
                if top_layer.config.get(req.name):
                    context.config[
                        interfaces.configuration.path_join(path, req.name)
                    ] = top_layer.config[req.name]
        name = context.layers.free_layer_name(top)
        context.add_layer(top_layer.__class__(context, path, name))
        context.config[path] = name

    @classmethod
    def _windows_isf_in_dirs(
        cls, dirs: List[str], pdb_name: str, guid: str, age: int
    ) -> Optional[str]:
        """The ISF of a Windows kernel's PDB below the directories, as `windows/<pdb name>/<GUID>-<age>` is found in a
        symbol path."""
        # the PDB name in the kernel's debug data is padded with NULs
        wanted = os.path.join(pdb_name.strip("\x00"), f"{guid.upper()}-{age}")
        for directory in dirs:
            for extension in constants.ISF_EXTENSIONS:
                for path in (
                    pathlib.Path(directory)
                    .joinpath("windows")
                    .rglob(wanted + extension)
                ):
                    return path.resolve().as_uri()
        return None

    @classmethod
    def _use_guest_symbol_dirs(
        cls, scanner: "pdbscan.KernelPDBScanner", dirs: List[str]
    ) -> None:
        """Makes the PDB automagic of this run take the Windows kernel's table from `--guest-symbol-dirs` first.

        Volatility's own lookup would have to be told the directories through the symbol path and the cache, which is
        global state that this run leaves alone. The table is constructed as `PDBUtility.load_windows_symbol_table`
        does, for the requirements that the scanner found."""
        original = scanner.recurse_symbol_fulfiller

        def fulfil(context, valid_kernel, progress_callback=None):
            # `valid_kernel` is (layer, offset, kernel info), or None if the scanner found no kernel
            if valid_kernel:
                _layer, _offset, kernel = valid_kernel
                url = cls._windows_isf_in_dirs(
                    dirs, kernel["pdb_name"], kernel["GUID"], kernel["age"]
                )
                if url:
                    join = interfaces.configuration.path_join
                    for sub_path, _requirement in scanner._symbol_requirements:
                        context.config[join(sub_path, "class")] = (
                            "volatility3.framework.symbols.windows.WindowsKernelIntermedSymbols"
                        )
                        context.config[join(sub_path, "isf_url")] = url
                        requirements.SymbolTableRequirement(
                            name=interfaces.configuration.path_head(sub_path),
                            description="Guest symbol table from --guest-symbol-dirs",
                        ).construct(
                            context, interfaces.configuration.parent_path(sub_path)
                        )
                    return None
            # no table of ours for this kernel: the usual lookup (identifier cache, download)
            return original(context, valid_kernel, progress_callback)

        scanner.recurse_symbol_fulfiller = fulfil

    @classmethod
    def _unsatisfied(
        cls,
        plugin: Type[interfaces.plugins.PluginInterface],
        vm: qemu_common.GuestVM,
        banner: Optional[object],
        built: bool,
        excp: exceptions.UnsatisfiedException,
    ) -> GuestSymbolsError:
        """The error for a guest plugin that its guest's symbol table does not satisfy."""
        if banner is None:
            banner = qemu_common.QemuCommon.guest_banner(vm.ram)
        advice = (
            "the symbol table built from its memory did not satisfy the plugin"
            if built
            else "its symbol table must be in --guest-symbol-dirs"
        )
        return GuestSymbolsError(
            f"{plugin.__name__} cannot run on the guest (unsatisfied: {', '.join(excp.unsatisfied)}). Guest "
            f"banner: {banner}; {advice}."
        )

    @classmethod
    def run(
        cls,
        host: interfaces.plugins.PluginInterface,
        host_os: str,
        find_guest: Callable[
            [interfaces.context.ContextInterface], qemu_common.GuestVM
        ],
    ) -> interfaces.renderers.TreeGrid:
        """Runs the plugin named by `--guest-plugin` on the guest that `find_guest` finds, in a copy of the host's
        context.

        Args:
            host: The plugin (`linux.qemu_guest.Run` or `windows.qemu_guest.Run`)
            host_os: 'linux' or 'windows'
            find_guest: Finds the selected guest in the context it is given

        Returns:
            The guest plugin's own table, whose rows are made as it is rendered; an empty one, after logging the
            reason, if the options name no plugin, an unknown or ambiguous one, or select no guest or several

        Raises:
            GuestSymbolsError: No symbol table for a Linux guest's kernel, or the plugin cannot run on the guest
        """
        kernel_name = host.config["kernel"]
        try:
            name = host.config.get("guest_plugin")
            if not name:
                raise GuestSelectionError(
                    "No plugin to run on the guest: add --guest-plugin, e.g. --guest-plugin linux.pslist.PsList"
                )
            plugin = cls.find_plugin(name)
            # everything that follows happens in a copy: the host's context gets no layer, module, table or key
            context = host.context.clone()
            vm = find_guest(context)
        except GuestSelectionError as excp:
            vollog.error(str(excp))
            return renderers.TreeGrid([("Guest", str)], None)
        vollog.info(
            f"Guest of PID {vm.pid}: RAM at {vm.ram.start:#x}, {vm.ram.size >> 20} MiB, {vm.machine}"
        )
        qemu_common.QemuCommon.log_residency(f"PID {vm.pid}", vm.ram)
        # the plugin's package (volatility3.plugins.<os>) says which kind of guest it is for
        linux_guest = cls.plugin_os(plugin) == "linux"
        banner = banners = None
        if linux_guest:
            # the banner is for messages; `banners` is what the symbol table is looked up by
            banners = qemu_common.QemuCommon.linux_banners(vm.ram)
            banner = (
                qemu_common.QemuCommon.preferred_banner(banners)
                if banners
                else qemu_common.QemuCommon.guest_banner(vm.ram)
            )
        # the host's blocks read their page caches now, while the module they walk them through is still the host's
        for block in vm.ram.blocks:
            if block.has_fallback:
                block.load_page_cache()
        kept = cls.release_host_module(context, kernel_name)
        layer_name = cls.add_guest_layer(context, vm, host_os, kept)
        # the host's page files belong to the QEMU process's layers; the guest's own page file is inside the guest,
        # and the automagic would hand the host's to the guest's kernel layer
        swap_key = interfaces.configuration.path_join(
            "automagic", "WinSwapLayers", "single_swap_locations"
        )
        if context.config.get(swap_key) is not None:
            del context.config[swap_key]
        # whether the guest's table was built from its memory, for the message if it does not fit
        built = False
        dirs = [os.path.abspath(d) for d in host.config.get("guest_symbol_dirs") or []]
        if linux_guest:
            if not banners:
                # no Linux banner in the guest's memory: no table can be found for it
                raise cls._unsatisfied(
                    plugin,
                    vm,
                    banner,
                    False,
                    exceptions.UnsatisfiedException(
                        plugin.unsatisfied(
                            context,
                            interfaces.configuration.path_join(
                                host.config_path, plugin.__name__
                            ),
                        )
                    ),
                )
            try:
                stacked, table_name, built = cls._linux_kernel(
                    host, context, layer_name, banners, dirs
                )
            except kernel_btf.BtfError as excp:
                raise GuestSymbolsError(
                    f"No symbol table for the guest kernel ({banner}) in --guest-symbol-dirs, and none "
                    f"could be built from its memory: {excp}"
                ) from excp
            # the stackers have nothing to find in a Linux guest: its kernel is preset in the plugin's requirements
            for path in cls._symbol_siblings(
                host.config_path, cls._plugin_requirement(plugin)
            ):
                context.config[path] = table_name
        else:
            # a Windows guest: the stackers find the kernel's layer, and the PDB automagic its symbols (below)
            by_name = {
                s.__name__: s
                for s in framework.class_subclasses(
                    interfaces.automagic.StackerLayerInterface
                )
            }
            stack_set = [by_name[n] for n in stacker.choose_os_stackers(plugin)]
            stacked = stacker.LayerStacker.stack_layer(
                context, layer_name, stack_set, host._progress_callback
            )
        cls._attach(context, host.config_path, plugin, stacked)
        magics = [
            magic
            for magic in automagic.choose_automagic(
                automagic.available(context), plugin
            )
            # the layers are stacked above, and the identifier cache is Volatility's own
            if not isinstance(
                magic, (stacker.LayerStacker, symbol_cache.SymbolCacheMagic)
            )
        ]
        if dirs and not linux_guest:
            # a Windows guest's table is looked for in the directories before the cache and the download
            for magic in magics:
                if isinstance(magic, pdbscan.KernelPDBScanner):
                    cls._use_guest_symbol_dirs(magic, dirs)
        try:
            guest_plugin = plugins.construct_plugin(
                context,
                magics,
                plugin,
                host.config_path,
                host._progress_callback,
                host.open,
            )
        except exceptions.UnsatisfiedException as excp:
            raise cls._unsatisfied(plugin, vm, banner, built, excp) from excp
        return guest_plugin.run()
