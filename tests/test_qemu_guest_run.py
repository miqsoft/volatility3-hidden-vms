"""Unit tests for linux.qemu_guest.Run, windows.qemu_guest.Run and what they share (qemu_guest_run), with small fakes
instead of images."""

import base64
import copy
import gc
import json
import lzma
import os
import weakref
from types import SimpleNamespace

import pytest
import volatility3.symbols
from volatility3.framework import constants, contexts, exceptions, interfaces, renderers
from volatility3.framework.automagic import symbol_cache
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import physical, scanners
from volatility3.plugins import kernel_btf, qemu_common, qemu_guest_run
from volatility3.plugins.linux import qemu_guest
from volatility3.plugins.windows import qemu_guest as wqemu_guest

PAGE = qemu_common.PAGE
QemuGuestLayer = qemu_guest_run.QemuGuestLayer
Run = qemu_guest_run.QemuGuestRun

# the entries of the fake process layer's pages that it does not translate
NEVER = 0
SWAPPED = (3 << 59) | (0x1234 << 12)  # a swap entry of area 3
MIGRATION = (
    28 << 59
)  # the migration, poison and marker entries are above the swap areas
PRESENT = 0x8000000000000001  # present: its frame is not in the image


def component(requirement):
    """The class a VersionRequirement names, and the version it asks for (no public accessor)."""
    return requirement._component, requirement._version


class ProcessLayer(physical.BufferDataLayer):
    """A QEMU process's layer: `mapped` pages are translated; every other page has an entry that `translate` raises
    with, as the Intel layers do (a page with no entry listed has an empty one)."""

    def __init__(self, context, name, data, mapped, entries=None):
        super().__init__(context, name, name, data)
        self.mapped, self.entries = mapped, entries or {}

    def mapping(self, offset, length, ignore_errors=False):
        position = offset
        while position < offset + length:
            stop = min((position & ~(PAGE - 1)) + PAGE, offset + length)
            if position // PAGE in self.mapped:
                yield position, stop - position, position, stop - position, self.name
            elif not ignore_errors:
                raise exceptions.InvalidAddressException(self.name, position, "hole")
            position = stop

    def translate(self, address, ignore_errors=False):
        page = address // PAGE
        if page in self.mapped:
            return address, self.name
        entry = self.entries.get(page, NEVER)
        if entry == PRESENT:
            raise exceptions.InvalidAddressException(
                "memory", address, "the frame is not in the image"
            )
        raise exceptions.PagedInvalidAddressException(
            self.name, address, 12, entry, "not present"
        )


def guest_layer(entries, mapped=(0, 3, 6), page_cache=False, host_os="linux"):
    """A guest layer of eight pages that sit at the same addresses in the process layer, where page p holds the byte
    0x10 + p: pages 0, 3 and 6 are translated, the others have the entries given."""
    context = contexts.Context()
    data = b"".join(bytes([0x10 + p]) * PAGE for p in range(8))
    context.add_layer(ProcessLayer(context, "process", data, set(mapped), entries))
    path = "QemuGuest.guest"
    context.config[path + ".base_layer"] = "process"
    context.config[path + ".segments"] = [0, 0, 8 * PAGE]
    context.config[path + ".host_os"] = host_os
    context.config[path + ".host_module"] = "host"
    context._module_space = {"host": SimpleNamespace(layer_name="kernel-layer")}
    if page_cache:
        context.config[path + ".page_cache"] = [0, 8 * PAGE, 0x5000]
        context.add_layer(physical.BufferDataLayer(context, "k", "kernel-layer", b"x"))
    return context, path


def standard_entries():
    return {1: NEVER, 2: SWAPPED, 4: NEVER, 5: PRESENT, 7: MIGRATION}


def test_guest_layer_pages_are_data_zeros_or_lost():
    """Translated pages are data, pages the host never backed are zeros, swapped, migrated and frameless ones lost."""
    context, path = guest_layer(standard_entries())
    layer = QemuGuestLayer(context, path, "guest")
    context.add_layer(layer)
    assert layer.read(0, PAGE) == b"\x10" * PAGE
    assert layer.read(3 * PAGE, PAGE) == b"\x13" * PAGE
    assert layer.read(PAGE, PAGE) == bytes(PAGE)  # never backed: the guest's zeros
    assert layer.is_valid(PAGE, PAGE) and layer.is_valid(0, 2 * PAGE)
    for lost in (2, 5, 7):
        assert not layer.is_valid(lost * PAGE)
        assert not layer.is_valid(lost * PAGE - 4, 8)
        with pytest.raises(exceptions.InvalidAddressException) as raised:
            layer.read(lost * PAGE + 8, 16)
        assert raised.value.invalid_address >= lost * PAGE
    # a read that pads gives zeros for what is lost and the data around it
    assert layer.read(3 * PAGE - 4, 8, pad=True) == bytes(4) + b"\x13" * 4
    assert layer.read(6 * PAGE - 4, 8, pad=True) == bytes(4) + b"\x16" * 4
    # outside the segments there is no RAM at all
    assert not layer.is_valid(8 * PAGE)
    with pytest.raises(exceptions.InvalidAddressException):
        layer.read(8 * PAGE - 4, 8)


def test_mapping_is_valid_and_read_agree_on_every_page():
    context, path = guest_layer(standard_entries())
    layer = QemuGuestLayer(context, path, "guest")
    context.add_layer(layer)
    runs = list(layer.mapping(0, 8 * PAGE, ignore_errors=True))
    covered = {
        page
        for gpa, size, _addr, _msize, _layer in runs
        for page in range(gpa // PAGE, (gpa + size) // PAGE)
    }
    # 0, 3 and 6 are translated, 1 and 4 were never backed; 2, 5 and 7 are lost
    assert covered == {0, 1, 3, 4, 6}
    for page in range(8):
        assert layer.is_valid(page * PAGE, PAGE) == (page in covered)
        if page in covered:
            layer.read(page * PAGE, PAGE)
    with pytest.raises(exceptions.InvalidAddressException):
        list(layer.mapping(0, 8 * PAGE))
    # the zero page that follows a translated one is a run of its own, and so are the others
    assert [run[:2] for run in runs] == [
        (0, PAGE),
        (PAGE, PAGE),
        (3 * PAGE, PAGE),
        (4 * PAGE, PAGE),
        (6 * PAGE, PAGE),
    ]
    assert all(run[2:] == (run[0], run[1], "process") for run in runs)


def test_scan_sees_what_read_returns():
    """A scan finds what `read` returns, at the right guest address, and nothing in a lost page."""
    context, path = guest_layer(standard_entries())
    layer = QemuGuestLayer(context, path, "guest")
    context.add_layer(layer)
    found = list(layer.scan(context, scanners.BytesScanner(b"\x13" * 16)))
    assert found == list(range(3 * PAGE, 4 * PAGE - 15))
    # page 2 holds 0x12 in the process layer, but is lost: a scan must not see it
    assert list(layer.scan(context, scanners.BytesScanner(b"\x12" * 16))) == []
    # the zeros of a page that was never backed are seen, as `read` gives them
    assert PAGE in list(layer.scan(context, scanners.BytesScanner(bytes(64))))


class FakePage:
    def __init__(self, index, address, content, mapping):
        self.index, self.mapping, self._content = index, mapping, content
        self.vol = SimpleNamespace(
            offset=address, type_name="host!page", layer_name="kernel-layer"
        )

    def has_member(self, name):
        return False

    def get_content(self):
        return self._content


HUGETLBFS = qemu_guest_run.qemu.HUGETLBFS_MAGIC
TMPFS = qemu_guest_run.qemu.TMPFS_MAGIC
EXT4 = 0xEF53


def with_page_cache(monkeypatch, context, pages, magic=HUGETLBFS, swapped=None):
    """The host's module reads the vm_area_struct at 0x5000; its file's page cache holds `pages` ({file index:
    content or None}). The file is on the file system with the superblock `magic`; a tmpfs file has `swapped` pages in
    swap (None: the kernel has no `shmem_inode_info`)."""
    mapping = "address-space"
    cached = [FakePage(i, 0x100 + i, c, mapping) for i, c in pages.items()]
    inode = SimpleNamespace(
        i_sb=SimpleNamespace(s_magic=magic),
        vol=SimpleNamespace(offset=0x9000),
        i_size=8 * PAGE,
        i_mapping=SimpleNamespace(
            is_readable=lambda: True, nrpages=len(cached), dereference=lambda: None
        ),
    )
    inode.i_mapping.__eq__ = lambda self, other: other == mapping
    for page in cached:
        page.mapping = inode.i_mapping
    vma = SimpleNamespace(
        vm_start=0,
        vm_end=8 * PAGE,
        vm_pgoff=0,
        vm_file=SimpleNamespace(get_inode=lambda: inode),
    )
    asked = []

    class FakePageCache:
        def __init__(self, context, kernel_module_name, page_cache):
            asked.append(kernel_module_name)

        def get_cached_pages(self):
            return iter(cached)

    monkeypatch.setattr(qemu_guest_run.linux, "PageCache", FakePageCache)
    utilities = qemu_guest_run.linux.LinuxUtilities
    monkeypatch.setattr(
        utilities,
        "get_module_from_volobj_type",
        classmethod(lambda cls, ctx, volobj: "kernel module"),
    )
    # SHMEM_I(inode): the inode is the member `vfs_inode` of a `shmem_inode_info`
    containers = []

    def container_of(cls, addr, type_name, member_name, vmlinux):
        containers.append((addr, type_name, member_name, vmlinux))
        if swapped is None:
            raise exceptions.SymbolError("shmem_inode_info", "host", "no such type")
        return SimpleNamespace(swapped=swapped)

    monkeypatch.setattr(utilities, "container_of", classmethod(container_of))
    context.shmem_calls = containers
    by_address = {page.vol.offset: page for page in cached}
    context.object = lambda type_name, layer_name, offset: by_address[offset]
    context._module_space["host"].object = lambda name, offset, absolute: vma
    return asked


def test_page_cache_fills_a_page_that_the_process_lacks(monkeypatch):
    """A page that only the file's page cache holds reads as that data; a cached page without data is lost; the
    cache is walked through the host's module, by name, and only when a page needs it."""
    context, path = guest_layer(standard_entries(), page_cache=True)
    asked = with_page_cache(
        monkeypatch, context, {4: b"\xaa" * PAGE, 5: None, 2: b"\xbb" * PAGE}
    )
    layer = QemuGuestLayer(context, path, "guest")
    context.add_layer(layer)
    assert layer.read(3 * PAGE, PAGE) == b"\x13" * PAGE
    assert asked == []  # translated pages need no page cache
    assert layer.read(4 * PAGE - 4, 8) == b"\x13" * 4 + b"\xaa" * 4
    assert asked == ["host"]
    assert layer.read(4 * PAGE, PAGE) == b"\xaa" * PAGE
    # page 2 is swapped out of the process, but its data is in the cache: that wins
    assert layer.read(2 * PAGE, 8) == b"\xbb" * 8
    # page 5 has a page-cache entry whose data is not in the image: lost
    assert not layer.is_valid(5 * PAGE)
    assert asked == ["host"]
    covered = [lo // PAGE for lo, *_ in layer.mapping(0, 8 * PAGE, ignore_errors=True)]
    assert covered == [0, 1, 2, 3, 4, 6]
    # the scans see the cached page
    found = list(layer.scan(context, scanners.BytesScanner(b"\xaa" * 32)))
    assert found == list(range(4 * PAGE, 5 * PAGE - 31))


def lost_and_zero_pages(monkeypatch, **file):
    """(pages that are valid, pages that read as zeros) of the guest layer over a file with the given file system."""
    context, path = guest_layer(standard_entries(), page_cache=True)
    with_page_cache(monkeypatch, context, {4: b"\xaa" * PAGE}, **file)
    layer = QemuGuestLayer(context, path, "guest")
    context.add_layer(layer)
    valid = [p for p in range(8) if layer.is_valid(p * PAGE)]
    return valid, [p for p in valid if layer.read(p * PAGE, PAGE) == bytes(PAGE)]


def test_a_page_missing_from_a_hugetlbfs_file_is_zeros(monkeypatch):
    """hugetlbfs has no swap and no disk: an empty entry and no page in the cache is a page that was never written."""
    valid, zeros = lost_and_zero_pages(monkeypatch, magic=HUGETLBFS)
    # pages 1 and 4 have an empty entry; 4 has data in the cache; 2, 5 and 7 are lost for their entries
    assert valid == [0, 1, 3, 4, 6] and zeros == [1]


def test_a_page_missing_from_a_tmpfs_file_is_zeros_only_if_nothing_is_swapped(
    monkeypatch,
):
    valid, zeros = lost_and_zero_pages(monkeypatch, magic=TMPFS, swapped=0)
    assert valid == [0, 1, 3, 4, 6] and zeros == [1]
    # a swapped-out shmem page is a value entry that the page-cache walk skips: it may be that page
    valid, zeros = lost_and_zero_pages(monkeypatch, magic=TMPFS, swapped=3)
    assert valid == [0, 3, 4, 6] and zeros == []


def test_shmem_inode_info_is_found_from_the_vfs_inode_of_the_host_kernel(monkeypatch):
    context, path = guest_layer(standard_entries(), page_cache=True)
    with_page_cache(monkeypatch, context, {}, magic=TMPFS, swapped=0)
    layer = QemuGuestLayer(context, path, "guest")
    assert layer.read(PAGE, PAGE) == bytes(PAGE)
    assert context.shmem_calls == [
        (0x9000, "shmem_inode_info", "vfs_inode", "kernel module")
    ]
    # the verdict is made once for the file
    layer.read(4 * PAGE, PAGE)
    assert len(context.shmem_calls) == 1


def test_a_tmpfs_file_of_an_unknown_kernel_layout_is_not_assumed_to_hold_zeros(
    monkeypatch,
):
    valid, zeros = lost_and_zero_pages(monkeypatch, magic=TMPFS, swapped=None)
    assert valid == [0, 3, 4, 6] and zeros == []


def test_a_page_missing_from_a_file_on_another_file_system_is_lost(monkeypatch):
    """A page of a regular file may be on disk only; the reason names the page cache."""
    valid, zeros = lost_and_zero_pages(monkeypatch, magic=EXT4)
    assert valid == [0, 3, 4, 6] and zeros == []
    context, path = guest_layer(standard_entries(), page_cache=True)
    with_page_cache(monkeypatch, context, {}, magic=EXT4)
    layer = QemuGuestLayer(context, path, "guest")
    with pytest.raises(exceptions.InvalidAddressException) as raised:
        layer.read(PAGE, PAGE)
    assert "not in the page cache (may be swapped or on disk)" in str(raised.value)
    # a page whose entry says more keeps its own reason
    with pytest.raises(exceptions.InvalidAddressException) as raised:
        layer.read(2 * PAGE, PAGE)
    assert "swapped out" in str(raised.value)


def test_an_anonymous_mapping_still_reads_zeros_for_an_empty_entry():
    context, path = guest_layer(standard_entries())
    layer = QemuGuestLayer(context, path, "guest")
    assert layer.read(PAGE, PAGE) == bytes(PAGE)
    assert layer.is_valid(4 * PAGE)


def test_layer_rebuilt_from_its_configuration_reads_the_same_bytes(monkeypatch):
    """Everything the layer needs is in its configuration (`build_configuration`): a layer made from it in a fresh
    context, which has only the process layer and the host's module, gives the same bytes as the first."""
    context, path = guest_layer(standard_entries(), page_cache=True)
    with_page_cache(monkeypatch, context, {4: b"\xaa" * PAGE})
    first = QemuGuestLayer(context, path, "guest")
    context.add_layer(first)
    config = first.build_configuration()
    assert {key.split(".")[0] for key in config} >= {
        "segments",
        "host_os",
        "host_module",
        "page_cache",
    }
    fresh = contexts.Context()
    fresh.add_layer(context.layers["process"])
    fresh.add_layer(context.layers["kernel-layer"])
    fresh._module_space = context._module_space
    fresh.object = context.object
    fresh.config.merge("QemuGuest.rebuilt", config)
    # the name of the layer below is the one value that a layer's configuration leaves to the requirement (as when
    # the framework rebuilds a stacked layer from `build_configuration`)
    fresh.config["QemuGuest.rebuilt.base_layer"] = first.config["base_layer"]
    rebuilt = QemuGuestLayer(fresh, "QemuGuest.rebuilt", "rebuilt")
    fresh.add_layer(rebuilt)
    assert rebuilt.dependencies == first.dependencies == ["process", "kernel-layer"]
    for page in range(8):
        for offset in (page * PAGE, page * PAGE + 100):
            assert rebuilt.is_valid(offset, 8) == first.is_valid(offset, 8)
            assert rebuilt.read(offset, 8, pad=True) == first.read(offset, 8, pad=True)
    assert rebuilt.read(4 * PAGE, PAGE) == b"\xaa" * PAGE
    assert rebuilt.read(0, 8 * PAGE, pad=True) == first.read(0, 8 * PAGE, pad=True)
    assert rebuilt.maximum_address == first.maximum_address


def test_layer_requirements_describe_the_fallback():
    names = {r.name: r for r in QemuGuestLayer.get_requirements()}
    assert {"base_layer", "segments", "host_os", "host_module", "page_cache"} <= set(
        names
    )
    assert names["segments"].optional is False
    for optional in ("host_os", "host_module", "page_cache"):
        assert names[optional].optional


def test_dependencies_name_the_host_layer_only_with_a_page_cache():
    context, path = guest_layer(standard_entries())
    assert QemuGuestLayer(context, path, "guest").dependencies == ["process"]


def test_windows_host_pages_are_classified_by_the_windows_pte(monkeypatch):
    """A Windows host's non-present entries: demand-zero is zeros, a paging file page is lost."""
    seen = []

    class FakePte:
        def __init__(self, context, module):
            seen.append(module)

        def reason(self, entry, bits):
            return {0: "demand-zero", 5: "pagefile 1"}.get(entry)

    monkeypatch.setattr(qemu_guest_run.windows_qemu, "WindowsPte", FakePte)
    context, path = guest_layer({1: 0, 2: 5, 4: 0, 5: 5, 7: 5}, host_os="windows")
    layer = QemuGuestLayer(context, path, "guest")
    context.add_layer(layer)
    assert layer.read(PAGE, PAGE) == bytes(PAGE)
    assert not layer.is_valid(2 * PAGE)
    assert seen == ["host"]


def test_a_host_without_a_kind_explains_only_empty_entries():
    context, path = guest_layer({1: NEVER, 2: SWAPPED}, host_os="")
    layer = QemuGuestLayer(context, path, "guest")
    assert layer.is_valid(PAGE) and not layer.is_valid(2 * PAGE)


def test_a_zero_length_mapping_translates():
    context, path = guest_layer(standard_entries())
    layer = QemuGuestLayer(context, path, "guest")
    assert layer.translate(3 * PAGE + 5) == (3 * PAGE + 5, "process")
    assert layer.translate(2 * PAGE, ignore_errors=True) == (None, None)


# --- the plugins ------------------------------------------------------------------------------------


def test_requirements_are_named_as_upstream_names_them():
    """Underscores in the names (the CLI turns them into hyphens), a list of directories, a flag for saving."""
    for plugin in (qemu_guest.Run, wqemu_guest.Run):
        required = {r.name: r for r in plugin.get_requirements()}
        assert not [name for name in required if "-" in name]
        assert {"guest_plugin", "pid", "ram_at", "guest_symbol_dirs"} <= set(required)
        # optional so that -h works (argparse reports a missing required option first); run() logs the error
        assert required["guest_plugin"].optional
        dirs = required["guest_symbol_dirs"]
        assert isinstance(dirs, requirements.ListRequirement)
        assert dirs.element_type is str and dirs.optional
        save = required["save_guest_symbols"]
        assert isinstance(save, requirements.BooleanRequirement) and not save.default
        assert component(required["qemu_guest_run"])[0] is Run
        assert component(required["qemu_common"])[1] >= (3, 0, 0)
        assert plugin._version[0] == 2
    assert "kvm" in {r.name for r in qemu_guest.Run.get_requirements()}
    assert "kvm" not in {r.name for r in wqemu_guest.Run.get_requirements()}


def test_the_helper_declares_the_host_plugins_whose_parts_it_uses():
    """`LinuxRamBlock`, `linux_pte_reason` and `uncached_reason` are linux.qemu's, `WindowsPte` is windows.qemu's."""
    required = {r.name: r for r in Run.get_requirements()}
    assert component(required["qemu"])[0] is qemu_guest_run.qemu.VMs
    assert component(required["qemu"])[1] >= (1, 6, 0)
    assert component(required["windows_qemu"])[0] is qemu_guest_run.windows_qemu.VMs
    assert hasattr(qemu_guest_run.qemu.LinuxRamBlock, "uncached_reason")


def test_each_run_has_its_own_host_requirements():
    windows = {r.name: r for r in wqemu_guest.Run.get_requirements()}
    linux = {r.name: r for r in qemu_guest.Run.get_requirements()}
    assert windows["kernel"].requirements["layer_name"].architectures == [
        "Intel32",
        "Intel64",
    ]
    assert linux["kernel"].requirements["layer_name"].architectures == ["Intel64"]
    assert "windows.qemu.VMs" in windows["ram_at"].description
    assert "linux.qemu.VMs" in linux["ram_at"].description
    assert wqemu_guest.Run.__bases__ == (interfaces.plugins.PluginInterface,)
    for name in ("guest_plugin", "pid", "guest_symbol_dirs", "save_guest_symbols"):
        assert type(windows[name]) is type(linux[name])
        assert windows[name].description == linux[name].description


def test_the_runs_share_one_helper_and_a_config_path():
    assert qemu_guest.Run.__name__ == wqemu_guest.Run.__name__ == "Run"
    assert qemu_guest.Run.__module__ != wqemu_guest.Run.__module__


# --- selection errors are logged, symbol errors raised ------------------------------------------------


def test_selection_errors_are_exceptions_with_the_old_messages():
    with pytest.raises(qemu_guest_run.GuestSelectionError) as raised:
        Run.only_guest([], "--pid / --ram-at", ["PID 7: encrypted (SEV)"])
    assert str(raised.value) == (
        "Need exactly one guest, found: none (select with --pid / --ram-at); skipped PID 7: encrypted (SEV)"
    )
    two = [
        SimpleNamespace(pid=1, ram=SimpleNamespace(start=0x1000)),
        SimpleNamespace(pid=2, ram=SimpleNamespace(start=0x2000)),
    ]
    with pytest.raises(
        qemu_guest_run.GuestSelectionError, match="PID 1 RAM at 0x1000, PID 2"
    ):
        Run.only_guest(two, "--pid")
    assert Run.only_guest(two[:1], "--pid") is two[0]


def test_plugin_names_are_found_by_full_name_or_file_name():
    assert Run.find_plugin("linux.pslist.PsList").__name__ == "PsList"
    assert Run.find_plugin("linux.pslist").__name__ == "PsList"
    with pytest.raises(
        qemu_guest_run.GuestSelectionError, match="Unknown plugin linux.nope"
    ):
        Run.find_plugin("linux.nope.Nope")
    with pytest.raises(qemu_guest_run.GuestSelectionError, match="matches several"):
        Run.find_plugin("linux.kvm")
    with pytest.raises(
        qemu_guest_run.GuestSelectionError, match=r"similar: .*linux\.pslist\.PsList"
    ):
        Run.find_plugin("linux.pslist.PsLis")


def test_symbol_failures_are_errors_that_vol_prints_with_their_message():
    """`vol` prints the message of a SymbolSpaceError; a bare VolatilityException is shown as an 'unexpected situation'
    without it. A selection error never reaches `vol`: `run` logs it."""
    assert issubclass(qemu_guest_run.GuestSymbolsError, exceptions.SymbolSpaceError)
    assert not issubclass(qemu_guest_run.GuestSelectionError, exceptions.LayerException)


class FakeHost:
    """A plugin as far as `QemuGuestRun.run` looks at it."""

    config_path = "plugins.Run"
    _progress_callback = None
    open = None

    def __init__(self, context, config):
        self.context, self.config = context, {"kernel": "kernel", **config}


def host_context():
    context = contexts.Context()
    context.add_layer(physical.BufferDataLayer(context, "k", "kernel-layer", b"x"))
    context._module_space = {}
    return context


def selecting_run(config, find_guest=lambda ctx: None):
    context = host_context()
    context._module_space = {"kernel": SimpleNamespace(layer_name="kernel-layer")}
    return Run.run(FakeHost(context, config), "linux", find_guest)


def assert_message_and_empty_grid(caplog, grid, message):
    errors = [r for r in caplog.records if r.levelname == "ERROR"]
    assert [r.getMessage() for r in errors] == [message]
    assert [c.name for c in grid.columns] == ["Guest"]
    rows = []
    grid.populate(lambda node, accumulator: rows.append(node))
    assert rows == []


def test_run_without_a_plugin_name_logs_and_returns_an_empty_table(caplog):
    grid = selecting_run({})
    assert_message_and_empty_grid(
        caplog,
        grid,
        "No plugin to run on the guest: add --guest-plugin, e.g. --guest-plugin linux.pslist.PsList",
    )


def test_run_with_an_unknown_or_ambiguous_plugin_logs_and_returns_an_empty_table(
    caplog,
):
    grid = selecting_run({"guest_plugin": "linux.nope"})
    assert_message_and_empty_grid(
        caplog, grid, "Unknown plugin linux.nope (see vol --help)"
    )
    caplog.clear()
    grid = selecting_run({"guest_plugin": "linux.kvm"})
    message = caplog.records[0].getMessage()
    assert message.startswith("linux.kvm matches several plugins, use the full name: ")
    assert [c.name for c in grid.columns] == ["Guest"]


def test_run_with_no_guest_or_several_logs_and_returns_an_empty_table(caplog):
    def none(ctx):
        return Run.only_guest([], "--pid / --ram-at")

    grid = selecting_run({"guest_plugin": "linux.pslist.PsList"}, none)
    assert_message_and_empty_grid(
        caplog,
        grid,
        "Need exactly one guest, found: none (select with --pid / --ram-at)",
    )
    caplog.clear()
    two = [
        SimpleNamespace(pid=1, ram=SimpleNamespace(start=0x1000)),
        SimpleNamespace(pid=2, ram=SimpleNamespace(start=0x2000)),
    ]
    grid = selecting_run(
        {"guest_plugin": "linux.pslist.PsList"},
        lambda ctx: Run.only_guest(two, "--pid", ["PID 3: encrypted (SEV)"]),
    )
    assert_message_and_empty_grid(
        caplog,
        grid,
        "Need exactly one guest, found: PID 1 RAM at 0x1000, PID 2 RAM at 0x2000 (select with --pid); "
        "skipped PID 3: encrypted (SEV)",
    )


class ModuleRecorder(dict):
    def free_module_name(self, prefix):
        count = 0
        while f"{prefix}{count or ''}" in self:
            count += 1
        return f"{prefix}{count or ''}"

    def add_module(self, module):
        self[module.name] = module


class FakeKernelModule:
    layer_name = "kernel-layer"

    def __init__(self, context, config_path, name):
        self.context, self.config_path, self.name = context, config_path, name


def test_the_host_module_changes_its_name_only_in_the_copy():
    context = host_context()
    context._module_space = ModuleRecorder(
        {"kernel": FakeKernelModule(context, "cfg", "kernel")}
    )
    copy = contexts.Context()
    copy._module_space = ModuleRecorder(
        {"kernel": FakeKernelModule(copy, "cfg", "kernel")}
    )
    assert Run.release_host_module(copy, "kernel") == "kernel_host"
    assert list(copy.modules) == ["kernel_host"]
    assert copy.modules["kernel_host"].context is copy
    assert list(context.modules) == ["kernel"]


def snapshot(context):
    return (
        list(context.layers),
        list(context.modules),
        list(context.symbol_space),
        sorted(context.config.data),
        list(volatility3.symbols.__path__),
    )


def test_run_leaves_the_host_context_and_the_symbol_path_alone(monkeypatch):
    """The guest is built and its plugin constructed in a copy: afterwards the host's layers, modules, symbol tables
    and configuration are as they were, and so is the symbol path."""
    context = host_context()
    context.add_layer(ProcessLayer(context, "process", bytes(8 * PAGE), {0, 1}))
    context._module_space = ModuleRecorder(
        {"kernel": FakeKernelModule(context, "cfg", "kernel")}
    )
    block = qemu_common.RamBlock(context.layers["process"], 0, 8 * PAGE, "anonymous")
    vm = qemu_common.GuestVM(
        7,
        qemu_common.GuestRam([block]),
        [qemu_common.Segment(0, 0, 8 * PAGE)],
        "pc",
    )
    seen = {}

    def construct(copy, magics, plugin, config_path, callback, open_method):
        seen["context"] = copy
        seen["magics"] = [type(m).__name__ for m in magics]
        return SimpleNamespace(run=lambda: "the guest plugin's table")

    monkeypatch.setattr(qemu_guest_run.plugins, "construct_plugin", construct)
    monkeypatch.setattr(
        qemu_common.QemuCommon,
        "linux_banners",
        classmethod(lambda cls, ram, start=0: ["Linux version 1"]),
    )
    monkeypatch.setattr(
        Run,
        "_linux_kernel",
        classmethod(
            lambda cls, host, ctx, layer, banners, dirs: ([layer], "table", True)
        ),
    )
    monkeypatch.setattr(
        qemu_common.QemuCommon,
        "log_residency",
        classmethod(lambda cls, label, ram: None),
    )
    host = FakeHost(
        context,
        {
            "guest_plugin": "linux.pslist.PsList",
            "guest_symbol_dirs": ["/guest/a", "/guest/b"],
        },
    )
    context.config[
        interfaces.configuration.path_join(
            "automagic", "WinSwapLayers", "single_swap_locations"
        )
    ] = ["pagefile.sys"]
    before = snapshot(context)
    config_before = dict(context.config)
    table = Run.run(host, "linux", lambda ctx: vm)
    assert table == "the guest plugin's table"
    assert snapshot(context) == before
    assert dict(context.config) == config_before
    copy = seen["context"]
    assert copy is not context
    assert any(name.startswith("QemuGuestLayer") for name in copy.layers)
    assert "kernel_host" in copy.modules and "kernel" not in copy.modules
    swap_key = interfaces.configuration.path_join(
        "automagic", "WinSwapLayers", "single_swap_locations"
    )
    assert copy.config.get(swap_key) is None
    assert context.config[swap_key] == ["pagefile.sys"]
    assert "LayerStacker" not in seen["magics"]
    assert "SymbolCacheMagic" not in seen["magics"]


def run_with_symbols(monkeypatch, banners, linux_kernel=None, construct=None):
    """`run` of a Linux guest plugin on a fake guest, with the banners that its memory holds."""
    context = host_context()
    context.add_layer(ProcessLayer(context, "process", bytes(8 * PAGE), {0, 1}))
    context._module_space = ModuleRecorder(
        {"kernel": FakeKernelModule(context, "cfg", "kernel")}
    )
    block = qemu_common.RamBlock(context.layers["process"], 0, 8 * PAGE, "anonymous")
    vm = qemu_common.GuestVM(
        7,
        qemu_common.GuestRam([block]),
        [qemu_common.Segment(0, 0, 8 * PAGE)],
        "pc",
    )
    common = qemu_common.QemuCommon
    monkeypatch.setattr(
        common, "linux_banners", classmethod(lambda cls, ram, start=0: banners)
    )
    monkeypatch.setattr(
        common, "guest_banner", classmethod(lambda cls, ram: "no banner")
    )
    monkeypatch.setattr(
        common, "log_residency", classmethod(lambda cls, label, ram: None)
    )
    if linux_kernel is not None:
        monkeypatch.setattr(Run, "_linux_kernel", classmethod(linux_kernel))
    if construct is not None:
        monkeypatch.setattr(qemu_guest_run.plugins, "construct_plugin", construct)
    host = FakeHost(context, {"guest_plugin": "linux.pslist.PsList"})
    return Run.run(host, "linux", lambda ctx: vm)


def test_a_guest_without_a_linux_banner_raises_a_symbols_error(monkeypatch):
    with pytest.raises(qemu_guest_run.GuestSymbolsError) as raised:
        run_with_symbols(monkeypatch, [])
    message = str(raised.value)
    assert message.startswith("PsList cannot run on the guest (unsatisfied: ")
    assert message.endswith(
        "Guest banner: no banner; its symbol table must be in --guest-symbol-dirs."
    )


def test_a_guest_whose_symbols_cannot_be_built_raises_a_symbols_error(monkeypatch):
    def fail(cls, host, context, layer, banners, dirs):
        raise kernel_btf.BtfError("no vmlinux BTF in the image")

    with pytest.raises(qemu_guest_run.GuestSymbolsError) as raised:
        run_with_symbols(monkeypatch, ["Linux version 1"], fail)
    assert str(raised.value) == (
        "No symbol table for the guest kernel (Linux version 1) in --guest-symbol-dirs, and none could be built from "
        "its memory: no vmlinux BTF in the image"
    )
    assert isinstance(raised.value.__cause__, kernel_btf.BtfError)


def test_a_plugin_that_the_symbols_do_not_satisfy_raises_a_symbols_error(monkeypatch):
    def unsatisfied(copy, magics, plugin, config_path, callback, open_method):
        raise exceptions.UnsatisfiedException(["plugins.Run.PsList.kernel"])

    with pytest.raises(qemu_guest_run.GuestSymbolsError) as raised:
        run_with_symbols(
            monkeypatch,
            ["Linux version 1"],
            lambda cls, host, ctx, layer, banners, dirs: ([layer], "table", True),
            unsatisfied,
        )
    assert str(raised.value) == (
        "PsList cannot run on the guest (unsatisfied: plugins.Run.PsList.kernel). Guest banner: Linux version 1; "
        "the symbol table built from its memory did not satisfy the plugin."
    )


def test_a_table_that_was_not_built_is_not_reported_as_built(monkeypatch):
    """A table from --guest-symbol-dirs or the identifier cache that does not fit the plugin says so by what it is."""

    def unsatisfied(copy, magics, plugin, config_path, callback, open_method):
        raise exceptions.UnsatisfiedException(["plugins.Run.PsList.kernel"])

    with pytest.raises(qemu_guest_run.GuestSymbolsError) as raised:
        run_with_symbols(
            monkeypatch,
            ["Linux version 1"],
            lambda cls, host, ctx, layer, banners, dirs: ([layer], "table", False),
            unsatisfied,
        )
    message = str(raised.value)
    assert "built from its memory" not in message
    assert message.endswith("its symbol table must be in --guest-symbol-dirs.")


# --- symbol tables ----------------------------------------------------------------------------------

BANNER = "Linux version 6.18.58-0-virt (buildozer@build) #1-Alpine SMP"


def isf(banner, compressed=False):
    data = json.dumps(
        {
            "metadata": {},
            "symbols": {
                "linux_banner": {
                    "constant_data": base64.b64encode(
                        banner.encode() + b"\n\x00"
                    ).decode()
                }
            },
        }
    ).encode()
    return lzma.compress(data) if compressed else data


def test_guest_symbol_dirs_are_searched_by_banner(tmp_path):
    (tmp_path / "linux").mkdir()
    (tmp_path / "linux" / "other.json").write_bytes(isf("Linux version 5.4 (x) #1"))
    (tmp_path / "linux" / "alpine.json.xz").write_bytes(isf(BANNER, True))
    (tmp_path / "linux" / "broken.json").write_bytes(b"not json")
    url, banner = Run.isf_in_dirs([str(tmp_path)], ["Linux version 0 #0", BANNER])
    assert url.endswith("/linux/alpine.json.xz") and banner == BANNER
    assert Run.isf_in_dirs([str(tmp_path)], ["Linux version 9 #9"]) is None
    assert Run.isf_in_dirs([str(tmp_path / "missing")], [BANNER]) is None


def test_known_isf_comes_from_the_identifier_cache_without_writing_it(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(constants, "CACHE_PATH", str(tmp_path))
    # no cache: nothing found, and the lookup does not create one
    assert Run.isf_known([BANNER]) is None
    assert not os.listdir(tmp_path)
    path = tmp_path / constants.IDENTIFIERS_FILENAME
    cache = symbol_cache.SqliteCache(str(path))
    cursor = cache._database.cursor()
    for identifier, location in (
        (BANNER.encode() + b"\n\x00", "file:///guest.json"),
        (b"Linux version 5.4 (x) #1", "https://remote/other.json"),
    ):
        cursor.execute(
            "INSERT INTO cache (location, identifier, operating_system, local) VALUES (?, ?, 'linux', 0)",
            (location, identifier),
        )
    cache._database.commit()
    before = path.read_bytes()
    assert Run.isf_known(["Linux version 0 #0", BANNER]) == (
        "file:///guest.json",
        BANNER,
    )
    assert Run.isf_known(["Linux version 5.4 (x) #1"])[0] == "https://remote/other.json"
    assert Run.isf_known(["Linux version 1.0 #1"]) is None
    assert path.read_bytes() == before


def test_windows_guest_isf_is_found_in_the_directories_as_volatility_finds_one(
    tmp_path,
):
    pdb = tmp_path / "windows" / "ntkrnlmp.pdb"
    pdb.mkdir(parents=True)
    (pdb / "ABCDEF-1.json.xz").write_bytes(b"x")
    assert Run._windows_isf_in_dirs(
        [str(tmp_path)], "ntkrnlmp.pdb\x00", "abcdef", 1
    ).endswith("/windows/ntkrnlmp.pdb/ABCDEF-1.json.xz")
    assert (
        Run._windows_isf_in_dirs([str(tmp_path)], "ntkrnlmp.pdb", "ABCDEF", 2) is None
    )
    assert (
        Run._windows_isf_in_dirs([str(tmp_path / "x")], "ntkrnlmp.pdb", "ABCDEF", 1)
        is None
    )


def test_guest_plugin_returns_its_own_table_so_rows_stream(monkeypatch):
    """`run` returns what the guest plugin's `run` returns: its columns and types, its rows as they are made."""
    produced = []

    def rows():
        for number in range(3):
            produced.append(number)
            yield 0, (number, "x")

    grid = renderers.TreeGrid([("N", int), ("S", str)], rows())

    def construct(copy, magics, plugin, config_path, callback, open_method):
        return SimpleNamespace(run=lambda: grid)

    result = run_with_symbols(
        monkeypatch,
        ["Linux version 1"],
        lambda cls, host, ctx, layer, banners, dirs: ([layer], "table", True),
        construct,
    )
    assert result is grid
    assert [(c.name, c.type) for c in result.columns] == [("N", int), ("S", str)]
    assert produced == []  # nothing is produced before the renderer asks
    seen = []
    result.populate(lambda node, accumulator: seen.append(tuple(node.values)))
    assert produced == [0, 1, 2]
    assert seen == [(0, "x"), (1, "x"), (2, "x")]


def test_plugin_os_is_the_package_under_plugins_or_the_first_part_of_a_short_name():
    def plugin(module):
        return SimpleNamespace(__module__=module)

    assert Run.plugin_os(plugin("volatility3.plugins.linux.pslist")) == "linux"
    assert Run.plugin_os(plugin("volatility3.plugins.windows.pslist")) == "windows"
    # a module with fewer than three parts used to raise IndexError
    assert Run.plugin_os(plugin("linux")) == "linux"
    assert Run.plugin_os(plugin("pslist")) == "pslist"
    assert Run.plugin_os(plugin("volatility3.plugins")) == "volatility3"
    assert Run.plugin_os(plugin("volatility3.plugins.mac")) != "linux"
    assert Run.plugin_os(qemu_guest.Run) in ("linux", "volatility3")


@pytest.mark.parametrize(
    "config, warned",
    [
        ({"kvm": True, "ram_at": 0x7F0000000000}, True),
        ({"kvm": True}, False),
        ({"ram_at": 0x7F0000000000}, False),
    ],
)
def test_ram_at_is_ignored_with_kvm_and_says_so(monkeypatch, caplog, config, warned):
    monkeypatch.setattr(
        qemu_guest.kvm.VMs, "find_vms", classmethod(lambda cls, *args: [])
    )
    monkeypatch.setattr(
        qemu_guest.qemu.VMs, "find_vms", classmethod(lambda cls, *a: [])
    )
    monkeypatch.setattr(
        qemu_guest_run.QemuGuestRun,
        "only_guest",
        classmethod(lambda cls, vms, option, encrypted: None),
    )
    plugin = SimpleNamespace(config={"kernel": "kernel", **config})
    with caplog.at_level("WARNING", logger=qemu_guest.vollog.name):
        qemu_guest.Run._guest(plugin, None)
    assert (
        any("--ram-at is ignored with --kvm" in r.message for r in caplog.records)
        is warned
    )


def test_each_layer_caches_its_own_short_reads_and_can_be_freed():
    first_context, path = guest_layer(standard_entries())
    second_context, _ = guest_layer(standard_entries())
    first = QemuGuestLayer(first_context, path, "first")
    second = QemuGuestLayer(second_context, path, "second")
    assert first.read(0, 8) == bytes([0x10]) * 8
    assert first.read(0, 8) == bytes([0x10]) * 8
    assert first._small_reader().cache_info().hits == 1
    assert first._small_reader().cache_info().currsize == 1
    assert second._small_reader().cache_info().currsize == 0
    assert first._small_reader().cache_info().maxsize == qemu_guest_run.SMALL_CACHE
    # a read of a lost page raises and leaves nothing in the cache
    with pytest.raises(exceptions.InvalidAddressException):
        first.read(2 * PAGE, 8)
    assert first._small_reader().cache_info().currsize == 1
    assert second.read(0, 8) == bytes([0x10]) * 8
    assert second._small_reader().cache_info().misses == 1  # not answered from first's
    reference = weakref.ref(first)
    del first
    gc.collect()
    assert reference() is None
    assert second.read(0, 8) == bytes([0x10]) * 8


def test_a_deep_copy_of_a_layer_has_a_cache_of_its_own():
    """`context.clone()` deep-copies the layers: the copy must not read through the original, which can be freed."""
    context, path = guest_layer(standard_entries())
    layer = QemuGuestLayer(context, path, "guest")
    assert layer.read(0, 8) == bytes([0x10]) * 8
    clone = copy.deepcopy(layer)
    assert clone._small_cache is None
    assert clone._small_reader() is not layer._small_reader()
    assert clone._small_reader().cache_info().currsize == 0
    reference = weakref.ref(layer)
    del layer
    gc.collect()
    assert reference() is None
    assert clone.read(0, 8) == bytes([0x10]) * 8
    assert clone.read(3 * PAGE, 8) == bytes([0x13]) * 8
    with pytest.raises(exceptions.InvalidAddressException):
        clone.read(2 * PAGE, 8)


def test_linux_kernel_says_whether_it_built_the_table(monkeypatch, tmp_path):
    """The flag is true only for a table built from the guest's memory, not for one from a directory or the cache."""
    symbol_space = SimpleNamespace(
        free_table_name=lambda prefix: prefix, append=lambda table: None
    )
    context = SimpleNamespace(symbol_space=symbol_space)
    monkeypatch.setattr(
        Run,
        "_load_table",
        classmethod(lambda cls, ctx, name, url, validate, mask: None),
    )
    monkeypatch.setattr(
        Run,
        "_kernel_layer",
        classmethod(
            lambda cls, ctx, table, name, layer, banner, host: SimpleNamespace(
                name="Intel", address_mask=0
            )
        ),
    )
    host = SimpleNamespace(config={})

    def kernel(dirs, known):
        monkeypatch.setattr(Run, "isf_in_dirs", classmethod(lambda cls, d, b: dirs))
        monkeypatch.setattr(Run, "isf_known", classmethod(lambda cls, b: known))
        return Run._linux_kernel(host, context, "memory", [BANNER], ["/symbols"])

    assert kernel(("file:///dir.json", BANNER), None) == (
        ["Intel", "memory"],
        "QemuGuestKernel",
        False,
    )
    # no table in the directories, one that Volatility knows
    assert kernel(None, ("file:///known.json", BANNER))[2] is False
    built = tmp_path / "built.json.xz"
    built.write_bytes(b"x")
    monkeypatch.setattr(
        Run,
        "_build_symbols",
        classmethod(lambda cls, h, c, layer: (str(built), BANNER)),
    )
    assert kernel(None, None)[2] is True
    assert not built.exists()  # removed once loaded


def test_windows_kernel_table_comes_from_the_guest_symbol_dirs_before_the_cache(
    tmp_path, monkeypatch
):
    """The PDB automagic of the copy takes the ISF from `--guest-symbol-dirs` without the identifier cache and
    without a download; a kernel that is not there goes the usual way."""
    pdb = tmp_path / "windows" / "ntkrnlmp.pdb"
    pdb.mkdir(parents=True)
    (pdb / "ABCDEF-1.json.xz").write_bytes(b"x")
    context = contexts.Context()
    requirement = requirements.SymbolTableRequirement(name="nt_symbols")
    scanner = SimpleNamespace(
        _symbol_requirements=[
            ("plugins.Run.PsList.kernel.symbol_table_name", requirement)
        ]
    )
    usual = []
    scanner.recurse_symbol_fulfiller = lambda ctx, kernel, callback=None: usual.append(
        kernel
    )
    constructed = []

    def construct(self, ctx, path):
        constructed.append(
            (self.name, path, ctx.config[path + ".symbol_table_name.isf_url"])
        )

    monkeypatch.setattr(requirements.SymbolTableRequirement, "construct", construct)
    qemu_guest_run.QemuGuestRun._use_guest_symbol_dirs(scanner, [str(tmp_path)])
    found = (None, 0, {"pdb_name": "ntkrnlmp.pdb", "GUID": "ABCDEF", "age": 1})
    scanner.recurse_symbol_fulfiller(context, found)
    assert usual == []
    name, path, url = constructed[0]
    assert (name, path) == ("symbol_table_name", "plugins.Run.PsList.kernel")
    assert url.endswith("/windows/ntkrnlmp.pdb/ABCDEF-1.json.xz")
    assert (
        context.config["plugins.Run.PsList.kernel.symbol_table_name.class"]
        == "volatility3.framework.symbols.windows.WindowsKernelIntermedSymbols"
    )
    other = (None, 0, {"pdb_name": "ntkrnlmp.pdb", "GUID": "123456", "age": 1})
    scanner.recurse_symbol_fulfiller(context, other)
    assert usual == [other]
