"""Unit tests for the QEMU / KVM plugins: one test per fixed defect, with small fakes instead of images."""

import logging
import struct
from types import SimpleNamespace
from unittest import mock

import pytest
from volatility3.framework import contexts, exceptions, interfaces, renderers
from volatility3.framework.layers import physical
from volatility3.framework.symbols import native
from volatility3.plugins import kernel_btf, qemu_common
from volatility3.plugins.linux import kvm, qemu
from volatility3.plugins.windows import qemu as wqemu

PAGE = qemu_common.PAGE
SWAP_KEY = interfaces.configuration.path_join(
    "automagic", "WinSwapLayers", "single_swap_locations"
)


def component(requirement):
    """The class a VersionRequirement names, and the version it asks for (no public accessor)."""
    return requirement._component, requirement._version


# --- linux.qemu.LinuxRamBlock -----------------------------------------------------------------------


class EmptyLayer:
    """A process layer that translates nothing."""

    name = "process"

    def mapping(self, offset, length, ignore_errors=False):
        return iter(())

    def read(self, offset, length, pad=False):
        return bytes(length)


def test_anonymous_block_never_asks_for_a_page_cache():
    """No file behind the mapping: no fallback, so a page that is not translated costs no `vm_file` read."""

    class Vma:
        vm_start, vm_end, vm_pgoff = 0x10000000, 0x10000000 + 4 * PAGE, 0
        reads = 0

        @property
        def vm_file(self):
            Vma.reads += 1
            return None

    context = SimpleNamespace(layers={"process": EmptyLayer()})
    block = qemu.LinuxRamBlock(context, "process", Vma(), "anonymous")
    Vma.reads = 0
    assert block.read(0, 4 * PAGE) == bytes(4 * PAGE)
    assert block.resident_pages() == 0
    assert Vma.reads == 0


def test_page_cache_index_skips_foreign_pages_and_builds_pages_on_lookup():
    """The index holds page offsets; a page of another address space is skipped as in `inode.get_contents`."""

    def page(index, mapping, offset):
        return SimpleNamespace(
            has_member=lambda name: False,
            index=index,
            mapping=mapping,
            vol=SimpleNamespace(
                offset=offset, type_name="host!page", layer_name="kernel-layer"
            ),
        )

    pages = [page(0, "m", 0x100), page(1, "other", 0x200), page(2, "m", 0x300)]
    inode = SimpleNamespace(
        i_mapping="m", get_pages=mock.Mock(return_value=iter(pages))
    )
    vma = SimpleNamespace(
        vm_start=0x10000000,
        vm_end=0x10000000 + 3 * PAGE,
        vm_pgoff=0,
        vm_file=SimpleNamespace(get_inode=lambda: inode),
    )
    context = SimpleNamespace(
        layers={"process": EmptyLayer()},
        object=mock.Mock(
            side_effect=lambda type_name, layer_name, offset: SimpleNamespace(
                type_name=type_name, layer_name=layer_name, offset=offset
            )
        ),
    )
    block = qemu.LinuxRamBlock(context, "process", vma, "memfd")
    assert block.cached_page(0).offset == 0x100
    assert block.cached_page(PAGE) is None
    assert block.cached_page(2 * PAGE).offset == 0x300
    assert block.cached_page(2 * PAGE).layer_name == "kernel-layer"
    inode.get_pages.assert_called_once_with()


def failing_page_cache(error):
    """A block whose inode yields one good page and then raises `error`, as `inode.get_pages` does."""

    def pages():
        yield SimpleNamespace(
            has_member=lambda name: False,
            index=0,
            mapping="m",
            vol=SimpleNamespace(
                offset=0x100, type_name="host!page", layer_name="kernel-layer"
            ),
        )
        raise error

    inode = SimpleNamespace(i_mapping="m", get_pages=pages)
    vma = SimpleNamespace(
        vm_start=0x10000000,
        vm_end=0x10000000 + 3 * PAGE,
        vm_pgoff=0,
        vm_file=SimpleNamespace(get_inode=lambda: inode),
    )
    context = SimpleNamespace(
        layers={"process": EmptyLayer()},
        object=lambda type_name, layer_name, offset: SimpleNamespace(offset=offset),
    )
    return qemu.LinuxRamBlock(context, "process", vma, "/memfd:ram (deleted)")


@pytest.mark.parametrize(
    "error",
    [
        exceptions.LinuxPageCacheException("Invalid cached page at 0x200, aborting"),
        exceptions.InvalidAddressException("kernel-layer", 0x200, "unreadable"),
    ],
)
def test_unwalkable_page_cache_is_kept_as_far_as_read_and_warned_once(error, caplog):
    """One invalid cached page must not abort the plugin: the pages before it stay, one warning names the block."""
    block = failing_page_cache(error)
    with caplog.at_level(logging.WARNING):
        block.load_page_cache()
        block.load_page_cache()
        # the lookups that follow neither raise nor walk the cache again
        assert block.cached_page(0).offset == 0x100
        assert block.cached_page(PAGE) is None
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "0x10000000" in warnings[0] and "/memfd:ram (deleted)" in warnings[0]
    assert "1 pages read" in warnings[0]


def test_slot_block_loads_the_page_cache_of_each_vma_without_raising():
    """The memslot's own `load_page_cache` goes through its VMAs, so it gets the same handling."""
    vma = failing_page_cache(exceptions.LinuxPageCacheException("bad page"))
    slot = kvm.Slot(0, 0, 0, 3, 0x10000000, 0, False)
    block = kvm.SlotBlock(EmptyLayer(), slot, [vma])
    assert block.has_fallback
    block.load_page_cache()
    assert vma.cached_page(0).offset == 0x100


def test_block_without_a_fallback_says_so():
    layer = EmptyLayer()
    assert not qemu_common.RamBlock(layer, 0, PAGE, "x").has_fallback
    assert qemu_common.RamBlock(layer, 0, PAGE, "x", lambda off: None).has_fallback


# --- linux.qemu.LinuxRamBlock: large folios and hugetlbfs in the page cache --------------------------

STRUCT_PAGE = 64
HUGE = 2 << 20  # 2 MiB huge pages: order 9
PG_HEAD = 6


def folio_block(
    entries,
    layout="folio_order",
    pgoff=0,
    pages=4096,
    magic=qemu.HUGETLBFS_MAGIC,
    flags=int,
):
    """A file-backed block whose page cache holds `entries`, (file index, order or None, address of the head page):
    `layout` is where the kernel keeps the order (see `LinuxRamBlock._folio_order`). The file is on the file system
    with the superblock `magic`; `flags` makes a flags word of an int (`int`, or `struct_flags` for Linux 6.18)."""
    orders = {address: order for _i, order, address in entries if order is not None}

    def page(index, order, address):
        members = {"compound_order"} if layout == "compound_order" else set()
        return SimpleNamespace(
            has_member=lambda name: name in members,
            index=index,
            mapping="m",
            # the head flag is set only on the head of a compound page
            flags=flags(1 << PG_HEAD if order is not None else 0),
            pageflags_enum={"PG_head": PG_HEAD},
            vol=SimpleNamespace(
                offset=address, type_name="host!page", layer_name="kernel-layer"
            ),
        )

    def make(type_name, layer_name, offset):
        if type_name == "host!folio":
            order = orders[offset]
            members = {
                "folio_order": {"_folio_order", "_flags_1"},
                # 6.9: the order is the low byte of _flags_1 (the other bits are page flags)
                "flags_1": {"_flags_1"},
            }[layout]
            return SimpleNamespace(
                has_member=lambda name: name in members,
                _folio_order=order,
                _flags_1=flags(0x5500 | order),
            )
        if offset - STRUCT_PAGE in orders and layout == "compound_order":
            return SimpleNamespace(compound_order=orders[offset - STRUCT_PAGE])
        return SimpleNamespace(
            offset=offset, layer_name=layer_name, type_name=type_name
        )

    inode = SimpleNamespace(
        i_mapping="m",
        i_sb=SimpleNamespace(s_magic=magic),
        get_pages=lambda: iter([page(i, o, a) for i, o, a in entries]),
    )
    vma = SimpleNamespace(
        vm_start=0x10000000,
        vm_end=0x10000000 + pages * PAGE,
        vm_pgoff=pgoff,
        vm_file=SimpleNamespace(get_inode=lambda: inode),
    )
    context = SimpleNamespace(
        layers={"process": EmptyLayer()},
        object=make,
        symbol_space=SimpleNamespace(
            has_type=lambda name: layout != "compound_order" and name == "host!folio",
            get_type=lambda name: SimpleNamespace(size=STRUCT_PAGE),
        ),
    )
    return qemu.LinuxRamBlock(context, "process", vma, "/dev/hugepages/x (deleted)")


def struct_flags(value):
    """A flags word as Linux 6.18 has it: a `memdesc_flags_t` struct whose member `f` holds the bits (not an int)."""
    return SimpleNamespace(f=value)


@pytest.fixture
def kernel_symbols(monkeypatch):
    """The kernel of the host: the set of symbols it has can be changed by the test."""
    symbols = set()
    module = SimpleNamespace(has_symbol=lambda name: name in symbols)
    monkeypatch.setattr(
        qemu.linux.LinuxUtilities,
        "get_module_from_volobj_type",
        classmethod(lambda cls, context, volobj: module),
    )
    return symbols


@pytest.mark.parametrize("flags", [int, struct_flags], ids=["int", "memdesc_flags_t"])
@pytest.mark.parametrize("layout", ["folio_order", "flags_1", "compound_order"])
def test_folio_order_is_read_where_the_kernel_keeps_it(layout, flags):
    block = folio_block(
        [(0, 9, 0x1000000), (512, 2, 0x2000000), (600, None, 0x3000000)],
        layout,
        flags=flags,
    )
    pages = [
        SimpleNamespace(
            has_member=lambda name: (
                layout == "compound_order" and name == "compound_order"
            ),
            flags=flags(1 << PG_HEAD if order is not None else 0),
            pageflags_enum={"PG_head": PG_HEAD},
            vol=SimpleNamespace(offset=a, type_name="host!page", layer_name="k"),
        )
        for _i, order, a in [
            (0, 9, 0x1000000),
            (512, 2, 0x2000000),
            (600, None, 0x3000000),
        ]
    ]
    assert [block._folio_order(p) for p in pages] == [9, 2, 0]


def test_folio_order_unknown_layout_is_one_page_and_logged_at_debug(caplog):
    block = folio_block([(0, 9, 0x1000000)])
    block._context.symbol_space.has_type = lambda name: False
    page = SimpleNamespace(
        has_member=lambda name: False,
        flags=1 << PG_HEAD,
        pageflags_enum={"PG_head": PG_HEAD},
        vol=SimpleNamespace(offset=0x1000000, type_name="host!page", layer_name="k"),
    )
    with caplog.at_level(logging.DEBUG, logger=qemu.vollog.name):
        assert block._folio_order(page) == 0
    assert "no folio order" in caplog.text
    # without the page flags enumeration (a kernel without PG_head) there is no compound page to find either
    page.pageflags_enum = {}
    assert folio_block([(0, 9, 0x1000000)])._folio_order(page) == 0


def test_a_flags_struct_that_has_no_bits_is_one_page_not_a_crash(caplog):
    """A `flags` that is neither an integer nor a struct with `f` raises TypeError in `int()`; it is not fatal."""
    block = folio_block([(0, 9, 0x1000000)])
    page = SimpleNamespace(
        has_member=lambda name: False,
        flags=SimpleNamespace(other=1),
        pageflags_enum={"PG_head": PG_HEAD},
        vol=SimpleNamespace(offset=0x1000000, type_name="host!page", layer_name="k"),
    )
    with caplog.at_level(logging.DEBUG, logger=qemu.vollog.name):
        assert block._folio_order(page) == 0
    assert "folio order" in caplog.text


def test_page_cache_of_a_6_18_host_with_struct_flags_is_read(kernel_symbols):
    block = folio_block(
        [(0, 9, 0x1000000), (512, 9, 0x2000000), (600, None, 0x3000000)],
        flags=struct_flags,
    )
    assert block.cached_page(HUGE + 3 * PAGE).offset == 0x2000000 + 3 * STRUCT_PAGE
    assert block.cached_page(600 * PAGE).offset == 0x3000000


def test_hugetlb_index_in_huge_pages_before_linux_6_7_is_scaled(kernel_symbols):
    """Linux 6.1 stores a 2 MiB hugetlbfs page at its index in huge pages (0, 1, 2), not in base pages."""
    kernel_symbols.add("hugetlb_basepage_index")
    block = folio_block([(0, 9, 0x1000000), (1, 9, 0x2000000), (2, 9, 0x3000000)])
    cases = [
        (0, 0x1000000),
        (HUGE - PAGE, 0x1000000 + 511 * STRUCT_PAGE),
        (HUGE, 0x2000000),
        (HUGE + 5 * PAGE, 0x2000000 + 5 * STRUCT_PAGE),
        (2 * HUGE + 511 * PAGE, 0x3000000 + 511 * STRUCT_PAGE),
        (3 * HUGE, None),
    ]
    for offset, address in cases:
        page = block.cached_page(offset)
        assert (page.offset if page else None) == address


def test_hugetlb_index_is_scaled_on_a_kernel_with_the_old_function_name(
    kernel_symbols,
):
    """Before Linux 5.13 (Ubuntu 20.04's 5.4, RHEL 8's 4.18) the function is `__basepage_index`."""
    kernel_symbols.add("__basepage_index")
    block = folio_block([(0, 9, 0x1000000), (1, 9, 0x2000000)])
    assert block.cached_page(HUGE).offset == 0x2000000
    assert block.cached_page(HUGE + 5 * PAGE).offset == 0x2000000 + 5 * STRUCT_PAGE


def test_hugetlb_index_of_a_sparse_file_before_linux_6_7_is_scaled(kernel_symbols):
    """Huge pages 0 and 512 of a sparse file: both indexes are multiples of 512, but they still count huge pages."""
    kernel_symbols.add("hugetlb_basepage_index")
    block = folio_block([(0, 9, 0x1000000), (512, 9, 0x2000000)], pages=512 * 513)
    assert block.cached_page(0).offset == 0x1000000
    assert block.cached_page(512 * HUGE).offset == 0x2000000
    assert block.cached_page(HUGE) is None


def test_only_hugetlbfs_has_its_index_in_huge_pages(kernel_symbols):
    """A tmpfs or memfd file with large folios keeps base-page indexes on a kernel that has the symbol too."""
    kernel_symbols.add("hugetlb_basepage_index")
    block = folio_block(
        [(0, 9, 0x1000000), (512, 9, 0x2000000)], magic=qemu.TMPFS_MAGIC
    )
    assert block.cached_page(HUGE).offset == 0x2000000
    assert block.cached_page(512 * HUGE) is None


def test_hugetlb_index_in_base_pages_from_linux_6_7_is_not_scaled(kernel_symbols):
    """Linux 6.7 and later (no `hugetlb_basepage_index`): the head's index is in base pages, the entry is found at its
    head."""
    block = folio_block([(0, 9, 0x1000000), (512, 9, 0x2000000), (1024, 9, 0x3000000)])
    assert block.cached_page(0).offset == 0x1000000
    assert block.cached_page(HUGE).offset == 0x2000000
    assert block.cached_page(HUGE + 3 * PAGE).offset == 0x2000000 + 3 * STRUCT_PAGE
    assert block.cached_page(2 * HUGE).offset == 0x3000000
    assert block.cached_page(HUGE * 7) is None


def test_large_shmem_folio_fills_its_pages_from_the_head():
    """A multi-index entry is only found at its head: a 4-page folio at index 8 holds pages 8 to 11."""
    block = folio_block(
        [(0, None, 0x1000000), (8, 2, 0x2000000), (12, None, 0x3000000)]
    )
    assert block.cached_page(0).offset == 0x1000000
    assert [block.cached_page(i * PAGE) for i in (7, 12 + 1)] == [None, None]
    for i in range(8, 12):
        assert block.cached_page(i * PAGE).offset == 0x2000000 + (i - 8) * STRUCT_PAGE
    assert block.cached_page(12 * PAGE).offset == 0x3000000


def test_large_folio_lookup_honours_the_vma_offset():
    """The index is the file's: a mapping that starts at page 512 of the file reads index 512 at offset 0."""
    block = folio_block([(512, 9, 0x2000000)], pgoff=512)
    assert block.cached_page(0).offset == 0x2000000
    assert block.cached_page(100 * PAGE).offset == 0x2000000 + 100 * STRUCT_PAGE


def test_a_page_without_the_head_flag_is_never_asked_for_an_order():
    """The first tail page's fields are another page's: an ordinary page is one page whatever follows it."""
    block = folio_block([(0, None, 0x1000000), (1, None, 0x1000040)])
    block._context.object = mock.Mock(
        side_effect=lambda type_name, layer_name, offset: SimpleNamespace(offset=offset)
    )
    assert block.cached_page(PAGE).offset == 0x1000040
    block._context.object.assert_called_once()


def test_an_empty_entry_of_a_file_mapping_is_explained_by_what_the_file_can_hold():
    """The residency reasons say what `Run` does: hugetlbfs never has more, a disk file may."""
    hugetlbfs = folio_block([(0, None, 0x1000000)], magic=qemu.HUGETLBFS_MAGIC)
    assert hugetlbfs._reason(0, 12) == "never present"
    assert hugetlbfs.uncached_reason is None
    ext4 = folio_block([(0, None, 0x1000000)], magic=0xEF53)
    assert ext4._reason(0, 12) == qemu.NOT_CACHED
    # an entry that says something else keeps its own reason
    assert ext4._reason((3 << 59) | 0x1000, 12) == "swapped out"
    anonymous = qemu.LinuxRamBlock(
        SimpleNamespace(layers={"process": EmptyLayer()}),
        "process",
        SimpleNamespace(vm_start=0, vm_end=PAGE, vm_pgoff=0, vm_file=None),
        "anonymous",
    )
    assert anonymous._reason(0, 12) == "never present"


def test_inode_address_identifies_the_file_behind_a_mapping():
    def block(file):
        vma = SimpleNamespace(
            vm_start=0x10000000, vm_end=0x10000000 + 4 * PAGE, vm_pgoff=0, vm_file=file
        )
        context = SimpleNamespace(layers={"process": EmptyLayer()})
        return qemu.LinuxRamBlock(context, "process", vma, "x")

    inode = SimpleNamespace(vol=SimpleNamespace(offset=0xFFFF000012345000))
    shared = SimpleNamespace(get_inode=lambda: inode)
    assert (
        block(shared).inode_address == block(shared).inode_address == 0xFFFF000012345000
    )
    assert block(None).inode_address is None
    broken = SimpleNamespace(
        get_inode=mock.Mock(side_effect=exceptions.InvalidAddressException("k", 1))
    )
    assert block(broken).inode_address is None


# --- linux.qemu: processes that only share the guest RAM -----------------------------------------------------


def found_row(pid, signal, inodes):
    blocks = [SimpleNamespace(inode_address=i) for i in inodes]
    guest = SimpleNamespace(ram=SimpleNamespace(blocks=blocks))
    return qemu._Found(SimpleNamespace(pid=pid), guest, "info", signal)


def test_a_process_that_only_shares_the_guest_ram_is_not_a_vmm_of_its_own(caplog):
    qemu_row = found_row(100, 2, [0xAAA])
    virtiofsd = found_row(200, 0, [0xAAA])
    other = found_row(300, 2, [0xBBB])
    anonymous = found_row(400, 1, [None])
    rows = [virtiofsd, qemu_row, other, anonymous]  # the weaker one may come first
    with caplog.at_level(logging.WARNING, logger=qemu.vollog.name):
        kept = qemu.VMs._without_shared_ram(rows)
    assert kept == [qemu_row, other, anonymous]
    assert [r.getMessage() for r in caplog.records] == [
        "PID 200 shares the guest RAM of PID 100 (vhost-user backend or virtiofsd?): not listed as a VMM of its own"
    ]


def test_equal_signals_on_one_file_keep_both_rows(caplog):
    rows = [found_row(1, 2, [0xAAA]), found_row(2, 2, [0xAAA])]
    with caplog.at_level(logging.WARNING, logger=qemu.vollog.name):
        assert qemu.VMs._without_shared_ram(rows) == rows
    assert not caplog.records


def test_rows_without_a_guest_or_a_file_are_kept():
    rows = [
        qemu._Found(SimpleNamespace(pid=1), None, "info", 2),
        found_row(2, 0, []),
        found_row(3, 2, [0xAAA]),
    ]
    assert qemu.VMs._without_shared_ram(rows) == rows


def test_the_weak_process_is_dropped_once_for_each_of_its_shared_files(caplog):
    rows = [found_row(100, 2, [0xAAA, 0xBBB]), found_row(200, 0, [0xAAA, 0xBBB])]
    with caplog.at_level(logging.WARNING, logger=qemu.vollog.name):
        assert qemu.VMs._without_shared_ram(rows) == rows[:1]
    assert len(caplog.records) == 1


# --- windows.qemu: the paging file table ------------------------------------------------------------


def test_paging_file_table_is_read_with_the_kernels_pointer_size():
    """On a 32-bit kernel the table holds 4-byte pointers; the compression store is found at its number."""
    pointers = [0] * wqemu.MAX_PAGING_FILES
    pointers[0], pointers[1], pointers[3] = 0x100, 0x200, 0x300
    table = 0x40
    buffer = bytearray(0x400)
    struct.pack_into(f"<{len(pointers)}I", buffer, table, *pointers)
    context = contexts.Context()
    context.symbol_space.append(native.x86NativeTable)
    context.layers.add_layer(physical.BufferDataLayer(context, "m", "m", bytes(buffer)))
    module = context.module("native", "m", 0)
    store = {0x300}

    def paging_file(offset):
        return SimpleNamespace(
            has_member=lambda name: True,
            VirtualStorePagefile=int(offset in store),
        )

    def get_symbol(name):
        if name == "MmPagingFile":
            return SimpleNamespace(address=table)
        raise exceptions.SymbolError(name, "native", "no such symbol")

    def obj(object_type, **kwargs):
        if object_type == "_MMPAGING_FILE":
            return paging_file(kwargs["offset"])
        return module.object(object_type=object_type, **kwargs)

    kernel = SimpleNamespace(
        offset=0, object=obj, get_type=module.get_type, get_symbol=get_symbol
    )
    pte = object.__new__(wqemu.WindowsPte)
    pte.kernel = kernel
    assert pte.virtual_store == {3}


def _pte(low_shift=12, store=frozenset({1})):
    pte = object.__new__(wqemu.WindowsPte)
    pte.low_shift, pte.low_width, pte.high_shift = low_shift, 4, 32
    pte.__dict__["virtual_store"] = set(store)
    pte._swap_warned = False
    return pte


def test_software_pte_reasons_use_the_kernels_page_file_low():
    """Windows 10 and later: the number is bits 12-15, bit 1 only is a reserved slot, bit 2 a written one."""
    pte = _pte()
    slot = 0x1234 << 32
    # PageFileAllocated, paging file 0 (x1b: 8,224 of these, all read from pagefile.sys)
    assert pte.reason(slot | 0x4, 12) == "pagefile 0"
    assert pte.reason(slot | 0x4 | 2 << 12, 12) == "pagefile 2"
    # PageFileReserved only: a reserved slot whose content may be stale (x1b: 41,968 of 75,804 are zero pages, 33,836 match the file)
    stale = "(slot reserved, content may be stale)"
    assert pte.reason(slot | 0x2, 12) == f"pagefile 0 {stale}"
    reserved_2 = slot | 0x2 | 2 << 12
    assert pte.reason(reserved_2, 12) == f"pagefile 2 {stale}"
    # PageFileReserved and PageFileAllocated, SwizzleBit: a written page
    assert pte.reason(slot | 0x6 | 0x10, 12) == "pagefile 0"
    # bits 1-4 holding 1 (the old number position) must not give paging file 1, the compression store on x1b
    assert pte.reason(slot | 0x4 | 1 << 12, 12) == "compressed store"
    assert pte.reason(0, 12) == "demand-zero"
    assert pte.reason(1 << 10 | 1 << 32, 12) == "prototype"


def test_software_pte_number_in_bits_1_to_4_without_swizzle_bit():
    """A kernel with PageFileLow at bits 1-4: bit 1 belongs to the number, not to a flag."""
    pte = _pte(low_shift=1, store=())
    assert pte.reason(1 << 32 | 1 << 1, 12) == "pagefile 1"
    assert pte.reason(1 << 32 | 2 << 1, 12) == "pagefile 2"


def _layer(count):
    config = {"swap_layers.number_of_elements": count} if count else {}
    return SimpleNamespace(config=config)


def test_swap_layer_warning_is_one_and_names_the_compression_store(caplog):
    pte = _pte()
    with caplog.at_level(logging.WARNING, logger=wqemu.vollog.name):
        pte.check_swap_layers(_layer(1))
        pte.check_swap_layers(_layer(3))
    messages = [record.getMessage() for record in caplog.records]
    assert len(messages) == 1
    assert "volatility3 PR #2080" in messages[0]
    assert "wrong PTE bits" in messages[0]
    assert "compression store is paging file 1" in messages[0]


def test_swap_layer_warning_needs_page_files_and_a_moved_page_file_low(caplog):
    with caplog.at_level(logging.WARNING, logger=wqemu.vollog.name):
        _pte().check_swap_layers(_layer(0))
        _pte(low_shift=1).check_swap_layers(_layer(2))
        _pte(store=()).check_swap_layers(_layer(1))
    messages = [record.getMessage() for record in caplog.records]
    # only the kernel without a compression store warns: the others gave no page files or have PageFileLow at bit 1
    assert len(messages) == 1
    assert "compression store" not in messages[0]


# --- linux.kvm ---------------------------------------------------------------------------------------


def test_registers_of_an_unknown_vendor_do_not_need_vcpu_vmx():
    """The fallback vendor `kvm` is neither AMD nor Intel: the generic registers, no exit code, no exception."""
    host = SimpleNamespace(
        vendor="kvm",
        enumerators={},
        object=mock.Mock(side_effect=exceptions.SymbolError("vcpu_vmx", "kvm", "x")),
    )
    cpu = SimpleNamespace(
        arch=SimpleNamespace(regs_avail=0, efer=0x500, regs=[0] * 20),
        vol=SimpleNamespace(offset=0),
    )
    vm = object.__new__(kvm.Vm)
    vm.host = host
    regs, exit_code, source, stale = vm._registers(cpu)
    assert (regs, exit_code, source, stale) == ({"efer": 0x500}, None, "cached", [])


@pytest.mark.parametrize(
    "error",
    [kernel_btf.BtfError("no type vcpu_vmx"), AttributeError("exit_reason")],
)
def test_intel_exit_reason_is_none_when_vcpu_vmx_cannot_be_read(error):
    """`Host.object` raises `BtfError` for a type the KVM BTF lacks, a missing member raises AttributeError."""
    host = SimpleNamespace(vendor="kvm_intel", object=mock.Mock(side_effect=error))
    cpu = SimpleNamespace(vol=SimpleNamespace(offset=0))
    vm = object.__new__(kvm.Vm)
    vm.host = host
    assert vm._vmx_exit_reason(cpu) is None


def test_memory_slots_before_5_17_are_built_at_their_offsets():
    """`memslots[]` is a flexible array member (no element in BTF): indexing it must not be needed."""

    class NoElements:
        vol = SimpleNamespace(offset=0x1000)

        def __getitem__(self, index):
            raise IndexError(index)

    ms = SimpleNamespace(
        has_member=lambda name: name != "gfn_tree",
        used_slots=3,
        memslots=NoElements(),
    )
    host = SimpleNamespace(
        context=SimpleNamespace(
            symbol_space=SimpleNamespace(
                get_type=lambda name: SimpleNamespace(size=0x60)
            )
        ),
        type_name=lambda name: name,
        object=lambda name, offset: (name, offset),
    )
    vm = object.__new__(kvm.Vm)
    vm.host = host
    assert list(vm._memory_slots(ms)) == [
        ("kvm_memory_slot", 0x1000),
        ("kvm_memory_slot", 0x1060),
        ("kvm_memory_slot", 0x10C0),
    ]


def _vcpu_vm(label, vendor="kvm_amd"):
    """A VM with one vCPU whose `_registers` returns AMD-like values, to see whether they are used."""
    vm = object.__new__(kvm.Vm)
    vm.host = SimpleNamespace(vendor=vendor)
    vm.addr, vm.userspace_pid, vm.task = 0x1000, 9, None
    vm.confidential = lambda: label
    vm.kvm = SimpleNamespace(
        has_member=lambda name: name == "vcpu_array",
        vcpu_array=None,
    )
    vm._registers = mock.Mock(
        return_value=({"rip": 0xFFFF0000, "cpl": 3}, 0x7B, "VMCB", [])
    )
    cpu = SimpleNamespace(pid=0, mode=1, vcpu_id=0, vol=SimpleNamespace(offset=0))
    vm.host.object = lambda name, addr: cpu
    vm.host.context = vm.host.kernel_name = None
    return vm


@pytest.fixture
def one_vcpu(monkeypatch):
    monkeypatch.setattr(
        kvm.linux,
        "XArray",
        lambda *a: SimpleNamespace(get_entries=lambda xarray: [0x2000]),
    )


@pytest.mark.parametrize("label", ["SEV-ES", "SEV-SNP", "TDX"])
def test_vcpus_of_a_confidential_vm_have_no_registers(one_vcpu, label):
    """The registers are in the encrypted VMSA / TD state: no VMCB value is shown as if it were exact."""
    vm = _vcpu_vm(label)
    (values,) = kvm.VCPUs.rows(object.__new__(kvm.VCPUs), vm)
    vm._registers.assert_not_called()
    assert values["Source"] == "encrypted"
    row = qemu_common.QemuCommon.row(kvm.VCPUs.COLUMNS, values)
    shown = dict(zip((name for name, _ in kvm.VCPUs.COLUMNS), row))
    for column in ("RIP", "RSP", "CR3", "CR0", "CR4", "EFER", "CPL", "CS", "Exit code"):
        assert isinstance(shown[column], renderers.NotAvailableValue), column
    assert isinstance(shown["Exit reason"], renderers.NotAvailableValue)
    assert shown["vCPU"] == 0


@pytest.mark.parametrize("label", [None, "SEV", "guest_memfd"])
def test_vcpus_of_a_plain_vm_keep_their_registers(one_vcpu, label):
    """Plain SEV encrypts only the RAM: its VMCB stays readable."""
    vm = _vcpu_vm(label)
    (values,) = kvm.VCPUs.rows(object.__new__(kvm.VCPUs), vm)
    assert values["Source"] == "VMCB"
    assert values["RIP"] == 0xFFFF0000 and values["CPL"] == 3


class RowsTable(kvm._Table):
    COLUMNS = [("PID", int)]
    config = {"kernel": "kernel"}
    context = None

    def rows(self, vm):
        if vm.unreadable:
            raise exceptions.InvalidAddressException("layer", 0x1000, "unreadable")
        yield {"PID": vm.pid}


def test_unreadable_vm_does_not_end_the_table(monkeypatch, caplog):
    """A VM whose structures cannot be read is reported and left out; the next VM still gets its rows."""
    vms = [
        SimpleNamespace(addr=0xABC, pid=1, unreadable=True),
        SimpleNamespace(addr=0xDEF, pid=2, unreadable=False),
    ]
    monkeypatch.setattr(RowsTable, "find_vms", classmethod(lambda cls, *a: vms))
    table = object.__new__(RowsTable)
    with caplog.at_level(logging.WARNING, logger=kvm.vollog.name):
        assert list(table._generator()) == [(0, [2])]
    assert any("0xabc" in record.getMessage() for record in caplog.records)


def test_confidential_vm_is_not_scanned_for_a_banner(monkeypatch):
    """A confidential guest's RAM is not readable: its banner is not scanned for."""

    class Vms(kvm.VMs):
        config = {}
        context = None

    vm = SimpleNamespace(
        addr=0x1000,
        pid=7,
        slots=[],
        task=None,
        in_list=True,
        fd_holders=[],
        online_vcpus=1,
        smram_pages=lambda: 0,
        guest=lambda: SimpleNamespace(ram=SimpleNamespace(resident_percent=1.0)),
        confidential=lambda: "SEV",
    )
    banner = mock.Mock(return_value="Linux version 6")
    monkeypatch.setattr(qemu_common.QemuCommon, "guest_banner", banner)
    monkeypatch.setattr(qemu_common.QemuCommon, "log_residency", mock.Mock())
    (values,) = Vms.rows(object.__new__(Vms), vm)
    banner.assert_not_called()
    assert values["Encrypted"] == "SEV"
    assert isinstance(
        values.get("Guest banner", renderers.NotAvailableValue()),
        renderers.NotAvailableValue,
    )


def test_kvm_version_requirements_cover_what_is_used():
    """kvm calls `log_residency` (QemuCommon 1.5.0) and `linux_pte_reason` (linux.qemu 1.2.0)."""
    required = {r.name: r for r in kvm.VMs.get_requirements()}
    assert component(required["qemu_common"])[1] >= (1, 5, 0)
    assert component(required["qemu"])[1] >= (1, 2, 0)


def test_kvm_guest_takes_the_address_space():
    """`Vm.guest(as_id)` is what the dump and the table rows use: address space 0 by default, 1 for SMM."""
    vm = object.__new__(kvm.Vm)
    vm.userspace_pid, vm.task = 55, None
    seen = []

    def ram(as_id=0):
        seen.append(as_id)
        return ("ram", ["segment"]) if as_id != 2 else None

    vm.ram = ram
    guest = vm.guest()
    assert (guest.pid, guest.ram, guest.segments, guest.machine) == (
        55,
        "ram",
        ["segment"],
        "KVM memslots",
    )
    assert vm.guest(1).ram == "ram" and vm.guest(2) is None
    assert seen == [0, 1, 2]


def test_kvm_dump_writes_the_guest_of_the_address_space(monkeypatch):
    dumped = []
    monkeypatch.setattr(
        qemu_common.QemuCommon,
        "dump_elf",
        classmethod(
            lambda cls, open_file, name, guest: dumped.append((name, guest)) or name
        ),
    )

    class Vms(kvm.VMs):
        config = {}
        context = None

    vm = SimpleNamespace(
        addr=0xABC, pid=7, guest=lambda as_id=0: None if as_id == 3 else f"guest{as_id}"
    )
    table = object.__new__(Vms)
    table._file_handler = None
    assert table._dump(vm, 0) == "kvm.7.0xabc.elf"
    assert table._dump(vm, 1) == "kvm.7.0xabc.smm.elf"
    assert isinstance(table._dump(vm, 3), renderers.NotAvailableValue)
    assert dumped == [("kvm.7.0xabc.elf", "guest0"), ("kvm.7.0xabc.smm.elf", "guest1")]


def test_kvm_process_layer_gets_a_free_name_and_is_made_once():
    layers = {"kvm_abc": object()}  # the name `kvm_abc` is taken

    class Layers(dict):
        def free_layer_name(self, prefix):
            count = 0
            while f"{prefix}{count or ''}" in self:
                count += 1
            return f"{prefix}{count or ''}"

        def add_layer(self, layer):
            self[layer.name] = layer

    class Parent:
        config = {"memory_layer": "memory"}

        def __init__(self, context=None, config_path=None, name=None):
            self.name = name

        def build_configuration(self):
            return {}

        def translate(self, address):
            return 0x5000, "memory"

    context = SimpleNamespace(
        layers=Layers(layers), config=SimpleNamespace(splice=mock.Mock())
    )
    host = SimpleNamespace(
        context=context,
        layer=Parent(),
        kernel=SimpleNamespace(object=lambda *a, **k: SimpleNamespace(pgd=1)),
    )
    vm = object.__new__(kvm.Vm)
    vm.host, vm.addr, vm.mm, vm._layer_name, vm._layer_made = (
        host,
        0xABC,
        0x1000,
        None,
        False,
    )
    name = vm.process_layer()
    assert name == "kvm_abc1" and name in context.layers
    assert vm.process_layer() == name and len(context.layers) == 2
    context.config.splice.assert_called_once()


def test_kvm_process_layer_that_cannot_be_made_is_none_and_not_retried():
    host = SimpleNamespace(
        context=SimpleNamespace(layers=SimpleNamespace(free_layer_name=lambda p: p)),
        layer=SimpleNamespace(
            translate=mock.Mock(side_effect=exceptions.InvalidAddressException("k", 1))
        ),
        kernel=SimpleNamespace(object=lambda *a, **k: SimpleNamespace(pgd=1)),
    )
    vm = object.__new__(kvm.Vm)
    vm.host, vm.addr, vm.mm, vm._layer_name, vm._layer_made = host, 1, 2, None, False
    assert vm.process_layer() is None and vm.process_layer() is None
    host.layer.translate.assert_called_once()


def test_kvm_plugins_have_a_version_of_their_own():
    """The tables share `_Table`, not its version: each plugin is bumped alone."""
    for plugin in (kvm.VMs, kvm.Slots, kvm.VCPUs):
        assert "_version" in vars(plugin), plugin
    assert "_version" not in vars(kvm._Table)


def test_kvm_table_finds_its_vms_without_naming_a_subclass(monkeypatch):
    """`_generator` asks `self.find_vms`, so a table that is not `VMs` (or a subclass of it) works."""
    assert all(
        issubclass(plugin, kvm._Table)
        and plugin.find_vms.__func__ is kvm._Table.find_vms.__func__
        for plugin in (kvm.VMs, kvm.Slots, kvm.VCPUs)
    )


def test_qemu_plugins_require_the_command_line_component():
    """linux.qemu and windows.qemu call QemuCmdline themselves, so they require it as well as QemuCommon 3."""
    for plugin in (qemu.VMs, wqemu.VMs):
        required = {r.name: r for r in plugin.get_requirements()}
        assert component(required["qemu_common"]) == (qemu_common.QemuCommon, (3, 0, 0))
        assert component(required["qemu_cmdline"]) == (
            qemu_common.qemu_cmdline.QemuCmdline,
            (1, 0, 0),
        )
