# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for the map-BTF attribute parser.

Pins ``inspect._parse_btf_map_attrs`` and ``inspect._btf_string``
against synthetic blobs: one well-formed map-attribute blob
resolving to its exact bounds, plus truncated and malformed blobs
covering every ``MBPF402`` branch. The happy path through a real
object stays with the build suites; these tests own the error
branches no genuine build ever produces.

Deterministic on any host: only the standard library plus pytest's
plain function collection.

Runnable under pytest (``python3 -m pytest tests/unit`` from the
repository root) or directly (``python3
tests/unit/test_inspect_btf.py``).
"""

import os
import struct
import sys

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"
    ),
)

from mojobpf import inspect as inspect_module  # noqa: E402

PATH = "synthetic.bpf.o"

_STRINGS = (
    b"\x00.maps\x00mojobpf_map0\x00type\x00key_size\x00"
    b"value_size\x00max_entries\x00"
)
_OFF = {
    "empty": 0,
    "maps": 1,
    "var": 7,
    "type": 20,
    "key_size": 25,
    "value_size": 34,
    "max_entries": 45,
}


def _record(name_off, kind, vlen, size_or_type):
    return struct.pack(
        "<III", name_off, (kind << 24) | vlen, size_or_type
    )


def _blob_and_offsets(member_type=3, member_target=2,
                      var_target=10, entry_type=11,
                      members=None, first_kind=1):
    """Build a minimal map-attribute BTF blob; return (blob, offsets).

    The type section holds one INT, four ARRAY/PTR bound pairs,
    one 4-member STRUCT, one VAR, and one DATASEC ``.maps``; the
    offsets dict gives the patch points the malformed cases use.
    """
    if members is None:
        members = (
            ("type", 3, 0),
            ("key_size", 5, 32),
            ("value_size", 7, 64),
            ("max_entries", 9, 96),
        )
    types = bytearray()
    offsets = {}
    types += _record(_OFF["empty"], first_kind, 0, 4)
    types += struct.pack("<I", 0x01000020)
    next_id = 2
    for nelems in (2, 4, 8, 1):
        types += _record(_OFF["empty"], 3, 0, 0)
        types += struct.pack("<III", 1, 1, nelems)
        array_id = next_id
        next_id += 1
        types += _record(_OFF["empty"], 2, 0, member_target
                         if array_id == 2 else array_id)
        next_id += 1
    offsets["struct"] = len(types)
    types += _record(_OFF["empty"], 4, len(members), 0)
    offsets["members"] = len(types)
    for name, type_id, bit_off in members:
        if name == "type":
            type_id = member_type
        types += struct.pack(
            "<III", _OFF[name], type_id, bit_off
        )
    offsets["var_target"] = len(types) + 8
    types += _record(_OFF["var"], 14, 0, var_target)
    types += struct.pack("<I", 0)
    offsets["datasec_entry"] = len(types) + 12
    types += _record(_OFF["maps"], 15, 1, 32)
    types += struct.pack("<III", entry_type, 0, 32)
    header = struct.pack(
        "<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(types),
        len(types), len(_STRINGS),
    )
    return bytes(header) + bytes(types) + _STRINGS, offsets


def _valid_blob():
    blob, _offsets = _blob_and_offsets()
    return blob


def _patch(blob, offset, data):
    return blob[:offset] + data + blob[offset + len(data):]


def test_valid_blob_resolves_map_attributes():
    attrs = inspect_module._parse_btf_map_attrs(_valid_blob(), PATH)
    assert attrs == {
        "mojobpf_map0": {
            "type": 2,
            "key_size": 4,
            "value_size": 8,
            "max_entries": 1,
        }
    }, attrs


def test_truncated_header_refused():
    for blob in (_valid_blob()[:10], _valid_blob()[:23]):
        try:
            inspect_module._parse_btf_map_attrs(blob, PATH)
        except inspect_module._ElfError as exc:
            assert exc.code == "MBPF402", exc.code
            assert exc.explanation == "truncated BTF header", (
                exc.explanation
            )
        else:
            raise AssertionError("truncated header parsed")


def test_bad_header_refused():
    blob = _valid_blob()
    cases = [
        ("bad magic", _patch(blob, 0, b"\x00\x00")),
        ("bad version", _patch(blob, 2, b"\x02")),
        ("bad header length", _patch(blob, 4, struct.pack("<I", 16))),
    ]
    for _label, bad in cases:
        try:
            inspect_module._parse_btf_map_attrs(bad, PATH)
        except inspect_module._ElfError as exc:
            assert exc.code == "MBPF402", exc.code
            assert exc.explanation == "bad BTF header", exc.explanation
        else:
            raise AssertionError("bad header parsed")


def test_unexpected_layout_refused():
    blob = _valid_blob()
    bad = _patch(blob, 8, struct.pack("<I", 4))
    try:
        inspect_module._parse_btf_map_attrs(bad, PATH)
    except inspect_module._ElfError as exc:
        assert exc.code == "MBPF402", exc.code
        assert exc.explanation == "unexpected BTF layout", (
            exc.explanation
        )
    else:
        raise AssertionError("shifted type section parsed")


def test_size_mismatch_refused():
    blob = _valid_blob() + b"\x00"
    try:
        inspect_module._parse_btf_map_attrs(blob, PATH)
    except inspect_module._ElfError as exc:
        assert exc.code == "MBPF402", exc.code
        assert exc.explanation == "BTF size mismatch", exc.explanation
    else:
        raise AssertionError("oversized blob parsed")


def test_truncated_record_refused():
    blob, _offsets = _blob_and_offsets()
    _header, rest = blob[:24], blob[24:]
    _magic, _ver, _flags, _hlen, _toff, type_len, _soff, _slen = (
        struct.unpack("<HBBIIIII", _header)
    )
    cut = 20
    types = rest[:cut]
    strings = rest[type_len:]
    header = struct.pack(
        "<HBBIIIII", 0xEB9F, 1, 0, 24, 0, cut, cut,
        len(strings),
    )
    try:
        inspect_module._parse_btf_map_attrs(
            header + types + strings, PATH
        )
    except inspect_module._ElfError as exc:
        assert exc.code == "MBPF402", exc.code
        assert exc.explanation == "truncated BTF record", (
            exc.explanation
        )
    else:
        raise AssertionError("truncated record parsed")


def test_string_offset_past_end_refused():
    blob, offsets = _blob_and_offsets()
    bad = _patch(
        blob, 24 + offsets["var_target"] - 8,
        struct.pack("<I", 0xFFFF),
    )
    try:
        inspect_module._parse_btf_map_attrs(bad, PATH)
    except inspect_module._ElfError as exc:
        assert exc.code == "MBPF402", exc.code
        assert exc.explanation == "BTF string offset past table end", (
            exc.explanation
        )
    else:
        raise AssertionError("wild string offset parsed")


def test_unexpected_kind_refused():
    blob, _offsets = _blob_and_offsets(first_kind=9)
    try:
        inspect_module._parse_btf_map_attrs(blob, PATH)
    except inspect_module._ElfError as exc:
        assert exc.code == "MBPF402", exc.code
        assert exc.explanation == "unexpected BTF kind 9", (
            exc.explanation
        )
    else:
        raise AssertionError("unknown kind parsed")


def test_extended_kinds_read_five_bits():
    # BTF kinds are five bits wide: 16-19 (FLOAT, DECL_TAG,
    # TYPE_TAG, ENUM64) must read as themselves and refuse as
    # unsupported, never misread through a four-bit mask (17
    # would silently parse as INT, 18 as PTR).
    for kind in (16, 17, 18, 19):
        blob, _offsets = _blob_and_offsets(first_kind=kind)
        try:
            inspect_module._parse_btf_map_attrs(blob, PATH)
        except inspect_module._ElfError as exc:
            assert exc.code == "MBPF402", exc.code
            assert exc.explanation == (
                "unexpected BTF kind %d" % kind
            ), exc.explanation
        else:
            raise AssertionError(
                "kind %d parsed instead of refusing" % kind
            )


def test_type_id_out_of_range_refused():
    blob, _offsets = _blob_and_offsets(member_type=99)
    try:
        inspect_module._parse_btf_map_attrs(blob, PATH)
    except inspect_module._ElfError as exc:
        assert exc.code == "MBPF402", exc.code
        assert exc.explanation == "BTF type id 99 out of range", (
            exc.explanation
        )
    else:
        raise AssertionError("wild type id parsed")


def test_maps_entry_not_var_refused():
    blob, _offsets = _blob_and_offsets(entry_type=10)
    try:
        inspect_module._parse_btf_map_attrs(blob, PATH)
    except inspect_module._ElfError as exc:
        assert exc.code == "MBPF402", exc.code
        assert exc.explanation == "BTF .maps entry is not a VAR", (
            exc.explanation
        )
    else:
        raise AssertionError("non-VAR .maps entry parsed")


def test_map_var_without_struct_refused():
    blob, _offsets = _blob_and_offsets(var_target=1)
    try:
        inspect_module._parse_btf_map_attrs(blob, PATH)
    except inspect_module._ElfError as exc:
        assert exc.code == "MBPF402", exc.code
        assert exc.explanation == "BTF map VAR has no STRUCT", (
            exc.explanation
        )
    else:
        raise AssertionError("VAR without STRUCT parsed")


def test_map_member_not_pointer_refused():
    blob, _offsets = _blob_and_offsets(member_type=1)
    try:
        inspect_module._parse_btf_map_attrs(blob, PATH)
    except inspect_module._ElfError as exc:
        assert exc.code == "MBPF402", exc.code
        assert exc.explanation == (
            "BTF map member 'type' is not a pointer"
        ), exc.explanation
    else:
        raise AssertionError("non-pointer member parsed")


def test_map_member_without_array_bound_refused():
    blob, _offsets = _blob_and_offsets(member_target=1)
    try:
        inspect_module._parse_btf_map_attrs(blob, PATH)
    except inspect_module._ElfError as exc:
        assert exc.code == "MBPF402", exc.code
        assert exc.explanation == (
            "BTF map member 'type' has no ARRAY bound"
        ), exc.explanation
    else:
        raise AssertionError("unbounded member parsed")


def test_map_var_lacking_field_refused():
    members = (
        ("type", 3, 0),
        ("key_size", 5, 32),
        ("value_size", 7, 64),
    )
    blob, _offsets = _blob_and_offsets(members=members)
    try:
        inspect_module._parse_btf_map_attrs(blob, PATH)
    except inspect_module._ElfError as exc:
        assert exc.code == "MBPF402", exc.code
        assert exc.explanation == (
            "BTF map VAR 'mojobpf_map0' lacks 'max_entries'"
        ), exc.explanation
    else:
        raise AssertionError("incomplete VAR parsed")


def test_btf_string_errors():
    try:
        inspect_module._btf_string(b"ab\x00", 5, PATH)
    except inspect_module._ElfError as exc:
        assert exc.code == "MBPF402", exc.code
        assert exc.explanation == "BTF string offset past table end"
    else:
        raise AssertionError("wild string offset parsed")
    try:
        inspect_module._btf_string(b"abc", 0, PATH)
    except inspect_module._ElfError as exc:
        assert exc.code == "MBPF402", exc.code
        assert exc.explanation == "unterminated BTF string", (
            exc.explanation
        )
    else:
        raise AssertionError("unterminated string parsed")
    try:
        inspect_module._btf_string(b"\xff\x00", 0, PATH)
    except inspect_module._ElfError as exc:
        assert exc.code == "MBPF402", exc.code
        assert exc.explanation == "non-ASCII BTF string", (
            exc.explanation
        )
    else:
        raise AssertionError("non-ASCII string parsed")
    assert inspect_module._btf_string(b"ok\x00", 0, PATH) == "ok"


def test_object_map_specs_missing_and_garbage_files():
    try:
        inspect_module.object_map_specs(
            os.path.join("no-such-dir", "missing.bpf.o")
        )
    except inspect_module.InspectionError as exc:
        assert exc.diagnostic.code == "MBPF401", exc.diagnostic
    else:
        raise AssertionError("missing file parsed")
    import tempfile

    handle, path = tempfile.mkstemp(suffix=".bpf.o")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(b"not an object file")
        try:
            inspect_module.object_map_specs(path)
        except inspect_module.InspectionError as exc:
            assert exc.diagnostic.code == "MBPF401", exc.diagnostic
        else:
            raise AssertionError("garbage file parsed")
    finally:
        os.remove(path)


def _direct_names():
    return sorted(
        name
        for name in globals()
        if name.startswith("test_") and callable(globals()[name])
    )


def _direct_run():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    for name in _direct_names():
        try:
            globals()[name]()
        except Exception:
            failures += 1
            print("FAIL %s" % name)
            import traceback

            traceback.print_exc()
        else:
            print("ok %s" % name)
    print("%d tests, %d failures" % (len(_direct_names()), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_direct_run())
