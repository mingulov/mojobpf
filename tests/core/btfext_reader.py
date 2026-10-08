# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Independent `.BTF` / `.BTF.ext` relocation reader.

Parses a BPF relocatable's ``.BTF`` type section and ``.BTF.ext``
relocation records from scratch (ELF64 little-endian only) and
resolves every CO-RE relocation to its section, instruction
offset, type name, kind, accessor chain, member path, and local
byte offset/size. It shares no code with the product BTF parser
(``src/mojobpf/inspect.py``) or with any other test helper: the
module imports only the standard library, and
``tests/core/test_core_object.py`` asserts that isolation by
scanning this file's imports and by checking ``sys.modules``
after importing it. Cross-check legs live beside it: the suites
also compare its output against ``bpftool btf dump`` (type IDs,
member offsets, sizes) and against the loader's own
``LIBBPF_DEBUG=1`` relocation transcript.

Usage: ``python3 btfext_reader.py obj.o`` prints a stable report;
importing exposes :func:`read_relocations`.

Any malformed input raises :class:`ReaderError`. Nothing here
ever passes silently.
"""

import struct
import sys

BTF_MAGIC = 0xEB9F
BTF_EXT_MAGIC = 0xEB9F

KIND_INT = 1
KIND_PTR = 2
KIND_ARRAY = 3
KIND_STRUCT = 4
KIND_UNION = 5
KIND_ENUM = 6
KIND_FWD = 7
KIND_TYPEDEF = 8
KIND_VOLATILE = 9
KIND_CONST = 10
KIND_RESTRICT = 11
KIND_FUNC = 12
KIND_FUNC_PROTO = 13
KIND_VAR = 14
KIND_DATASEC = 15
KIND_FLOAT = 16
KIND_DECL_TAG = 17
KIND_TYPE_TAG = 18
KIND_ENUM64 = 19

RELO_KINDS = {
    0: "FIELD_BYTE_OFFSET",
    1: "FIELD_BYTE_SIZE",
    2: "FIELD_EXISTS",
    3: "FIELD_SIGNED",
    4: "FIELD_LSHIFT_U64",
    5: "FIELD_RSHIFT_U64",
    6: "TYPE_ID_LOCAL",
    7: "TYPE_ID_TARGET",
    8: "TYPE_EXISTS",
    9: "TYPE_SIZE",
    10: "ENUM_VALUE_EXISTS",
    11: "ENUM_VALUE",
}


class ReaderError(Exception):
    """Malformed or unsupported input bytes."""


def _u16(data, offset):
    try:
        return struct.unpack_from("<H", data, offset)[0]
    except struct.error:
        raise ReaderError("truncated u16 at %d" % offset)


def _u32(data, offset):
    try:
        return struct.unpack_from("<I", data, offset)[0]
    except struct.error:
        raise ReaderError("truncated u32 at %d" % offset)


def _u64(data, offset):
    try:
        return struct.unpack_from("<Q", data, offset)[0]
    except struct.error:
        raise ReaderError("truncated u64 at %d" % offset)


def read_sections(data):
    """Map ELF64LE section names to their bytes."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ReaderError("not an ELF file")
    if data[4] != 2 or data[5] != 1 or data[6] != 1:
        raise ReaderError("not a 64-bit little-endian ELF")
    machine = _u16(data, 18)
    if machine != 247:
        raise ReaderError("not an EM_BPF object (machine %d)" % machine)
    shoff = _u64(data, 40)
    shentsize = _u16(data, 58)
    shnum = _u16(data, 60)
    shstrndx = _u16(data, 62)
    if shentsize != 64 or shnum == 0 or shstrndx >= shnum:
        raise ReaderError("bad section header table")
    headers = []
    for index in range(shnum):
        base = shoff + index * 64
        if base + 64 > len(data):
            raise ReaderError("section header %d truncated" % index)
        name, _type, _flags, _addr, offset, size = struct.unpack_from(
            "<IIQQQQ", data, base
        )
        headers.append((name, offset, size))
    str_off, str_size = headers[shstrndx][1], headers[shstrndx][2]
    sections = {}
    for name_off, offset, size in headers:
        if str_off + name_off >= len(data):
            raise ReaderError("section name truncated")
        try:
            end = data.index(b"\0", str_off + name_off)
        except ValueError:
            raise ReaderError("section name has no terminator")
        name = data[str_off + name_off : end].decode("ascii")
        if offset + size > len(data):
            raise ReaderError("section %r truncated" % name)
        sections[name] = bytes(data[offset : offset + size])
    return sections


class Btf:
    """Parsed `.BTF`: types plus the string table."""

    def __init__(self, blob):
        if len(blob) < 24:
            raise ReaderError(".BTF shorter than its header")
        magic, version, _flags, hdr_len = struct.unpack_from(
            "<HBBI", blob, 0
        )
        if magic != BTF_MAGIC or version != 1:
            raise ReaderError("bad .BTF magic/version")
        if hdr_len < 24 or hdr_len > len(blob):
            raise ReaderError("bad .BTF header length")
        _type_off, type_len, str_off, str_len = struct.unpack_from(
            "<IIII", blob, 8
        )
        types_end = hdr_len + str_off
        if hdr_len + str_off + str_len > len(blob):
            raise ReaderError(".BTF strings overrun the section")
        self.strings = blob[hdr_len + str_off : types_end + str_len]
        self.types = {}
        pos = hdr_len + _type_off
        type_id = 1
        while pos < hdr_len + _type_off + type_len:
            if pos + 12 > len(blob):
                raise ReaderError(".BTF type %d truncated" % type_id)
            name_off, info, size_or_type = struct.unpack_from(
                "<III", blob, pos
            )
            kind = (info >> 24) & 0x1F
            vlen = info & 0xFFFF
            pos += 12
            record = {
                "id": type_id,
                "name": self.string(name_off),
                "kind": kind,
                "vlen": vlen,
                "size_or_type": size_or_type,
                "members": [],
                "params": [],
                "values": [],
            }
            if kind in (KIND_STRUCT, KIND_UNION):
                for _ in range(vlen):
                    if pos + 12 > len(blob):
                        raise ReaderError("member truncated")
                    m_name, m_type, m_off = struct.unpack_from(
                        "<III", blob, pos
                    )
                    pos += 12
                    record["members"].append(
                        {
                            "name": self.string(m_name),
                            "type": m_type,
                            "bits_offset": m_off,
                        }
                    )
            elif kind == KIND_ARRAY:
                if pos + 12 > len(blob):
                    raise ReaderError("array dims truncated")
                record["array"] = struct.unpack_from("<III", blob, pos)
                pos += 12
            elif kind == KIND_ENUM:
                for _ in range(vlen):
                    if pos + 8 > len(blob):
                        raise ReaderError("enum value truncated")
                    v_name, v_val = struct.unpack_from("<Ii", blob, pos)
                    pos += 8
                    record["values"].append(
                        (self.string(v_name), v_val)
                    )
            elif kind == KIND_ENUM64:
                for _ in range(vlen):
                    if pos + 12 > len(blob):
                        raise ReaderError("enum64 value truncated")
                    v_name, v_lo, v_hi = struct.unpack_from(
                        "<III", blob, pos
                    )
                    pos += 12
                    record["values"].append(
                        (self.string(v_name), (v_hi << 32) | v_lo)
                    )
            elif kind == KIND_VAR:
                if pos + 4 > len(blob):
                    raise ReaderError("var linkage truncated")
                record["linkage"] = _u32(blob, pos)
                pos += 4
            elif kind == KIND_FUNC_PROTO:
                for _ in range(vlen):
                    if pos + 8 > len(blob):
                        raise ReaderError("proto param truncated")
                    p_name, p_type = struct.unpack_from("<II", blob, pos)
                    pos += 8
                    record["params"].append(
                        (self.string(p_name), p_type)
                    )
            elif kind == KIND_DATASEC:
                for _ in range(vlen):
                    if pos + 12 > len(blob):
                        raise ReaderError("datasec var truncated")
                    v_type, v_off, v_size = struct.unpack_from(
                        "<III", blob, pos
                    )
                    pos += 12
                    record["members"].append(
                        {
                            "type": v_type,
                            "offset": v_off,
                            "size": v_size,
                        }
                    )
            elif kind in (KIND_INT, KIND_FLOAT):
                if pos + 4 > len(blob):
                    raise ReaderError("int data truncated")
                record["data"] = _u32(blob, pos)
                pos += 4
            elif kind in (
                KIND_PTR,
                KIND_FWD,
                KIND_TYPEDEF,
                KIND_VOLATILE,
                KIND_CONST,
                KIND_RESTRICT,
                KIND_FUNC,
                KIND_DECL_TAG,
                KIND_TYPE_TAG,
            ):
                pass
            else:
                raise ReaderError(
                    "unsupported BTF kind %d at type %d"
                    % (kind, type_id)
                )
            self.types[type_id] = record
            type_id += 1

    def string(self, offset):
        if offset >= len(self.strings):
            raise ReaderError("string offset %d out of range" % offset)
        try:
            end = self.strings.index(b"\0", offset)
        except ValueError:
            raise ReaderError(
                "string at %d has no terminator" % offset
            )
        return self.strings[offset:end].decode("utf-8")


def _resolve_member(btf, type_id, accessors):
    """Resolve a single-level accessor chain to its member facts.

    The observed single-level form is ``0:<index>`` (libbpf's root
    designator plus the member index); anything else is reported
    with its raw chain and left unresolved.
    """
    record = btf.types.get(type_id)
    if record is None:
        raise ReaderError("relocation against missing type %d" % type_id)
    if record["kind"] not in (KIND_STRUCT, KIND_UNION):
        return {"type": record["name"], "member": None}
    if len(accessors) != 2 or accessors[0] != 0:
        return {
            "type": record["name"],
            "member": None,
            "chain": accessors,
        }
    index = accessors[1]
    if index < 0 or index >= len(record["members"]):
        raise ReaderError(
            "member index %d out of range for %s"
            % (index, record["name"])
        )
    member = record["members"][index]
    target = btf.types.get(member["type"], {})
    size = None
    if target.get("kind") == KIND_INT:
        size = (target.get("data", 0) & 0xFF) // 8 or None
        if size is None:
            size = target.get("size_or_type")
    elif target.get("kind") in (KIND_STRUCT, KIND_UNION, KIND_ENUM):
        size = target.get("size_or_type")
    return {
        "type": record["name"],
        "member": member["name"],
        "member_type": target.get("name", ""),
        "local_byte_offset": member["bits_offset"] // 8,
        "local_size": size,
    }


def read_relocations(data):
    """Resolve every `.BTF.ext` CO-RE relocation in the object."""
    sections = read_sections(data)
    if ".BTF" not in sections:
        raise ReaderError("object has no .BTF section")
    if ".BTF.ext" not in sections:
        raise ReaderError("object has no .BTF.ext section")
    btf = Btf(sections[".BTF"])
    ext = sections[".BTF.ext"]
    if len(ext) < 32:
        raise ReaderError(".BTF.ext shorter than its header")
    magic, version, _flags, hdr_len = struct.unpack_from(
        "<HBBI", ext, 0
    )
    if magic != BTF_EXT_MAGIC or version != 1 or hdr_len != 32:
        raise ReaderError("bad .BTF.ext header")
    _foff, _flen, _loff, _llen, coff, clen = struct.unpack_from(
        "<IIIIII", ext, 8
    )
    if hdr_len + coff + clen > len(ext):
        raise ReaderError(".BTF.ext relocations overrun the section")
    blob = ext[hdr_len + coff : hdr_len + coff + clen]
    if len(blob) < 4:
        raise ReaderError(".BTF.ext relocation blob truncated")
    record_size = _u32(blob, 0)
    if record_size != 16:
        raise ReaderError(
            "unsupported core_relo record size %d" % record_size
        )
    pos = 4
    relocations = []
    while pos < len(blob):
        if pos + 8 > len(blob):
            raise ReaderError(".BTF.ext info section truncated")
        sec_name_off, num_info = struct.unpack_from(
            "<II", blob, pos
        )
        pos += 8
        section = btf.string(sec_name_off)
        for _ in range(num_info):
            if pos + 16 > len(blob):
                raise ReaderError(".BTF.ext record truncated")
            insn_off, type_id, acc_off, kind = struct.unpack_from(
                "<IIII", blob, pos
            )
            pos += 16
            access = btf.string(acc_off)
            try:
                accessors = [
                    int(part) for part in access.split(":")
                ]
            except ValueError:
                raise ReaderError(
                    "bad accessor string %r" % access
                )
            facts = _resolve_member(btf, type_id, accessors)
            facts.update(
                {
                    "section": section,
                    "insn_off": insn_off,
                    "type_id": type_id,
                    "kind": kind,
                    "kind_name": RELO_KINDS.get(
                        kind, "UNKNOWN(%d)" % kind
                    ),
                    "access": access,
                }
            )
            relocations.append(facts)
    return {
        "type_count": len(btf.types),
        "func_len": _flen,
        "line_len": _llen,
        "relocations": relocations,
    }


def report(path):
    """Print the stable relocation report for an object file."""
    with open(path, "rb") as handle:
        result = read_relocations(handle.read())
    lines = [
        "types %d" % result["type_count"],
        "func_info_len %d" % result["func_len"],
        "line_info_len %d" % result["line_len"],
        "relocations %d" % len(result["relocations"]),
    ]
    for index, relo in enumerate(result["relocations"]):
        lines.append(
            "relo %d: section=%s insn_off=%d type_id=%d "
            "type=%s kind=%d(%s) access=%s member=%s "
            "local_off=%s local_size=%s"
            % (
                index,
                relo["section"],
                relo["insn_off"],
                relo["type_id"],
                relo.get("type"),
                relo["kind"],
                relo["kind_name"],
                relo["access"],
                relo.get("member"),
                relo.get("local_byte_offset"),
                relo.get("local_size"),
            )
        )
    return "\n".join(lines) + "\n"


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: btfext_reader.py obj.o\n")
        return 2
    try:
        sys.stdout.write(report(argv[1]))
    except ReaderError as exc:
        sys.stderr.write("btfext_reader: %s\n" % exc)
        return 1
    except OSError as exc:
        sys.stderr.write("btfext_reader: %s\n" % exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
