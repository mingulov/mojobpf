# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Shared bytes-based ELF reader for inspection and verification.

This module owns the ELF container boundary: it decodes untrusted
object bytes into sections and symbols, failing closed on every
malformed shape. Both :mod:`mojobpf.inspect` (structural findings)
and :mod:`mojobpf.verify` (informational section/license reads)
decode through this module, so there is exactly one ELF
decoder -- no second oracle with its own edge-case opinions.
:func:`parse_elf` decodes headers, sections and symbols;
:func:`parse_elf_sections` decodes headers and sections through
the same shared code without symbol decode, for the
informational reader that never consumed symbols (verification's
section/license read keeps its pre-extraction behavior there:
symbol-table shapes cannot fail it). Header and section
acceptance has exactly one decision either way.
Callers keep their own error vocabularies: inspection maps
:class:`ElfError` to ``MBPF401``/``MBPF402`` structural findings,
while verification translates it to ``ValueError`` (its parse
stays informational-only: the loader's own verdict, not this
reader, decides loadability).

The ``MBPF401``/``MBPF402`` codes on :class:`ElfError` are the
shared structural vocabulary: ``MBPF401`` for unreadable or
non-ELF input (not an object file, not 64-bit, not
little-endian, truncated header) and ``MBPF402`` for malformed
ELF internals (section table, names, symbols).

Standard library only.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

SHT_SYMTAB = 2
SHT_RELA = 4
SHT_REL = 9
SHT_NOBITS = 8


class ElfError(Exception):
    """Internal parse failure carrying a finding, not a traceback."""

    def __init__(self, code: str, explanation: str, location: str) -> None:
        super().__init__(explanation)
        self.code = code
        self.explanation = explanation
        self.location = location


@dataclass
class Section:
    index: int
    name: str
    name_off: int
    type: int
    flags: int
    offset: int
    size: int
    link: int
    info: int
    entsize: int


@dataclass
class Symbol:
    name: str
    type: int
    shndx: int
    value: int
    size: int


@dataclass
class Elf:
    image: bytes
    machine: int
    objtype: int
    sections: list[Section]
    symbols: list[Symbol]


def _parse_header_and_sections(
    image: bytes, path: str
) -> tuple[int, int, list[Section]]:
    """Decode the ELF header and section table, failing closed.

    This is the single shared container decode behind both
    :func:`parse_elf` and :func:`parse_elf_sections`: header and
    section acceptance is decided here once, never per caller.
    Returns ``(machine, object type, sections)``.
    """
    if len(image) < 64 or image[:4] != b"\x7fELF":
        raise ElfError("MBPF401", "not an ELF object file", path)
    if image[4] != 2:
        raise ElfError("MBPF401", "not a 64-bit object file", path)
    if image[5] != 1:
        raise ElfError("MBPF401", "not a little-endian object file", path)
    try:
        (objtype, machine, _version) = struct.unpack_from("<HHI", image, 16)
        (e_shoff,) = struct.unpack_from("<Q", image, 40)
        (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
            "<HHH", image, 58
        )
    except struct.error:
        raise ElfError("MBPF401", "truncated ELF header", path) from None
    if e_shentsize != 0 and e_shentsize < 64:
        raise ElfError("MBPF402", "bad section header size", path)
    if e_shnum == 0 and e_shoff != 0:
        raise ElfError(
            "MBPF402", "extended section numbering is not supported", path
        )
    if e_shnum != 0 and e_shoff + e_shnum * e_shentsize > len(image):
        raise ElfError("MBPF402", "section table runs past end", path)
    sections: list[Section] = []
    for index in range(e_shnum):
        off = e_shoff + index * e_shentsize
        try:
            fields = struct.unpack_from("<IIQQQQIIQQ", image, off)
        except struct.error:
            raise ElfError(
                "MBPF402", "truncated section header %d" % index, path
            ) from None
        (name, stype, flags, _addr, sec_off, size, link, info,
         _align, entsize) = fields
        if stype != SHT_NOBITS and sec_off + size > len(image):
            raise ElfError(
                "MBPF402",
                "section %d contents run past end of file" % index,
                path,
            )
        sections.append(
            Section(index, "", name, stype, flags, sec_off, size, link,
                    info, entsize)
        )
    if sections:
        if e_shstrndx >= len(sections):
            raise ElfError("MBPF402", "bad section-name table", path)
        strtab = sections[e_shstrndx]
        for section in sections:
            raw = _cstr(
                image, strtab.offset, strtab.size, section.name_off,
                path,
            )
            try:
                section.name = raw.decode("ascii")
            except UnicodeDecodeError:
                raise ElfError(
                    "MBPF402",
                    "section %d name is not ASCII" % section.index,
                    path,
                ) from None
    return machine, objtype, sections


def _parse_symbols(
    image: bytes, sections: list[Section], path: str
) -> list[Symbol]:
    """Decode every symbol-table section, failing closed."""
    symbols: list[Symbol] = []
    for section in sections:
        if section.type != SHT_SYMTAB:
            continue
        stride = section.entsize or 24
        if stride < 24 or section.size % stride != 0:
            raise ElfError(
                "MBPF402",
                "symbol table %r has a bad entry size" % section.name,
                path,
            )
        if section.link >= len(sections):
            raise ElfError(
                "MBPF402",
                "symbol table %r links a missing string table"
                % section.name,
                path,
            )
        strsec = sections[section.link]
        for entry in range(section.size // stride):
            off = section.offset + entry * stride
            try:
                (st_name, st_info, _other, st_shndx, st_value,
                 st_size) = struct.unpack_from("<IBBHQQ", image, off)
            except struct.error:
                raise ElfError(
                    "MBPF402", "truncated symbol table entry", path
                ) from None
            raw = _cstr(image, strsec.offset, strsec.size, st_name, path)
            try:
                name = raw.decode("ascii")
            except UnicodeDecodeError:
                raise ElfError(
                    "MBPF402", "symbol name is not ASCII", path
                ) from None
            symbols.append(
                Symbol(name, st_info & 0xF, st_shndx, st_value, st_size)
            )
    return symbols


def parse_elf(image: bytes, path: str) -> Elf:
    """Parse a 64-bit little-endian ELF object, failing closed.

    ``image`` is the complete captured object bytes; ``path`` only
    labels parse failures and is never read.
    """
    machine, objtype, sections = _parse_header_and_sections(
        image, path
    )
    symbols = _parse_symbols(image, sections, path)
    return Elf(image, machine, objtype, sections, symbols)


def parse_elf_sections(image: bytes, path: str) -> Elf:
    """Parse headers and sections only, skipping symbol decode.

    Header and section acceptance is the same single decision as
    :func:`parse_elf` (shared code, not a second decoder);
    symbol-table shapes can never fail this entry point, and the
    returned ``symbols`` is always empty. For informational
    readers that never consumed symbols.
    """
    machine, objtype, sections = _parse_header_and_sections(
        image, path
    )
    return Elf(image, machine, objtype, sections, [])


def _cstr(image: bytes, base: int, size: int, off: int,
          path: str) -> bytes:
    """Read a NUL-terminated string; fail closed on bad bounds."""
    if off >= size:
        raise ElfError("MBPF402", "string offset past table end", path)
    end = image.find(b"\x00", base + off, base + size)
    if end < 0:
        raise ElfError("MBPF402", "unterminated table string", path)
    return image[base + off:end]


def section_bytes(elf: Elf, section: Section) -> bytes:
    if section.type == SHT_NOBITS:
        return b""
    return elf.image[section.offset:section.offset + section.size]
