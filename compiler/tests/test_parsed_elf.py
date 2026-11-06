# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Independent local ELF/BTF, backend frame and instruction-model checks.

This test-owned reader/model checks emitted bytes against independently
specified workloads. Helper effects and context inputs are test contracts;
no program is loaded and no kernel/verifier/runtime qualification is claimed.
"""
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct

import pytest

from test_target_model import (ROOT, KEY, MAP, VALUE, DECLS, capture, checked,
                               digest, module, run, spec, llvm_tool, CASES)
from test_parsed_lowering import SOURCES, lower, lower_success, text_ir, assert_conserved

LICENSE = b'Apache-2.0 WITH LLVM-exception\0'


def tool(name):
    executable = Path(checked([__import__('os').environ.get('MOJOBPF_LLVM_CONFIG', 'llvm-config'), '--bindir']).stdout.strip()) / name
    assert executable.is_file(), f'ENVIRONMENT FAILURE: missing {name}'
    assert digest(executable) == CASES['tools'][name], 'unadmitted backend tool'
    return executable


def cstring(data, offset):
    assert 0 <= offset < len(data), 'string offset outside table'
    end = data.find(b'\0', offset)
    assert end >= offset, 'unterminated string'
    return data[offset:end].decode('utf-8')


class ELF:
    def __init__(self, data):
        self.data = data
        assert len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01', 'malformed ELF header'
        kind, machine, version, _, _, shoff, _, ehsize, _, _, shsize, shcount, names = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
        assert (kind, machine, version, ehsize, shsize) == (1, 247, 1, 64, 64), 'non-BPF relocatable header'
        assert 0 < shcount <= 256 and names < shcount and shoff + shcount * 64 <= len(data), 'malformed section table'
        self.sections = []
        for index in range(shcount):
            row = struct.unpack_from('<IIQQQQIIQQ', data, shoff + index * 64)
            name, kind, flags, address, offset, size, link, info, alignment, entsize = row
            assert kind == 8 or offset + size <= len(data), 'truncated section'
            assert link < shcount and (not alignment or alignment & (alignment - 1) == 0), 'invalid section properties'
            self.sections.append(dict(index=index, name_offset=name, kind=kind, flags=flags, offset=offset,
                                      size=size, link=link, info=info, alignment=alignment, entsize=entsize,
                                      header_offset=shoff + index * 64))
        strings = self.bytes(self.sections[names])
        for section in self.sections:
            section['name'] = cstring(strings, section['name_offset'])
        self.by_name = {s['name']: s for s in self.sections}
        assert len(self.by_name) == len(self.sections), 'duplicate section name'
        self.symbols = []
        tables = [s for s in self.sections if s['kind'] == 2]
        assert len(tables) == 1, 'missing/ambiguous symbol table'
        table = tables[0]
        assert table['entsize'] == 24 and table['size'] % 24 == 0
        strings = self.bytes(self.sections[table['link']])
        for offset in range(table['offset'], table['offset'] + table['size'], 24):
            name, info, other, section, value, size = struct.unpack_from('<IBBHQQ', data, offset)
            self.symbols.append(dict(name=cstring(strings, name), info=info, section=section,
                                     value=value, size=size, record_offset=offset))
        self.relocations = []
        for section in self.sections:
            if section['kind'] not in (4, 9):
                continue
            stride = 24 if section['kind'] == 4 else 16
            assert section['entsize'] == stride and section['size'] % stride == 0 and section['link'] == table['index']
            assert section['info'] < len(self.sections)
            for offset in range(section['offset'], section['offset'] + section['size'], stride):
                address, info = struct.unpack_from('<QQ', data, offset)
                symbol, kind = info >> 32, info & 0xffffffff
                assert symbol < len(self.symbols), 'bad relocation symbol'
                self.relocations.append(dict(section=self.sections[section['info']]['name'], offset=address,
                                             kind=kind, symbol=self.symbols[symbol]['name']))

    def bytes(self, section):
        return self.data[section['offset']:section['offset'] + section['size']]


class BTF:
    def __init__(self, data):
        assert len(data) >= 24, 'missing BTF header'
        magic, version, flags, header, typeoff, typelen, stroff, strlen = struct.unpack_from('<HBBIIIII', data)
        assert (magic, version, flags, header) == (0xeb9f, 1, 0, 24), 'malformed BTF header'
        assert header + typeoff + typelen <= len(data) and header + stroff + strlen == len(data), 'malformed BTF bounds'
        strings = data[header + stroff:]
        assert strings and strings[0] == 0
        self.records = [None]
        cursor, end = header + typeoff, header + typeoff + typelen
        while cursor < end:
            assert len(self.records) <= 256 and cursor + 12 <= end, 'BTF type bounds exhausted'
            name, info, size = struct.unpack_from('<III', data, cursor)
            kind, count = (info >> 24) & 31, info & 0xffff
            assert not info & 0x80000000, 'bitfield BTF is outside this fixture contract'
            extra = {1:4, 2:0, 3:12, 4:12*count, 5:12*count, 6:8*count, 7:0,
                     8:0, 9:0, 10:0, 11:0, 12:0, 13:8*count, 14:4, 15:12*count,
                     16:0, 17:4, 18:0, 19:12*count}.get(kind)
            assert extra is not None and cursor + 12 + extra <= end, 'unknown/truncated BTF type'
            payload = data[cursor+12:cursor+12+extra]
            self.records.append(dict(name=cstring(strings, name), kind=kind, count=count,
                                     size=size, payload=payload, offset=cursor))
            cursor += 12 + extra
        assert cursor == end, 'malformed BTF type stream'
        self.strings = strings

    def resolve(self, index):
        seen = set()
        while True:
            assert 0 < index < len(self.records) and index not in seen, 'invalid/cyclic BTF type reference'
            seen.add(index)
            row = self.records[index]
            if row['kind'] not in (8, 9, 10, 11, 18):
                return row
            index = row['size']

    def map_facts(self):
        sections = [r for r in self.records[1:] if r['kind'] == 15 and r['name'] == '.maps']
        assert len(sections) == 1 and sections[0]['count'] == 1, 'missing/ambiguous BTF map datasec'
        section = sections[0]
        assert section['size'] in (0, 32), 'BTF map datasec size differs'
        var, offset, size = struct.unpack('<III', section['payload'])
        variable = self.resolve(var)
        assert variable['kind'] == 14 and variable['name'] == 'mojobpf_map0' and (offset, size) == (0, 32), 'BTF map variable differs'
        assert struct.unpack('<I', variable['payload'])[0] == 1, 'map is not globally allocated'
        record = self.resolve(variable['size'])
        assert record['kind'] == 4 and record['size'] == 32 and record['count'] == 4, 'BTF map struct differs'
        facts = {'size':32, 'offsets':[], 'flags':0}
        for index, name in enumerate(('type', 'max_entries', 'key', 'value')):
            string, typeid, offset = struct.unpack_from('<III', record['payload'], index*12)
            assert cstring(self.strings, string) == name and offset == index*64, 'BTF member layout differs'
            facts['offsets'].append(offset//8)
            pointer = self.resolve(typeid)
            assert pointer['kind'] == 2, 'BTF map member is not a pointer'
            target = self.resolve(pointer['size'])
            if index < 2:
                assert target['kind'] == 3
                element, _, count = struct.unpack('<III', target['payload'])
                assert self.resolve(element)['kind'] == 1
                facts[name] = count
            else:
                assert target['kind'] == 1
                encoding = struct.unpack('<I', target['payload'])[0]
                assert encoding >> 16 == 0, 'map key/value is not an ordinary unsigned integer'
                bits = encoding & 0xffff
                assert target['size'] * 8 == bits
                facts[name + '_bits'] = bits
        assert facts == dict(size=32, offsets=[0,8,16,24], flags=0, type=2, max_entries=1, key_bits=32, value_bits=64), 'map semantic schema differs'
        return facts


def object_contract(path, has_map, entry='xdp_entry', lookups=1, updates=1):
    image = ELF(path.read_bytes())
    assert 'xdp' in image.by_name and 'license' in image.by_name, 'missing program/license section'
    assert image.bytes(image.by_name['license']) == LICENSE, 'license bytes differ'
    code = image.by_name['xdp']
    assert code['flags'] & 4 and code['size'] and code['size'] % 8 == 0
    executable = [s for s in image.sections if s['flags'] & 4 and s['size']]
    functions = [s for s in image.symbols if s['info'] & 15 == 2 and s['section'] == code['index']]
    assert len(executable) == len(functions) == 1 and functions[0]['name'] == entry and functions[0]['value'] == 0
    assert functions[0]['size'] == code['size'] and functions[0]['info'] >> 4 == 1
    assert not [s for s in image.symbols if s['name'] and s['section'] == 0], 'unresolved ordinary symbol'
    instructions = image.bytes(code)
    calls = [struct.unpack_from('<i', instructions, i+4)[0] for i in range(0,len(instructions),8) if instructions[i] == 0x85]
    if has_map:
        assert calls.count(1) == lookups and calls.count(2) == updates and len(calls) == lookups + updates, 'helper calls differ'
        assert '.maps' in image.by_name and '.BTF' in image.by_name, 'missing map/BTF section'
        maps = image.by_name['.maps']
        assert maps['size'] == 32 and maps['alignment'] == 8 and image.bytes(maps) == bytes(32)
        symbols = [s for s in image.symbols if s['section'] == maps['index'] and s['info'] & 15 == 1]
        assert len(symbols) == 1 and symbols[0]['name'] == 'mojobpf_map0' and symbols[0]['size'] == 32
        rels = [r for r in image.relocations if r['section'] == 'xdp']
        assert len(rels) == lookups + updates and all(r['kind'] == 1 and r['symbol'] == 'mojobpf_map0' for r in rels), 'missing/incorrect map relocation'
        for r in rels:
            assert r['offset'] % 8 == 0 and r['offset'] + 16 <= len(instructions) and instructions[r['offset']] == 0x18
        assert any(r['section'] == '.BTF' and r['symbol'] == 'mojobpf_map0' and r['kind'] == 4 for r in image.relocations), 'missing BTF map datasec relocation'
        facts = BTF(image.bytes(image.by_name['.BTF'])).map_facts()
    else:
        assert not calls and '.maps' not in image.by_name and not [r for r in image.relocations if r['section'] == 'xdp']
        facts = None
    return image, facts


def observe_frame(mir, has_map, *, require_spills=False, owned_names=True):
    machine = mir.split('\n---\n', 1)
    assert len(machine) == 2, 'missing machine-function MIR'
    machine = machine[1]
    frame = re.search(r'^frameInfo:\n(.*?)^fixedStack:', machine, re.M | re.S)
    assert frame, 'missing usable frame observation'
    size = re.search(r'^  stackSize:\s+(\d+)\s*$', frame[1], re.M)
    assert size, 'missing usable stack size'
    size = int(size[1])
    assert 0 <= size <= 512 and re.search(r'^fixedStack:\s+\[\]\s*$', machine, re.M), 'unproved fixed/oversized frame'
    stack = re.search(r'^stack:\s*(.*?)^entry_values:', machine, re.M | re.S)
    assert stack, 'missing frame-object inventory'
    cells = []
    for row in re.findall(r'\{(.*?)\}', stack[1], re.S):
        fields = dict(part.strip().split(':', 1) for part in row.split(',') if ':' in part)
        offset, extent, alignment = (int(fields[key]) for key in ('offset','size','alignment'))
        assert extent > 0 and alignment > 0 and alignment & (alignment-1) == 0
        assert -size <= offset < 0 and offset + extent <= 0 and offset % alignment == 0, 'invalid frame object bounds/alignment'
        cells.append(dict(name=fields['name'].strip(), type=fields['type'].strip(), offset=offset, size=extent, alignment=alignment))
    for index, left in enumerate(cells):
        for right in cells[index+1:]:
            assert left['offset'] + left['size'] <= right['offset'] or right['offset'] + right['size'] <= left['offset'], 'overlapping backend cells'
    if has_map:
        key = [c for c in cells if c['name'].startswith('mojobpf.key')] if owned_names else [c for c in cells if c['type'] == 'default' and c['size'] == 4]
        value = [c for c in cells if c['name'].startswith('mojobpf.value')] if owned_names else [c for c in cells if c['type'] == 'default' and c['size'] == 8]
        assert len(key) == len(value) == 1 and (key[0]['size'],key[0]['alignment']) == (4,4) and (value[0]['size'],value[0]['alignment']) == (8,8)
    else:
        assert size == 0 and cells == []
    if require_spills:
        assert any(c['type'] == 'spill-slot' for c in cells), 'pressure control did not actually spill'
    assert 'INLINEASM &"r0 = r10' not in machine and 'INLINEASM &"r0 = mojobpf_map0' not in machine
    return {'stack_size':size, 'objects':cells}


def backend(tmp_path, ir):
    obj, mir = tmp_path/'program.o', tmp_path/'program.mir'
    checked([tool('llc'), '-mtriple=bpfel', '-mcpu=v3', '-O2', '-filetype=obj', ir, '-o', obj])
    checked([tool('llc'), '-mtriple=bpfel', '-mcpu=v3', '-O2', '-stop-after=prologepilog', ir, '-o', mir])
    checked([tool('llvm-readelf'), '-h', '-S', '-s', '-r', obj])
    disassembly = checked([tool('llvm-objdump'), '-dr', obj]).stdout
    return obj, mir, disassembly


def bpftool_facts(path):
    executable = shutil.which('bpftool')
    assert executable, 'ENVIRONMENT FAILURE: bpftool missing (include its bin directory in PATH)'
    assert digest(executable) == CASES['tools']['bpftool'], 'unadmitted BTF reader'
    rows = json.loads(checked([executable, '-j', 'btf', 'dump', 'file', path]).stdout)['types']
    types = {row['id']:row for row in rows}
    def resolved(number):
        visited = set()
        while types[number]['kind'] in {'TYPEDEF','CONST','VOLATILE','RESTRICT','TYPE_TAG'}:
            assert number not in visited
            visited.add(number)
            number = types[number]['type_id']
        return types[number]
    section = next(row for row in rows if row['kind'] == 'DATASEC' and row['name'] == '.maps')
    assert len(section['vars']) == 1 and section['vars'][0]['size'] == 32
    variable = resolved(section['vars'][0]['type_id'])
    assert variable['kind'] == 'VAR' and variable['name'] == 'mojobpf_map0' and variable['linkage'] == 'global'
    record = resolved(variable['type_id'])
    assert record['kind'] == 'STRUCT' and record['size'] == 32 and len(record['members']) == 4
    facts = {'size':32,'offsets':[],'flags':0}
    for index, name in enumerate(('type','max_entries','key','value')):
        field = record['members'][index]
        assert field['name'] == name
        facts['offsets'].append(field['bits_offset']//8)
        pointer = resolved(field['type_id'])
        assert pointer['kind'] == 'PTR'
        target = resolved(pointer['type_id'])
        if index < 2:
            assert target['kind'] == 'ARRAY'
            facts[name] = target['nr_elems']
        else:
            assert target['kind'] == 'INT' and target['encoding'] == '(none)' and target['bits_offset'] == 0
            facts[name+'_bits'] = target['nr_bits']
    return facts


def check_frame_accesses(image, frame):
    code = image.bytes(image.by_name['xdp'])
    for cursor in range(0, len(code), 8):
        opcode, regs, offset, _ = struct.unpack_from('<BBhi', code, cursor)
        if opcode & 7 not in (1,2,3) or opcode & 0xe0 != 0x60:
            continue
        base = regs >> 4 if opcode & 7 == 1 else regs & 15
        if base != 10:
            continue
        size = {0:4,8:2,16:1,24:8}[opcode & 24]
        assert any(c['offset'] <= offset and offset + size <= c['offset'] + c['size'] for c in frame['objects']), 'machine memory access lacks a frame object'


def interpret_object(image, frame, packet=b'', value=41, *, hit=True):
    """Finite test-owned ISA model; helpers follow independent test contracts.

    It reads the actual code/relocations, checks initialized scratch and
    clobbers call-volatile registers. It is not kernel execution evidence.
    """
    context, data, handle, map_value, stack = 0x10000, 0x20000, 0x30000, 0x40000, 0x80000
    memory = {}
    def put(address, number, size):
        for i, byte in enumerate((number & ((1 << (size*8))-1)).to_bytes(size,'little')):
            memory[address+i] = byte
    put(context, data, 4); put(context+4, data+len(packet), 4); put(map_value, value, 8)
    for i, byte in enumerate(packet): memory[data+i] = byte
    def read(address, size):
        assert all(address+i in memory for i in range(size)), 'uninitialized/out-of-bounds machine read'
        return int.from_bytes(bytes(memory[address+i] for i in range(size)), 'little')
    def write(address, number, size):
        assert stack-frame['stack_size'] <= address and address+size <= stack or map_value <= address and address+size <= map_value+8, 'escaped/out-of-frame machine store'
        put(address, number, size)
    code = image.bytes(image.by_name['xdp'])
    rels = {r['offset']:r for r in image.relocations if r['section'] == 'xdp'}
    registers = [None]*11
    registers[1], registers[10] = context, stack
    def reg(index):
        assert 0 <= index < 11 and registers[index] is not None, 'uninitialized/call-clobbered register'
        return registers[index]
    def signed(number, bits):
        return number - (1 << bits) if number & (1 << (bits-1)) else number
    cursor = 0
    for _ in range(16384):
        assert cursor % 8 == 0 and 0 <= cursor <= len(code)-8, 'invalid machine control flow'
        opcode, regs, offset, immediate = struct.unpack_from('<BBhi',code,cursor)
        dst, src, cls, operation = regs & 15, regs >> 4, opcode & 7, opcode & 0xf0
        next_cursor = cursor+8
        if opcode == 0x18:
            assert cursor+16 <= len(code) and code[cursor+8] == 0
            high = struct.unpack_from('<I',code,cursor+12)[0]
            registers[dst] = handle if cursor in rels else (immediate & 0xffffffff) | high << 32
            next_cursor += 8
        elif cls in (1,2,3) and opcode & 0xe0 == 0x60:
            size = {0:4,8:2,16:1,24:8}[opcode & 24]
            if cls == 1: registers[dst] = read(reg(src)+offset,size)
            else: write(reg(dst)+offset, reg(src) if cls == 3 else immediate, size)
        elif cls in (4,7):
            bits = 32 if cls == 4 else 64
            mask = (1 << bits)-1
            right = (reg(src) if opcode & 8 else immediate) & mask
            left = reg(dst) & mask if operation != 0xb0 else 0
            if operation == 0xb0: result = right
            elif operation == 0x00: result = left+right
            elif operation == 0x10: result = left-right
            elif operation == 0x20: result = left*right
            elif operation == 0x40: result = left | right
            elif operation == 0x50: result = left & right
            elif operation == 0x60: result = left << right
            elif operation == 0x70: result = left >> right
            elif operation == 0x80: result = -left
            elif operation == 0xa0: result = left ^ right
            elif operation == 0xc0: result = signed(left,bits) >> right
            else: raise AssertionError(f'unmodeled ALU instruction {opcode:#x}')
            registers[dst] = result & mask
        elif cls in (5,6):
            if operation == 0x90:
                return reg(0) & 0xffffffff, read(map_value,8)
            if operation == 0x80:
                assert opcode == 0x85 and immediate in (1,2) and reg(1) == handle
                key = reg(2)
                assert stack-frame['stack_size'] <= key and key+4 <= stack and read(key,4) == 0, 'corrupted helper key'
                if immediate == 1: result = map_value if hit else 0
                else:
                    pointer = reg(3)
                    assert stack-frame['stack_size'] <= pointer and pointer+8 <= stack and reg(4) == 0, 'corrupted update value/flags'
                    put(map_value,read(pointer,8),8)
                    result = 0
                registers[0] = result
                registers[1:6] = [None]*5
            elif operation == 0x00:
                next_cursor += offset*8
            else:
                bits = 32 if cls == 6 else 64
                mask = (1 << bits)-1
                left, right = reg(dst) & mask, (reg(src) if opcode & 8 else immediate) & mask
                conditions = {0x10:left==right, 0x20:left>right, 0x30:left>=right, 0x40:bool(left & right),
                              0x50:left!=right, 0x60:signed(left,bits)>signed(right,bits),
                              0x70:signed(left,bits)>=signed(right,bits), 0xa0:left<right, 0xb0:left<=right,
                              0xc0:signed(left,bits)<signed(right,bits), 0xd0:signed(left,bits)<=signed(right,bits)}
                assert operation in conditions, f'unmodeled jump {opcode:#x}'
                if conditions[operation]: next_cursor += offset*8
        else:
            raise AssertionError(f'unmodeled instruction {opcode:#x}')
        cursor = next_cursor
    raise AssertionError('finite instruction-model work budget exhausted')


def classifier_oracle(frame, inverted=False):
    return 1 if len(frame) >= 15 and frame[14] % 2 == (0 if inverted else 1) else 2


def assert_workload(image, frame, source, *, pressure=None):
    if 'map_roundtrip' in source or pressure is not None:
        for initial in (0,41,(1 << 64)-1):
            if pressure is None:
                expected = (initial + (2 if 'mutated' in source else 1)) & ((1 << 64)-1)
            else:
                expected = sum(initial+i+1 for i in range(pressure)) & ((1 << 64)-1)
            assert interpret_object(image,frame,value=initial) == (2,expected)
            assert interpret_object(image,frame,value=initial,hit=False) == (2,initial)
    else:
        corpus = ROOT/'examples/packet_classifier/corpus'
        manifest = json.loads((corpus/'manifest.json').read_text())
        frames = [corpus/row['file'] for row in manifest['frames']]
        for row, path in zip(manifest['frames'],frames):
            assert digest(path) == row['sha256']
            packet = path.read_bytes()
            expected = classifier_oracle(packet,'mutated' in source)
            assert interpret_object(image,frame,packet)[0] == expected


@pytest.mark.parametrize('source,has_map', SOURCES)
@pytest.mark.parametrize('frontend_emit', ['llvm','llvm-bitcode'])
def test_genuine_objects_have_standard_elf_btf_and_measured_frames(tmp_path, source, has_map, frontend_emit):
    raw = capture(tmp_path, ROOT/source, frontend_emit)
    result, report, output = lower(tmp_path, raw, spec(has_map), emit='bitcode' if frontend_emit == 'llvm-bitcode' else 'llvm')
    lower_success(result, report, output)
    assert_conserved(text_ir(raw), text_ir(output), report['transformations'])
    obj, mir, disassembly = backend(tmp_path, output)
    image, facts = object_contract(obj, has_map)
    frame = observe_frame(mir.read_text(), has_map)
    check_frame_accesses(image,frame)
    assert_workload(image,frame,source)
    assert 'xdp_entry' in disassembly
    if has_map:
        assert bpftool_facts(obj) == facts


@pytest.mark.parametrize('name,has_map,entry', [
    ('xdp_classifier_ref.bpf.c',False,'xdp_classifier_ref'),
    ('map_roundtrip_ref.bpf.c',True,'map_roundtrip_ref')])
def test_independent_exact_workload_c_reference_objects(tmp_path,name,has_map,entry):
    source = ROOT/'tests/reference_c'/name
    obj = tmp_path/'reference.o'
    checked([tool('clang'), '--target=bpfel', '-mcpu=v3', '-O2', '-g', '-c', source, '-o', obj])
    image, facts = object_contract(obj,has_map,entry)
    ir = tmp_path/'reference.ll'
    checked([tool('clang'), '--target=bpfel', '-mcpu=v3', '-O2', '-g', '-S', '-emit-llvm', source, '-o', ir])
    _, mir, _ = backend(tmp_path,ir)
    if has_map:
        # C owns its own anonymous stack cells, independently of Mojo names.
        frame = observe_frame(mir.read_text(),True,owned_names=False)
        assert bpftool_facts(obj) == facts
        assert_workload(image,frame,'map_roundtrip')
        raw = capture(tmp_path,ROOT/'tests/compile/map_roundtrip.mojo','llvm')
        result, report, lowered = lower(tmp_path,raw,spec(True))
        lower_success(result,report,lowered)
        mojo_obj, _, _ = backend(tmp_path,lowered)
        assert object_contract(mojo_obj,True)[1] == facts
    else:
        frame = observe_frame(mir.read_text(),False)
        assert_workload(image,frame,'classifier')


def pressure_source(count):
    body = 'entry:\n'
    for index in range(count):
        body += f'''  %key{index} = {KEY}
  %map{index} = {MAP}
  %found{index} = call i64 @__mojobpf_lookup_v1(i64 %map{index}, ptr %key{index})
  %null{index} = icmp eq i64 %found{index}, 0
  br i1 %null{index}, label %done, label %hit{index}
hit{index}:
  %ptr{index} = call ptr asm "", "=r,0"(i64 %found{index})
  %old{index} = load i64, ptr %ptr{index}, align 8
  %payload{index} = add i64 %old{index}, {index+1}
'''
    last = '%payload0'
    for index in range(1,count):
        body += f'  %sum{index} = add i64 {last}, %payload{index}\n'
        last = f'%sum{index}'
    body += f'''  %value = {VALUE}
  store i64 {last}, ptr %value, align 8
  %finalkey = {KEY}
  %finalmap = {MAP}
  %updated = call i64 @__mojobpf_update_v1(i64 %finalmap, ptr %finalkey, ptr %value, i64 0)
  br label %done
done:
  ret i32 2
'''
    return module(body,DECLS)


@pytest.mark.parametrize('count',[2,10,24])
@pytest.mark.parametrize('bitcode',[False,True])
def test_backend_spills_preserve_shared_cells_and_live_scalar_values(tmp_path,count,bitcode):
    source = tmp_path/'pressure.ll'
    source.write_text(pressure_source(count))
    if bitcode:
        bc = tmp_path/'pressure.bc'
        checked([llvm_tool('llvm-as'),source,'-o',bc]); source = bc
    result,report,output = lower(tmp_path,source,spec(True))
    lower_success(result,report,output)
    assert_conserved(text_ir(source),text_ir(output),report['transformations'])
    obj,mir,_ = backend(tmp_path,output)
    image,_ = object_contract(obj,True,lookups=count)
    frame = observe_frame(mir.read_text(),True,require_spills=count >= 10)
    check_frame_accesses(image,frame)
    assert_workload(image,frame,'pressure',pressure=count)


@pytest.mark.parametrize('mutation',['no-relocation','no-btf','key-width','map-symbol-size','truncated'])
def test_post_compile_object_mutants_reach_independent_checker(tmp_path,mutation):
    raw = capture(tmp_path,ROOT/'tests/compile/map_roundtrip.mojo','llvm')
    result,report,output = lower(tmp_path,raw,spec(True)); lower_success(result,report,output)
    original,_,_ = backend(tmp_path,output)
    image,_ = object_contract(original,True)
    mutant = tmp_path/'artifact-mutant.o'
    if mutation in {'no-relocation','no-btf'}:
        section = '.relxdp' if mutation == 'no-relocation' else '.BTF'
        checked([tool('llvm-objcopy'),'--remove-section',section,original,mutant])
    else:
        data = bytearray(original.read_bytes())
        if mutation == 'key-width':
            section = image.by_name['.BTF']
            btf = BTF(image.bytes(section))
            key = next(r for r in btf.records[1:] if r['kind'] == 1 and r['name'] == 'UInt32')
            struct.pack_into('<I',data,section['offset']+key['offset']+12,16)
        elif mutation == 'map-symbol-size':
            symbol = next(s for s in image.symbols if s['name'] == 'mojobpf_map0')
            struct.pack_into('<Q',data,symbol['record_offset']+16,16)
        else:
            data = data[:45]
        mutant.write_bytes(data)
    assert mutant.read_bytes() != original.read_bytes()
    run([tool('llvm-readelf'),'-h','-r',mutant])
    with pytest.raises(AssertionError):
        object_contract(mutant,True)


@pytest.mark.parametrize('mutation',['absent','missing-size','overlap','oversize'])
def test_missing_or_corrupt_frame_observations_fail_closed(tmp_path,mutation):
    source = tmp_path/'pressure.ll'; source.write_text(pressure_source(10))
    result,report,output = lower(tmp_path,source,spec(True)); lower_success(result,report,output)
    _,mir,_ = backend(tmp_path,output)
    text = mir.read_text()
    observe_frame(text,True,require_spills=True)
    if mutation == 'absent': text = text.split('\n---\n')[0]
    elif mutation == 'missing-size': text = re.sub(r'^  stackSize:.*\n','',text,flags=re.M)
    elif mutation == 'overlap': text = text.replace('offset: -16, size: 8','offset: -4, size: 8',1)
    else: text = re.sub(r'^  stackSize:.*$', '  stackSize: 1024',text,flags=re.M)
    with pytest.raises(AssertionError): observe_frame(text,True,require_spills=True)


@pytest.mark.parametrize('has_map',[False,True])
def test_isa_oracle_refuses_valid_objects_with_changed_behavior(tmp_path,has_map):
    source = 'tests/compile/map_roundtrip.mojo' if has_map else 'examples/xdp_pass/xdp_pass.mojo'
    raw = capture(tmp_path,ROOT/source,'llvm')
    result,report,output = lower(tmp_path,raw,spec(has_map)); lower_success(result,report,output)
    obj,mir,_ = backend(tmp_path,output)
    image,_ = object_contract(obj,has_map)
    frame = observe_frame(mir.read_text(),has_map)
    assert_workload(image,frame,source)
    section = image.by_name['xdp']
    data = bytearray(obj.read_bytes())
    code = image.bytes(section)
    for cursor in range(0,len(code),8):
        opcode,_,_,immediate = struct.unpack_from('<BBhi',code,cursor)
        if (has_map and opcode == 0x07 and immediate == 1) or (not has_map and opcode in (0x54,0x57) and immediate == 1):
            struct.pack_into('<i',data,section['offset']+cursor+4,7 if has_map else 0)
            break
    else: raise AssertionError('missing behavior mutation point')
    mutant = tmp_path/'behavior-mutant.o'; mutant.write_bytes(data)
    run([tool('llvm-readelf'),'-h','-r',mutant])
    changed,_ = object_contract(mutant,has_map)
    with pytest.raises(AssertionError): assert_workload(changed,frame,source)


# ---------------------------------------------------------------------------
# T4a-1 byte-identity: parsed objects equal the Lane-A pins.
# ---------------------------------------------------------------------------

from test_parsed_lowering import SUBPROG_SOURCES as _SUBPROG_SOURCES
from test_parsed_lowering import subprog_spec as _subprog_spec
from test_parsed_lowering import tc_spec as _tc_spec
from test_parsed_lowering import PERMISSIVE_GAPS as _PERMISSIVE_GAPS

LANE_A_OBJECT_PINS = {
    'examples/xdp_pass/xdp_pass.mojo':
        '17570ee79a16b64ccc4f723d00d26ae316a286cffdd3382ba3a6e6b4be95097c',
    'examples/subprog_call/decision.mojo':
        '6bc42a7e1cbd90befb7f01a2a4a2a4d0442561792f46248cce9afb3e404b8b56',
    'tests/compile/subprog_entry_first.mojo':
        'c62683ac82ac5f62cf704f9e921855d218459e663bff1a504b2b887d1d583115',
    'tests/compile/packet_unguarded.mojo':
        '7443e0772400f707546f789f18462eff804ca4cb8057e7772b5b1bc513b85b83',
    'tests/compile/packet_var_offset.mojo':
        'e7d23f1359724cb44e7b7eb3cba30d37a2dfc8e4232ce2ae2db4cc6694679c8a',
    'tests/compile/parse_trunc.mojo':
        'ad4ba7bb849596af4e5bde09dc19d65e05f3efc5791bf5a5e02fc7a5591bc7d3',
    'tests/compile/scalar_addr_edge.mojo':
        '7af64ad6d3f30df640ccd9d5288c913e8725d34911e988011905a7cceeae462a',
    'examples/tc_classifier/tc.mojo':
        '19d605af318d1200d12dc7861c36720006f0e86afbfc01162efe891df5241a34',
    'examples/tc_classifier/tc_mutated.mojo':
        'bd31c52d5a3d96c8cb86a610517f3bfc012e16cae55edc4820baa677d1fa19a2',
}


def _parsed_object(tmp_path, source):
    raw = capture(tmp_path, ROOT/source, 'llvm')
    if 'subprog' in source or 'decision.mojo' in source:
        request = _subprog_spec()
    elif 'tc_classifier' in source:
        request = _tc_spec()
    else:
        request = spec()
    permissive = source in {gap for gap, _code in _PERMISSIVE_GAPS}
    result, report, output = lower(tmp_path, raw, request, permissive=permissive)
    lower_success(result, report, output)
    obj, _, _ = backend(tmp_path, output)
    return obj


@pytest.mark.parametrize('source,pinned', sorted(LANE_A_OBJECT_PINS.items()))
def test_parsed_object_matches_lane_a_pin(tmp_path, source, pinned):
    # Byte-identity with the qualified Lane-A emission (pins owned
    # by tests/compile/test_build_pipeline.py EXPECTED_PINS and
    # tests/elf/test_subprog_struct.py): guest behavior cannot drift
    # between routes because the bytes are the same bytes.
    obj = _parsed_object(tmp_path, source)
    observed = hashlib.sha256(obj.read_bytes()).hexdigest()
    assert observed == pinned, (source, observed)


# ---------------------------------------------------------------------------
# T4a-2 map stability: parsed map bytes pinned with BTF semantics.
#
# No byte-identity (transparent allocas lower differently from
# opaque fixed-slot asm, and map BTF uses the modern typed
# spelling): these pins prove parsed-route stability while the
# spill-gate multisets (shared with Lane-A), the BTF map facts
# below, and the kernel suites prove equivalence.
# ---------------------------------------------------------------------------

PARSED_MAP_OBJECT_PINS = {
    'tests/compile/map_roundtrip.mojo':
        '741a97051533b2ab303593c3ea1422c72a5a89addc5228d2b71b8b6a5fda3652',
    'tests/compile/map_unchecked.mojo':
        '33ddef751ce2727068963d69cb1fb79c4c71af3db2f926881b2d0ccec9958a9f',
    'tests/compile/map_oob.mojo':
        '7abd683557b776e9daffaa6581960fd743c33b8fd35a5ae8373fac847916ed0f',
    'tests/compile/subset/subset_oob_store.mojo':
        'afa53215e30c482c5db07b0b7c0f36977f4c085d71dbcf2a9dbf09e3d3e54e6d',
    'tests/packaging/external_consumer/canary.mojo':
        '5513af99f1cb7047ccf1196863a4240e01bceaf2785b4891c4c6d190ae3b0683',
}

_MAP_KERNEL_NEGATIVES = {
    'tests/compile/map_unchecked.mojo',
    'tests/compile/map_oob.mojo',
    'tests/compile/subset/subset_oob_store.mojo',
}


def _parsed_map_object(tmp_path, source):
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, output = lower(
        tmp_path, raw, spec(has_map=True),
        permissive=source in _MAP_KERNEL_NEGATIVES,
    )
    lower_success(result, report, output)
    obj, _, _ = backend(tmp_path, output)
    return obj


@pytest.mark.parametrize('source,pinned', sorted(PARSED_MAP_OBJECT_PINS.items()))
def test_parsed_map_object_matches_stability_pin(tmp_path, source, pinned):
    # Parsed-route bytes plus modern-BTF map semantics (array,
    # u32 key, u64 value, one entry): stability here, equivalence
    # via the shared spill multisets and the kernel suites.
    obj = _parsed_map_object(tmp_path, source)
    observed = hashlib.sha256(obj.read_bytes()).hexdigest()
    assert observed == pinned, (source, observed)
    image = ELF(obj.read_bytes())
    facts = BTF(image.bytes(image.by_name['.BTF'])).map_facts()
    assert facts == {
        'size': 32, 'offsets': [0, 8, 16, 24], 'flags': 0,
        'type': 2, 'max_entries': 1, 'key_bits': 32,
        'value_bits': 64,
    }, (source, facts)


@pytest.mark.parametrize('source,callee', _SUBPROG_SOURCES)
def test_parsed_subprog_object_shape(tmp_path, source, callee):
    # Shape the pins transfer from the Lane-A struct tests: entry
    # in xdp, callee in .text, one R_BPF_64_32 subprog call.
    obj = _parsed_object(tmp_path, source)
    image = ELF(obj.read_bytes())
    assert image.by_name['xdp']['size'] == 72, source
    assert image.by_name['.text']['size'] == 40, source
    funcs = {s['name']: s for s in image.symbols if s['info'] == 0x12}
    assert sorted(funcs) == sorted(['xdp_entry', callee]), (source, sorted(funcs))
    assert funcs['xdp_entry']['section'] == image.by_name['xdp']['index'], source
    assert funcs[callee]['section'] == image.by_name['.text']['index'], source
    rels = [r for r in image.relocations if r['section'] == 'xdp']
    assert len(rels) == 1, (source, rels)
    assert rels[0]['kind'] == 10 and rels[0]['symbol'] == callee, (source, rels)
    assert rels[0]['offset'] == 0x38, (source, rels)
