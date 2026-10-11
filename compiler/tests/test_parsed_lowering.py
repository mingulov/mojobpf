# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Real-source lowering and independent conservation/semantic controls.

All captures use the admitted Mojo producer. These are local compiler
checks; none load a BPF program or establish kernel runtime qualification.
"""
import json
import os
from pathlib import Path
import re
import shutil

import pytest

from test_target_model import (ROOT, MAP_BODY, DECLS, capture, checked, digest,
                               llvm_tool, lower_tool, module, run, spec)

from test_target_model import VALUE
from test_target_model import equal_reachability_payload

SOURCES = [
    ('examples/xdp_pass/xdp_pass.mojo', False),
    ('examples/xdp_pass/xdp_pass_mutated.mojo', False),
    ('tests/compile/map_roundtrip.mojo', True),
    ('tests/compile/map_roundtrip_mutated.mojo', True),
]


def lower(tmp_path, source, request, *, emit='llvm'):
    request_path = tmp_path / 'spec.json'
    request_path.write_text(json.dumps(request))
    output = tmp_path / ('lowered.bc' if emit == 'bitcode' else 'lowered.ll')
    report_path = tmp_path / 'lower.report.json'
    result = run([lower_tool(), '--mode', 'lower', '--input', source,
                  '--spec', request_path, '--report', report_path,
                  '--output', output, '--emit', emit])
    report = json.loads(report_path.read_text()) if report_path.exists() else None
    return result, report, output


def lower_success(result, report, output):
    assert result.returncode == 0, result.stdout + result.stderr
    assert report is not None and report['ok'] is True, 'missing/contradictory report'
    assert report['mode'] == 'lower' and report['runtime_qualified'] is False
    assert report['diagnostics'] == [] and output.is_file()
    assert report['output_digest'] == digest(output)
    assert report['transformations'], 'missing explicit rewrite ledger'
    checked([llvm_tool('opt'), '-passes=verify', '-disable-output', output])


def text_ir(path):
    return checked([llvm_tool('opt'), '-S', '-passes=verify', path, '-o', '-']).stdout


def body_lines(text, entry='xdp_entry'):
    body = re.search(r'^define .*@' + re.escape(entry) + r'\(.*?\{\n(.*?)^}', text, re.M | re.S)
    assert body, 'missing entry body'
    lines = []
    for line in body.group(1).splitlines():
        line = line.split(';', 1)[0].strip()
        if line:
            lines.append(re.sub(r' #\d+$', '', line))
    return lines


def assert_conserved(source, lowered, transformations, entry='xdp_entry'):
    """Compare the complete instruction/CFG sequence through explicit rewrites.

    This test-only reader compares verified LLVM printer output. It derives
    expected operations from the source, not from a lowerer-produced graph.
    It permits only the documented primitive/callee/global transformations.
    """
    mappings = {row['source']: row['target'] for row in transformations if row['kind'] == 'value-map'}
    rewrites = {row['source_ordinal']: row for row in transformations if row['kind'] in {'key', 'value', 'map', 'helper'}}
    def rename(line):
        return re.sub(r'%[-a-zA-Z$._0-9]+', lambda m: mappings.get(m[0], m[0]), line)
    wanted = []
    ordinal = 0
    source_lines = body_lines(source, entry)
    if not source_lines[0].endswith(':'):
        entry_row = next(row for row in transformations if row.get('value_kind') == 'entry-block')
        source_lines.insert(0, entry_row['source'][1:] + ':')
    for line in source_lines:
        if line.endswith(':'):
            old = '%' + line[:-1]
            wanted.append(mappings.get(old, old)[1:] + ':')
            continue
        row = rewrites.get(ordinal)
        ordinal += 1
        if row and row['kind'] in {'value', 'map'}:
            continue
        if row and row['kind'] == 'key':
            wanted.append(f"store i32 {row['literal']}, ptr {row['target']}, align 4")
            continue
        line = rename(line)
        if row and row['kind'] == 'helper':
            line = line.replace('@' + row['callee'], f"inttoptr (i64 {row['helper_id']} to ptr)")
        wanted.append(line)
    actual = [line for line in body_lines(lowered, entry) if ' = alloca ' not in line]
    assert actual == wanted, 'source instruction/value/CFG conservation failed'


def audit_lowered(tmp_path, text, request=None, *, bitcode=False):
    source = tmp_path / 'post-audit.ll'
    source.write_text(text)
    if bitcode:
        bitcode_path = tmp_path / 'post-audit.bc'
        checked([llvm_tool('llvm-as'), source, '-o', bitcode_path])
        source = bitcode_path
    bindings = tmp_path / 'post-spec.json'
    bindings.write_text(json.dumps(request or spec(True)))
    driver = Path(os.environ.get('MOJOBPF_AUDIT_DRIVER', str(lower_tool().with_name('mojobpf-audit-driver'))))
    result = run([driver, '--analysis', 'lowered', '--input', source, '--bindings', bindings])
    report = json.loads(result.stdout)
    return result, report


@pytest.mark.parametrize('source,has_map', SOURCES)
@pytest.mark.parametrize('frontend_emit', ['llvm', 'llvm-bitcode'])
def test_genuine_sources_lower_without_runtime_or_fixed_stack(tmp_path, source, has_map, frontend_emit):
    raw = capture(tmp_path, ROOT / source, frontend_emit)
    identity = digest(raw)
    result, report, output = lower(tmp_path, raw, spec(has_map))
    lower_success(result, report, output)
    assert digest(raw) == identity
    text = text_ir(output)
    assert 'target triple = "bpfel-unknown-none"' in text
    assert 'section "xdp"' in text and 'section "license"' in text
    assert 'r10' not in text and 'r0 = mojobpf_map0 ll' not in text
    assert '@__mojobpf_' not in text
    assert '"target-cpu"="znver4"' not in text
    if has_map:
        assert len(re.findall(r'alloca i32\b', text)) == 1
        assert len(re.findall(r'alloca i64\b', text)) == 1
        assert 'inttoptr (i64 1 to ptr)' in text
        assert 'inttoptr (i64 2 to ptr)' in text
        assert 'section ".maps"' in text and 'DW_LANG_Mojo' in text
    else:
        assert 'alloca ' not in text and 'inttoptr (i64 ' not in text
    assert_conserved(text_ir(raw), text, report['transformations'])


def synthetic_lowered(tmp_path):
    source = tmp_path / 'source.ll'
    source.write_text(module(MAP_BODY, DECLS))
    result, report, output = lower(tmp_path, source, spec(True))
    lower_success(result, report, output)
    return source, report, text_ir(output)


@pytest.mark.parametrize('bitcode', [False, True])
def test_independent_post_audit_accepts_actual_lowered_forms(tmp_path, bitcode):
    _, _, text = synthetic_lowered(tmp_path)
    result, report = audit_lowered(tmp_path, text, bitcode=bitcode)
    assert result.returncode == 0 and report['ok'] is True, result.stderr + result.stdout
    assert report['whole_program_admitted'] is False and report['runtime_qualified'] is False


@pytest.mark.parametrize('mutation', ['increment', 'branch', 'removal'])
def test_conservation_oracle_rejects_llvm_valid_semantic_mutations(tmp_path, mutation):
    source, report, text = synthetic_lowered(tmp_path)
    if mutation == 'increment':
        corrupt = text.replace('add i64 %old, 1', 'add i64 %old, 7')
    elif mutation == 'branch':
        corrupt = text.replace('br i1 %null, label %done, label %hit', 'br i1 %null, label %hit, label %done')
    else:
        corrupt = text.replace('  store i64 %sum, ptr %mojobpf.value, align 8\n', '')
    assert corrupt != text
    path = tmp_path / 'conservation-mutant.ll'
    path.write_text(corrupt)
    checked([llvm_tool('opt'), '-passes=verify', '-disable-output', path])
    with pytest.raises(AssertionError, match='conservation'):
        assert_conserved(text_ir(source), text_ir(path), report['transformations'])


POST_MUTANTS = [
    ('helper-id', 'inttoptr (i64 1 to ptr)', 'inttoptr (i64 7 to ptr)', 'MBPF313'),
    ('helper-prototype', '%updated = call i64', '%updated = call i32', 'MBPF313'),
    ('update-flags', 'ptr %mojobpf.value, i64 0)', 'ptr %mojobpf.value, i64 1)', 'MBPF314'),
    ('uninitialized-value', '  store i64 %sum, ptr %mojobpf.value, align 8\n', '', 'MBPF314'),
    ('missing-key-preparation', '  store i32 0, ptr %mojobpf.key, align 4\n', '', 'MBPF318'),
    ('pointer-store', 'store i64 %sum, ptr %mojobpf.value', 'store ptr %mojobpf.value, ptr %mojobpf.value', 'MBPF316'),
    ('address-select', '  %key2 =', '  %key2 =', 'MBPF316'),
    ('wrong-license', 'Apache-2.0 WITH LLVM-exception', 'Apache-2.0 WITH LLVM-exceptioN', 'MBPF319'),
    ('key-layout', 'alloca i32, align 4', 'alloca i16, align 4', 'MBPF310'),
    ('value-alignment', 'alloca i64, align 8', 'alloca i64, align 16', 'MBPF310'),
    ('map-member-offset', 'offset: 128', 'offset: 120', 'MBPF319'),
]


@pytest.mark.parametrize('bitcode', [False, True])
@pytest.mark.parametrize('name,before,after,code', POST_MUTANTS)
def test_post_audit_refuses_actual_lowered_corruption(tmp_path, bitcode, name, before, after, code):
    _, _, text = synthetic_lowered(tmp_path)
    if name == 'address-select':
        corrupt = text.replace('  store i64 %sum, ptr %mojobpf.value, align 8',
            '  %bits = select i1 %null, i64 1, i64 0\n  store i64 %bits, ptr %mojobpf.value, align 8')
    else:
        corrupt = text.replace(before, after)
    assert corrupt != text, name
    result, report = audit_lowered(tmp_path, corrupt, bitcode=bitcode)
    assert result.returncode == 4 and report['ok'] is False, result.stdout + result.stderr
    assert report['diagnostics'][0]['code'] == code, report


@pytest.mark.parametrize('bitcode', [False, True])
@pytest.mark.parametrize('name', ['function-metadata', 'fixed-stack', 'unaligned-scratch', 'resource'])
def test_post_audit_preserves_existing_boundary_proofs(tmp_path, bitcode, name):
    _, _, text = synthetic_lowered(tmp_path)
    if name == 'function-metadata':
        corrupt = text.replace('section "xdp" {', 'section "xdp" !unproved !999 {') + '\n!999 = !{}\n'
        code = 'MBPF319'
    elif name == 'fixed-stack':
        corrupt = text.replace('  ret i32 2', '  %bad = ' + VALUE + '\n  ret i32 2')
        code = 'MBPF306'
    elif name == 'unaligned-scratch':
        corrupt = text.replace('  %updated =', '  %off = getelementptr i8, ptr %mojobpf.value, i32 1\n'
            '  store i32 7, ptr %off, align 4\n  %updated =')
        code = 'MBPF319'
    else:
        corrupt = text.replace('}\n\nattributes', ''.join(f'extra{i}:\n  ret i32 2\n' for i in range(130)) + '}\n\nattributes', 1)
        code = 'MBPF320'
    assert corrupt != text
    result, report = audit_lowered(tmp_path, corrupt, bitcode=bitcode)
    assert result.returncode == 4 and report['diagnostics'][0]['code'] == code, report


@pytest.mark.parametrize('bitcode',[False,True])
@pytest.mark.parametrize('name,code',[
    ('missing-map','MBPF313'),('helper-prototype','MBPF313'),('flags','MBPF314'),
    ('uninitialized','MBPF314'),('partial-value','MBPF314'),('escaped-scratch','MBPF316'),
    ('collision-license','MBPF309'),('collision-map','MBPF309')])
def test_lower_source_negatives_preserve_inputs_and_existing_output(tmp_path,bitcode,name,code):
    text, request = module(MAP_BODY,DECLS), spec(True)
    if name == 'missing-map': request = spec(False)
    elif name == 'helper-prototype':
        text = text.replace('call i64 @__mojobpf_update_v1','call i32 @__mojobpf_update_v1').replace('declare i64 @__mojobpf_update_v1','declare i32 @__mojobpf_update_v1')
    elif name == 'flags': text = text.replace('ptr %value, i64 0)','ptr %value, i64 1)')
    elif name == 'uninitialized': text = text.replace('  store i64 %sum, ptr %value, align 8\n','')
    elif name == 'partial-value': text = text.replace('  store i64 %sum, ptr %value, align 8','  %narrow = trunc i64 %sum to i32\n  store i32 %narrow, ptr %value, align 4')
    elif name == 'escaped-scratch': text = text.replace('  store i64 %sum, ptr %value, align 8','  %escaped = ptrtoint ptr %value to i64\n  store i64 %escaped, ptr %value, align 8')
    else:
        entry = '_license' if name == 'collision-license' else 'mojobpf_map0'
        text = text.replace('@xdp_entry','@'+entry)
        request = spec(True,entry)
    source = tmp_path/'source.ll'; source.write_text(text)
    if bitcode:
        bc = tmp_path/'source.bc'; checked([llvm_tool('llvm-as'),source,'-o',bc]); source = bc
    original = digest(source)
    output = tmp_path/'lowered.ll'; output.write_bytes(b'existing-output')
    result,report,_ = lower(tmp_path,source,request)
    assert result.returncode == 4 and report is not None and report['ok'] is False
    assert report['diagnostics'][0]['code'] == code, report
    assert digest(source) == original and output.read_bytes() == b'existing-output'


@pytest.mark.parametrize('field,bad', [('key_bits',16),('value_bits',32),('type',1),('max_entries',2),('flags',1)])
def test_mismatched_map_request_is_usage_failure_before_any_output(tmp_path,field,bad):
    source = tmp_path/'source.ll'; source.write_text(module(MAP_BODY,DECLS))
    request = spec(True); request['map'][field] = bad
    output = tmp_path/'lowered.ll'; output.write_bytes(b'existing-output')
    report_path = tmp_path/'lower.report.json'; report_path.write_bytes(b'existing-report')
    request_path = tmp_path/'spec.json'; request_path.write_text(json.dumps(request))
    result = run([lower_tool(),'--mode','lower','--input',source,'--spec',request_path,
                  '--output',output,'--report',report_path])
    assert result.returncode == 2 and 'MBPF202' in result.stderr
    assert output.read_bytes() == b'existing-output' and report_path.read_bytes() == b'existing-report'


@pytest.mark.parametrize('owner',['output','report'])
@pytest.mark.parametrize('input_path',['input','spec'])
@pytest.mark.parametrize('alias',['direct','symlink','hardlink'])
def test_lower_aliases_preserve_captured_input_and_request(tmp_path,owner,input_path,alias):
    source = tmp_path/'source.ll'; source.write_text(module(MAP_BODY,DECLS))
    request = tmp_path/'spec.json'; request.write_text(json.dumps(spec(True)))
    target = source if input_path == 'input' else request
    output, report = tmp_path/'owned.ll', tmp_path/'owned.json'
    link = tmp_path/'alias'
    if alias == 'symlink': link.symlink_to(target)
    elif alias == 'hardlink': os.link(target,link)
    else: link = target
    if owner == 'output': output = link
    else: report = link
    hashes = digest(source),digest(request)
    result = run([lower_tool(),'--mode','lower','--input',source,'--spec',request,'--output',output,'--report',report])
    assert result.returncode == 2 and (digest(source),digest(request)) == hashes


@pytest.mark.parametrize('owner',['output','report'])
@pytest.mark.parametrize('failure',['directory','missing-parent','full'])
def test_lower_write_failures_never_claim_success(tmp_path,owner,failure):
    source = tmp_path/'source.ll'; source.write_text(module(MAP_BODY,DECLS))
    request = tmp_path/'spec.json'; request.write_text(json.dumps(spec(True)))
    output, report = tmp_path/'owned.ll', tmp_path/'owned.json'
    broken = tmp_path/'broken'
    if failure == 'directory': broken.mkdir()
    elif failure == 'missing-parent': broken = tmp_path/'missing'/'file'
    else: broken.symlink_to('/dev/full')
    if owner == 'output': output = broken
    else: report = broken
    original = digest(source),digest(request)
    result = run([lower_tool(),'--mode','lower','--input',source,'--spec',request,'--output',output,'--report',report])
    assert result.returncode == 4 and (digest(source),digest(request)) == original
    assert not (output.exists() and output.is_file()), 'failed operation left a newly claimed output'
    if owner == 'output':
        payload = json.loads(report.read_text())
        assert payload['ok'] is False and payload['diagnostics'][0]['code'] == 'MBPF106'


@pytest.mark.parametrize('bitcode',[False,True])
def test_renaming_and_declaration_order_do_not_select_lowering_algorithm(tmp_path,bitcode):
    text = module(MAP_BODY,DECLS).replace('xdp_entry','other_entry').replace('%key','%fresh').replace('hit','taken')
    text = text.replace(DECLS,'\n'.join(reversed(DECLS.splitlines()))+'\n')
    source = tmp_path/'renamed.ll'; source.write_text(text)
    if bitcode:
        bc = tmp_path/'renamed.bc'; checked([llvm_tool('llvm-as'),source,'-o',bc]); source = bc
    result,report,output = lower(tmp_path,source,spec(True,'other_entry'))
    lower_success(result,report,output)
    assert_conserved(text_ir(source),text_ir(output),report['transformations'],'other_entry')


@pytest.mark.parametrize('bitcode',[False,True])
@pytest.mark.parametrize('predicate',['true','false','scalar'])
def test_post_audit_retains_equal_reachability_phi_taint(tmp_path,bitcode,predicate):
    source = tmp_path/'equal-join.ll'
    source.write_text(equal_reachability_payload(predicate,same_value=True))
    result,report,output = lower(tmp_path,source,spec(True)); lower_success(result,report,output)
    text = text_ir(output)
    accepted,proof = audit_lowered(tmp_path,text,bitcode=bitcode)
    assert accepted.returncode == 0 and proof['ok'] is True
    corrupt = re.sub(r'(phi i64 \[ )7(,.*?\], \[ )7(,)',r'\g<1>1\g<2>0\g<3>',text)
    assert corrupt != text
    refused,proof = audit_lowered(tmp_path,corrupt,bitcode=bitcode)
    assert refused.returncode == 4 and proof['diagnostics'][0]['code'] == 'MBPF316', proof


@pytest.mark.parametrize('bitcode',[False,True])
@pytest.mark.parametrize('root',['map','scratch'])
@pytest.mark.parametrize('offset,bits,alignment,expected',[(1,32,4,'MBPF319'),(2,32,4,'MBPF319'),(4,32,4,'accept'),(1,8,1,'accept'),(2,8,1,'accept')])
def test_post_audit_proves_root_plus_offset_alignment(tmp_path,bitcode,root,offset,bits,alignment,expected):
    _,_,text = synthetic_lowered(tmp_path)
    pointer = '%ptr' if root == 'map' else '%mojobpf.value'
    corrupt = text.replace('  %updated =',f'  %postoff = getelementptr i8, ptr {pointer}, i32 {offset}\n'
                           f'  store i{bits} 7, ptr %postoff, align {alignment}\n  %updated =')
    result,proof = audit_lowered(tmp_path,corrupt,bitcode=bitcode)
    if expected == 'accept': assert result.returncode == 0 and proof['ok'] is True, proof
    else: assert result.returncode == 4 and proof['diagnostics'][0]['code'] == expected, proof


@pytest.mark.parametrize('bitcode',[False,True])
@pytest.mark.parametrize('extra',['splitDebugFilename: "forged.dwo"','debugInfoForProfiling: true','dwoId: 1'])
def test_post_audit_refuses_unproduced_compile_unit_options(tmp_path,bitcode,extra):
    _,_,text = synthetic_lowered(tmp_path)
    corrupt = text.replace('emissionKind: FullDebug, globals:',f'emissionKind: FullDebug, {extra}, globals:')
    assert corrupt != text
    result,proof = audit_lowered(tmp_path,corrupt,bitcode=bitcode)
    assert result.returncode == 4 and proof['diagnostics'][0]['code'] == 'MBPF319', proof


@pytest.mark.parametrize('bitcode',[False,True])
def test_post_audit_refuses_unproduced_type_graph_properties(tmp_path,bitcode):
    _,_,text = synthetic_lowered(tmp_path)
    corrupt = text.replace('name: "mojobpf_array_map",','name: "mojobpf_array_map", identifier: "forged-type",')
    assert corrupt != text
    result,proof = audit_lowered(tmp_path,corrupt,bitcode=bitcode)
    assert result.returncode == 4 and proof['diagnostics'][0]['code'] == 'MBPF319', proof
