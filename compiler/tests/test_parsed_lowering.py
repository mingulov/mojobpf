# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Real-source lowering and independent conservation/semantic controls.

All captures use the admitted Mojo producer. These are local compiler
checks; none load a BPF program or establish kernel runtime qualification.
"""
import json
import os
from pathlib import Path
import re
import resource
import shlex
import shutil

import pytest

from test_target_model import (ROOT, MAP_BODY, DECLS, capture, checked, digest,
                               llvm_tool, lower_tool, module, run, spec,
                               refusal)

from test_target_model import VALUE
from test_target_model import equal_reachability_payload
from test_target_model import ATTRS, LAYOUT

SOURCES = [
    ('examples/xdp_pass/xdp_pass.mojo', False),
    ('examples/xdp_pass/xdp_pass_mutated.mojo', False),
    ('tests/compile/map_roundtrip.mojo', True),
    ('tests/compile/map_roundtrip_mutated.mojo', True),
]


def lower(tmp_path, source, request, *, emit='llvm', permissive=False):
    request_path = tmp_path / 'spec.json'
    request_path.write_text(json.dumps(request))
    output = tmp_path / ('lowered.bc' if emit == 'bitcode' else 'lowered.ll')
    report_path = tmp_path / 'lower.report.json'
    argv = [lower_tool(), '--mode', 'lower', '--input', source,
           '--spec', request_path, '--report', report_path,
           '--output', output, '--emit', emit]
    if permissive:
        argv.append('--permissive-proof')
    result = run(argv)
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


# max_entries admits any positive count (dense keys 0..N-1);
# only 0 (and non-integers) are usage failures. Real map
# types flip per kind commit (T4a-3), so the bad type pins a
# value no kind ever takes.
@pytest.mark.parametrize('field,bad', [('key_bits',16),('value_bits',32),('type',99),('max_entries',0),('flags',1)])
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


# A real native caller, linked to the same library as the actual lower tool.
# Serialized equality must not permit stale primitive/helper/cache pointers.
IDENTITY_CALLER = r'''
#include "mojobpf/Lowering.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/SourceMgr.h"
using namespace llvm;
std::string bytes(const Module &M) {
  std::string S; raw_string_ostream OS(S); WriteBitcodeToFile(M, OS); return S;
}
int main(int argc, char **argv) {
  if (argc != 6) return 2;
  LLVMContext C; SMDiagnostic D;
  auto M = parseIRFile(argv[1], D, C); if (!M) return 3;
  auto S = mojobpf::readLoweringSpec(R"({"schema_version":1,"model_id":"mojo-1.1.0-x86_64-bpfel-v3-minimal-v1","profile_id":"linux-bpfel-v3","entry":"xdp_entry","program_type":"xdp","section":"xdp","kernel_license":"Apache-2.0 WITH LLVM-exception","map":{"symbol":"mojobpf_map0","type":2,"key_bits":32,"value_bits":64,"max_entries":1,"flags":0}})");
  if (!S) return 4;
  auto F = mojobpf::inspectTargetModel(*M, *S); if (!F) return 5;
  auto P = mojobpf::auditSource(*M, *S, *F); if (!P) return 6;
  StringRef Phase = argv[2], Binding = argv[3], Lifetime = argv[4], Operation = argv[5];
  if (Phase == "pending") {
    if (auto E = mojobpf::lowerPrimitivesAndHelpers(*P)) {
      errs() << toString(std::move(E)); return 7;
    }
  }
  std::vector<Instruction *> Selected;
  auto Add = [&](const Value *V) {
    auto *I = dyn_cast<Instruction>(const_cast<Value *>(V));
    if (I && !is_contained(Selected, I)) Selected.push_back(I);
  };
  unsigned Primitives = P->primitives().size(), Helpers = P->helpers().size();
  unsigned Cells = P->scratch().Cells.size(), Inert = P->scratch().InertCalls.size();
  unsigned KeyUses = P->keyUses().size();
  if (Binding != "pristine" && Phase == "source") {
    for (const auto &B : P->primitives()) {
      if (Binding == "all" ||
          (Binding == "key" && B.Kind == mojobpf::PrimitiveKind::Key) ||
          (Binding == "value" && B.Kind == mojobpf::PrimitiveKind::Value) ||
          (Binding == "map" && B.Kind == mojobpf::PrimitiveKind::Map) ||
          (Binding == "reinterpret" && B.Kind == mojobpf::PrimitiveKind::Reinterpret)) Add(B.Call);
    }
    for (const auto *Call : P->helpers())
      if (Binding == "all" || (Binding == "lookup" && Call->arg_size() == 2) ||
          (Binding == "update" && Call->arg_size() == 4)) Add(Call);
    if (Binding == "all") {
      for (const auto &Cell : P->scratch().Cells) Add(Cell.first);
      for (const auto *Call : P->scratch().InertCalls) Add(Call);
      for (const auto &Use : P->keyUses()) {
        Add(Use.Call); Add(Use.Buffer); Add(Use.Preparation);
      }
    }
  } else if (Binding != "pristine" && Phase == "pending") {
    for (BasicBlock &BB : *M->getFunction(S->Entry)) for (Instruction &I : BB) {
      if (Binding == "all") Add(&I);
      if (auto *A = dyn_cast<AllocaInst>(&I)) {
        if ((Binding == "key-cell" && A->getAllocatedType()->isIntegerTy(32)) ||
            (Binding == "value-cell" && A->getAllocatedType()->isIntegerTy(64))) Add(A);
      } else if (auto *Store = dyn_cast<StoreInst>(&I)) {
        if ((Binding == "key-store" && Store->getValueOperand()->getType()->isIntegerTy(32)) ||
            (Binding == "value-store" && Store->getValueOperand()->getType()->isIntegerTy(64))) Add(Store);
      } else if (auto *Call = dyn_cast<CallInst>(&I)) {
        auto *CE = dyn_cast<ConstantExpr>(Call->getCalledOperand());
        auto *ID = CE ? dyn_cast<ConstantInt>(CE->getOperand(0)) : nullptr;
        if (ID && ((Binding == "lookup" && ID->equalsInt(1)) ||
                   (Binding == "update" && ID->equalsInt(2)))) Add(Call);
        if (Binding == "reinterpret" && Call->isInlineAsm()) Add(Call);
      }
    }
  }
  if (Binding != "pristine" && Selected.empty()) return 8;
  std::string Before = bytes(*M);
  std::vector<Instruction *> Detached;
  for (Instruction *Old : Selected) {
    auto *New = Old->clone(); New->insertBefore(Old->getIterator()); New->takeName(Old);
    Old->replaceAllUsesWith(New);
    if (Lifetime == "alive") {
      Old->removeFromParent();
      // A detached node must not remain a user of live module instructions.
      // Keep its object alive while removing those detached-only references.
      Old->dropAllReferences(); Detached.push_back(Old);
    }
    else Old->eraseFromParent();
  }
  std::string Replaced = bytes(*M);
  bool Verified = !verifyModule(*M, &errs());
  Error E = Operation == "guard" ? P->requireUnchangedSource() :
      Phase == "source" ? mojobpf::lowerPrimitivesAndHelpers(*P) : mojobpf::emitMapMetadata(*P);
  bool Accepted = !E;
  auto Diagnostics = mojobpf::takeDiagnostics(std::move(E));
  bool Unmutated = bytes(*M) == Replaced;
  bool Expected = Binding == "pristine";
  bool Typed = !Diagnostics.empty() && *Diagnostics.front().getAsObject()->getString("code") == "MBPF319";
  if (Expected && Accepted && Operation != "guard") {
    if (Phase == "source") {
      if (auto E2 = mojobpf::emitMapMetadata(*P)) { errs() << toString(std::move(E2)); return 9; }
    }
    if (auto E2 = mojobpf::auditLowered(*M, *S, *F)) { errs() << toString(std::move(E2)); return 10; }
  }
  bool Passed = Verified && Before == Replaced && (Expected ? Accepted : !Accepted && Typed && Unmutated);
  json::Object Data{{"phase", Phase.str()}, {"binding", Binding.str()}, {"lifetime", Lifetime.str()},
      {"operation", Operation.str()}, {"serialized_equal", Before == Replaced}, {"llvm_valid", Verified},
      {"accepted", Accepted}, {"unchanged_on_refusal", Unmutated}, {"diagnostics", std::move(Diagnostics)},
      {"selected_identities", int64_t(Selected.size())}, {"cached_primitives", int64_t(Primitives)},
      {"cached_helpers", int64_t(Helpers)}, {"cached_scratch", int64_t(Cells)}, {"cached_inert", int64_t(Inert)},
      {"cached_key_uses", int64_t(KeyUses)}, {"passed", Passed}, {"runtime_qualified", false}};
  outs() << formatv("{0:2}\n", json::Value(std::move(Data)));
  for (Instruction *Old : Detached) Old->deleteValue();
  return 0;
}
'''


@pytest.fixture(scope='session')
def identity_caller(tmp_path_factory):
    directory = tmp_path_factory.mktemp('native-identity-caller')
    source, executable = directory/'identity.cpp', directory/'identity-caller'
    source.write_text(IDENTITY_CALLER)
    config = os.environ.get('MOJOBPF_LLVM_CONFIG') or shutil.which('llvm-config')
    flags = shlex.split(checked([config, '--cxxflags']).stdout)
    link = shlex.split(checked([config, '--ldflags', '--system-libs', '--libs']).stdout)
    clang = llvm_tool('clang').with_name('clang++')
    build = lower_tool().parent
    # A baseline replay must use that library's own header layout, not a
    # repaired private class layout from the current source checkout.
    cache = (build/'CMakeCache.txt').read_text()
    home = re.search(r'^CMAKE_HOME_DIRECTORY:INTERNAL=(.+)$',cache,re.M)
    assert home, 'native caller requires the actual library build metadata'
    include = Path(home[1])/'include'
    checked([clang, '-x', 'c++', *flags, '-std=c++17', '-I', include, source,
             '-x', 'none', build/'libmojobpf-compiler.a', *link, '-o', executable])
    return executable


IDENTITY_CASES = ([('source', binding, operation) for binding in
    ('key', 'value', 'map', 'reinterpret', 'lookup', 'update', 'all') for operation in ('guard', 'lower')]
    + [('pending', binding, 'metadata') for binding in
       ('key-cell', 'value-cell', 'key-store', 'value-store', 'lookup', 'update', 'reinterpret', 'all')])


@pytest.mark.parametrize('frontend_emit', ['llvm', 'llvm-bitcode'])
@pytest.mark.parametrize('lifetime', ['alive', 'erased'])
def test_native_byte_identical_replacement_refuses_before_mutation(tmp_path,identity_caller,frontend_emit,lifetime,subtests):
    raw = capture(tmp_path,ROOT/'tests/compile/map_roundtrip.mojo',frontend_emit)
    original = digest(raw)
    for phase,binding,operation in IDENTITY_CASES:
        with subtests.test(phase=phase,binding=binding,operation=operation):
            def no_core(): resource.setrlimit(resource.RLIMIT_CORE,(0,0))
            result = run([identity_caller,raw,phase,binding,lifetime,operation],preexec_fn=no_core)
            assert result.returncode == 0, result.stdout + result.stderr
            proof = json.loads(result.stdout)
            assert proof['llvm_valid'] and proof['serialized_equal'], proof
            assert proof['passed'] and proof['unchanged_on_refusal'] and not proof['accepted'], proof
            assert proof['diagnostics'][0]['code'] == 'MBPF319', proof
            if phase == 'source':
                assert all(proof[key] > 0 for key in ('cached_primitives','cached_helpers','cached_scratch','cached_inert','cached_key_uses'))
            else:
                assert all(proof[key] == 0 for key in ('cached_primitives','cached_helpers','cached_scratch','cached_inert','cached_key_uses'))
    assert digest(raw) == original


@pytest.mark.parametrize('frontend_emit', ['llvm', 'llvm-bitcode'])
@pytest.mark.parametrize('phase', ['source', 'pending'])
def test_native_genuine_map_pristine_transitions_remain_valid(tmp_path,identity_caller,frontend_emit,phase):
    raw = capture(tmp_path,ROOT/'tests/compile/map_roundtrip.mojo',frontend_emit)
    result = run([identity_caller,raw,phase,'pristine','alive','lower' if phase=='source' else 'metadata'])
    assert result.returncode == 0, result.stdout + result.stderr
    proof = json.loads(result.stdout)
    assert proof['passed'] and proof['accepted'] and proof['diagnostics'] == [], proof


# ---------------------------------------------------------------------------
# Subprogram (BPF-to-BPF call) slice.
# ---------------------------------------------------------------------------

SUBPROG_PROFILE = 'linux-bpfel-v3-subprog'

SUBPROG_SOURCES = [
    ('examples/subprog_call/decision.mojo', 'decide'),
    ('tests/compile/subprog_entry_first.mojo', 'classify'),
]

SUBPROG_ATTEMPTS = [
    ('tests/compile/subprog_recursion_attempt.mojo', 'MBPF312'),
    ('tests/compile/subprog_multi_attempt.mojo', 'MBPF309'),
    ('tests/compile/subprog_arity_attempt.mojo', 'MBPF302'),
    ('tests/compile/subprog_narrow_attempt.mojo', 'MBPF302'),
    ('tests/compile/subprog_trace_attempt.mojo', 'MBPF302'),
    ('tests/compile/subprog_map_attempt.mojo', 'MBPF313'),
]

CALLEE_BODY = '''entry:
  %r = and i64 %n, 1
  %c = icmp eq i64 %r, 1
  %s = select i1 %c, i64 1, i64 2
  ret i64 %s
'''

ENTRY_CALL_BODY = '''entry:
  %v = tail call i64 @decide(i64 7)
  %t = trunc i64 %v to i32
  ret i32 %t
'''


def subprog_spec(entry='xdp_entry'):
    return spec(profile=SUBPROG_PROFILE, entry=entry)


def subprog_module(callee_body, entry_body, *, order='callee-first',
                   callee_name='decide', callee_sig='i64',
                   callee_param='i64 noundef %n', callee_marker='noinline ',
                   entry_marker='',
                   entry_header='i32 @xdp_entry(ptr noundef %ctx)',
                   extra_defines=''):
    if order == 'callee-first':
        callee_index, entry_index = 0, 1
        first, second = 'callee', 'entry'
    else:
        callee_index, entry_index = 1, 0
        first, second = 'entry', 'callee'
    callee_define = ('define dso_local %s @%s(%s) #%d {\n%s}\n'
                     % (callee_sig, callee_name, callee_param,
                        callee_index, callee_body))
    entry_define = ('define dso_local %s #%d {\n%s}\n'
                    % (entry_header, entry_index, entry_body))
    defines = {'callee': callee_define, 'entry': entry_define}
    text = ('target datalayout = "%s"\ntarget triple = "x86_64-unknown-linux-gnu"\n'
            % LAYOUT)
    text += defines[first] + extra_defines + defines[second]
    for index, marker in ((callee_index, callee_marker),
                          (entry_index, entry_marker)):
        text += ATTRS.replace('attributes #0', 'attributes #%d' % index, 1)
        if marker:
            text = text.replace('attributes #%d = { ' % index,
                                'attributes #%d = { %s' % (index, marker), 1)
    text += ('!llvm.module.flags = !{!0}\n'
             '!0 = !{i32 2, !"Debug Info Version", i32 3}\n')
    return text


@pytest.mark.parametrize('source,callee', SUBPROG_SOURCES)
@pytest.mark.parametrize('frontend_emit', ['llvm', 'llvm-bitcode'])
def test_genuine_subprog_source_lowers(tmp_path, source, callee, frontend_emit):
    raw = capture(tmp_path, ROOT/source, frontend_emit)
    result, report, output = lower(tmp_path, raw, subprog_spec())
    lower_success(result, report, output)
    assert_conserved(text_ir(raw), text_ir(output), report['transformations'])
    rows = [row for row in report['transformations'] if row['kind'] == 'subprog']
    assert len(rows) == 1 and rows[0]['callee'] == callee, report['transformations']


@pytest.mark.parametrize('source,code', SUBPROG_ATTEMPTS)
def test_genuine_subprog_attempt_refused(tmp_path, source, code):
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, output = lower(tmp_path, raw, subprog_spec())
    refusal(result, report, code)


@pytest.mark.parametrize('order', ['callee-first', 'entry-first'])
def test_subprog_call_shape_lowers(tmp_path, order):
    source = tmp_path/'input.ll'
    source.write_text(subprog_module(CALLEE_BODY, ENTRY_CALL_BODY, order=order))
    result, report, output = lower(tmp_path, source, subprog_spec())
    lower_success(result, report, output)
    assert_conserved(text_ir(source), text_ir(output), report['transformations'])


def test_subprog_base_profile_refuses_extra_definition(tmp_path):
    source = tmp_path/'input.ll'
    source.write_text(subprog_module(CALLEE_BODY, ENTRY_CALL_BODY))
    result, report, output = lower(tmp_path, source, spec())
    refusal(result, report, 'MBPF309')


@pytest.mark.parametrize('body,code', [
    ('entry:\n  %r = tail call i64 @decide(i64 %n)\n  ret i64 %r\n', 'MBPF312'),
    ('entry:\n  %r = load i64, ptr null, align 8\n  ret i64 %r\n', 'MBPF303'),
    ('entry:\n  store i64 %n, ptr null, align 8\n  ret i64 0\n', 'MBPF316'),
    ('entry:\n  %r = add i64 %n, 1\n  ret i64 %r\n', None),
])
def test_subprog_callee_body_envelope(tmp_path, body, code):
    source = tmp_path/'input.ll'
    source.write_text(subprog_module(body, ENTRY_CALL_BODY))
    result, report, output = lower(tmp_path, source, subprog_spec())
    if code is None:
        lower_success(result, report, output)
    else:
        refusal(result, report, code)


@pytest.mark.parametrize('entry_body,code', [
    ('entry:\n  %v = call i64 @decide(i64 7)\n  %t = trunc i64 %v to i32\n  ret i32 %t\n', 'MBPF306'),
    ('entry:\n  %v = tail call i64 @decide(i64 7) [ "deopt" (i32 0) ]\n  %t = trunc i64 %v to i32\n  ret i32 %t\n', 'MBPF306'),
    # Call attributes die at the inspector (first layer), not the
    # call-form check: only NoUndef off the function slot survives.
    ('entry:\n  %v = tail call i64 @decide(i64 7) nounwind\n  %t = trunc i64 %v to i32\n  ret i32 %t\n', 'MBPF319'),
    ('entry:\n  ret i32 2\n', 'MBPF307'),
])
def test_subprog_call_sites_checked(tmp_path, entry_body, code):
    # Note: arg-count/type mismatches and musttail never reach the
    # audit: LLVM verification owns them (MBPF106) before any check.
    source = tmp_path/'input.ll'
    source.write_text(subprog_module(CALLEE_BODY, entry_body))
    result, report, output = lower(tmp_path, source, subprog_spec())
    refusal(result, report, code)


ARITY_CALL_BODY = '''entry:
  %v = tail call i64 @decide(i64 7, i64 8)
  %t = trunc i64 %v to i32
  ret i32 %t
'''

NARROW_CALL_BODY = '''entry:
  %v = tail call i32 @decide(i32 7)
  ret i32 %v
'''

RESERVED_CALL_BODY = '''entry:
  %v = tail call i64 @__mojobpf_lookup_v1(i64 7)
  %t = trunc i64 %v to i32
  ret i32 %t
'''


@pytest.mark.parametrize('kwargs,entry_body,callee_body,code', [
    ({'callee_marker': ''}, ENTRY_CALL_BODY, CALLEE_BODY, 'MBPF302'),
    ({'entry_marker': 'noinline '}, ENTRY_CALL_BODY, CALLEE_BODY, 'MBPF302'),
    ({'callee_name': '__mojobpf_lookup_v1'}, RESERVED_CALL_BODY, CALLEE_BODY, 'MBPF303'),
    ({'callee_param': 'i64 noundef %a, i64 noundef %b'}, ARITY_CALL_BODY,
     'entry:\n  %r = add i64 %a, %b\n  ret i64 %r\n', 'MBPF302'),
    ({'callee_sig': 'i32', 'callee_param': 'i32 noundef %n'}, NARROW_CALL_BODY,
     'entry:\n  %r = and i32 %n, 1\n  ret i32 %r\n', 'MBPF302'),
])
def test_subprog_callee_contract(tmp_path, kwargs, entry_body, callee_body, code):
    source = tmp_path/'input.ll'
    source.write_text(subprog_module(callee_body, entry_body, **kwargs))
    result, report, output = lower(tmp_path, source, subprog_spec())
    refusal(result, report, code)


def test_subprog_second_definition_refused(tmp_path):
    source = tmp_path/'input.ll'
    extra = ('define dso_local i64 @second(i64 noundef %n) #0 {\n'
             'entry:\n  ret i64 %n\n}\n')
    source.write_text(subprog_module(CALLEE_BODY, ENTRY_CALL_BODY, extra_defines=extra))
    result, report, output = lower(tmp_path, source, subprog_spec())
    refusal(result, report, 'MBPF309')


def test_lowered_retention_matches_lane_a_emission(tmp_path):
    # The parsed object must be what the qualified Lane-A route
    # emits: license dso_local, llvm.compiler.used (never
    # llvm.used, whose GNU-RETAIN flag perturbs section flags and
    # the EI_OSABI byte), operands [license, entry].
    source = tmp_path/'input.ll'
    source.write_text(subprog_module(CALLEE_BODY, ENTRY_CALL_BODY))
    result, report, output = lower(tmp_path, source, subprog_spec())
    lower_success(result, report, output)
    text = text_ir(output)
    assert '@llvm.used = ' not in text, text
    assert '@_license = dso_local global ' in text, text
    assert ('@llvm.compiler.used = appending global [2 x ptr] '
            '[ptr @_license, ptr @xdp_entry]') in text, text


# ---------------------------------------------------------------------------
# T4a-1 permissive proof + tc family.
#
# Lane-A positives the strict proof cannot establish lower in
# permissive mode: the property is recorded as an unproved
# obligation (kept distinct from proof diagnostics), and the
# emission mirrors Lane-A byte for byte (pins live in
# test_parsed_elf). The strict proof keeps refusing each gap:
# permissive mode obligates, it never weakens the proof.
# ---------------------------------------------------------------------------

PERMISSIVE_GAPS = [
    ('tests/compile/packet_unguarded.mojo', 'MBPF314'),
    ('tests/compile/packet_var_offset.mojo', 'MBPF311'),
    ('tests/compile/parse_trunc.mojo', 'MBPF317'),
    ('tests/compile/scalar_addr_edge.mojo', 'MBPF311'),
]

TC_PROFILE = 'linux-bpfel-v3-net'

TC_SOURCES = [
    'examples/tc_classifier/tc.mojo',
    'examples/tc_classifier/tc_mutated.mojo',
]


def tc_spec():
    request = spec()
    request.update({'profile_id': TC_PROFILE, 'entry': 'tc_entry',
                    'program_type': 'tc', 'section': 'classifier'})
    return request


@pytest.mark.parametrize('source,code', PERMISSIVE_GAPS)
def test_strict_proof_refuses_gap(tmp_path, source, code):
    # Regression guard for proof strength: the strict proof still
    # refuses each Lane-A positive it cannot establish, with the
    # diagnosed code.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, _output = lower(tmp_path, raw, spec())
    refusal(result, report, code)


@pytest.mark.parametrize('source,code', PERMISSIVE_GAPS)
def test_permissive_lowering_obligates_gap(tmp_path, source, code):
    # Permissive proof obligates the unproved property, emits the
    # Lane-A-identical module, and records every obligation with
    # its proof code and a warning severity.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, output = lower(tmp_path, raw, spec(), permissive=True)
    lower_success(result, report, output)
    unproved = report.get('unproved')
    assert isinstance(unproved, list) and unproved, report
    assert report.get('unproved_total', 0) >= len(unproved), report
    assert code in {entry['code'] for entry in unproved}, (source, unproved)
    for entry in unproved:
        assert set(entry) == {'code', 'stage', 'severity', 'explanation',
                              'location', 'remedy'}, entry
        assert entry['severity'] == 'warning', entry
        assert entry['explanation'] and entry['location'], entry
        assert entry['remedy'], entry


CLASSIFIER_PREAMBLE = '''entry:
  %2 = load i32, ptr %0, align 4
  %3 = zext i32 %2 to i64
  %4 = getelementptr inbounds i32, ptr %0, i32 1
  %5 = load i32, ptr %4, align 4
  %6 = add i64 %3, 15
  %7 = zext i32 %5 to i64
  %8 = icmp ugt i64 %6, %7
  br i1 %8, label %early, label %check
'''

DYNAMIC_OFFSET_BODY = CLASSIFIER_PREAMBLE + '''early:
  br label %join
check:
  %p = call ptr asm "", "=r,0"(i64 %3)
  %q = getelementptr inbounds i8, ptr %p, i64 %3
  %b = load i8, ptr %q, align 1
  %t = icmp eq i8 %b, 1
  %a = select i1 %t, i32 1, i32 2
  br label %join
join:
  %r = phi i32 [ 2, %early ], [ %a, %check ]
  ret i32 %r
'''

ESCAPED_LOAD_BODY = CLASSIFIER_PREAMBLE + '''early:
  %p0 = call ptr asm "", "=r,0"(i64 %3)
  br label %join
check:
  %p1 = call ptr asm "", "=r,0"(i64 %3)
  br label %join
join:
  %phi = phi ptr [ %p0, %early ], [ %p1, %check ]
  %b = load i8, ptr %phi, align 1
  %t = icmp eq i8 %b, 1
  %a = select i1 %t, i32 1, i32 2
  ret i32 %a
'''


def classifier_fixture(body):
    return module(body, header='dso_local i32 @xdp_entry(ptr noundef %0)')


def test_dynamic_offset_strict_refuses(tmp_path):
    source = tmp_path/'input.ll'
    source.write_text(classifier_fixture(DYNAMIC_OFFSET_BODY))
    result, report, _output = lower(tmp_path, source, spec())
    refusal(result, report, 'MBPF317')


def test_dynamic_offset_refuses_in_both_modes(tmp_path):
    # Boundary pin: dynamic GEP offsets refuse even in permissive
    # mode. The target-model pre-check owns dynamic offsets (it
    # must establish the measured offset facts), so the walker's
    # downgrade sites never see them.
    source = tmp_path/'input.ll'
    source.write_text(classifier_fixture(DYNAMIC_OFFSET_BODY))
    result, report, _output = lower(tmp_path, source, spec(), permissive=True)
    refusal(result, report, 'MBPF317')


def test_escaped_load_strict_refuses(tmp_path):
    source = tmp_path/'input.ll'
    source.write_text(classifier_fixture(ESCAPED_LOAD_BODY))
    result, report, _output = lower(tmp_path, source, spec())
    refusal(result, report, 'MBPF311')


def test_escaped_load_permissive_obligates(tmp_path):
    source = tmp_path/'input.ll'
    source.write_text(classifier_fixture(ESCAPED_LOAD_BODY))
    result, report, output = lower(tmp_path, source, spec(), permissive=True)
    lower_success(result, report, output)
    unproved = report.get('unproved')
    assert [entry['code'] for entry in unproved] == ['MBPF311'], unproved
    assert report.get('unproved_total') == 1, report


def test_check_target_rejects_permissive_flag(tmp_path):
    # The flag downgrades lowering only; the proof gate stays
    # strict and says so instead of silently ignoring the flag.
    source = tmp_path/'input.ll'
    source.write_text(classifier_fixture(DYNAMIC_OFFSET_BODY))
    request_path = tmp_path/'spec.json'
    request_path.write_text(json.dumps(spec()))
    report_path = tmp_path/'report.json'
    result = run([lower_tool(), '--mode', 'check-target', '--input', source,
                  '--spec', request_path, '--report', report_path,
                  '--permissive-proof'])
    assert result.returncode == 2, result.stdout + result.stderr
    assert 'MBPF202' in result.stderr, result.stderr
    assert not report_path.exists(), 'usage failure must not write a report'


# ---------------------------------------------------------------------------
# T4a-2 map core (array pairs + deletes).
#
# Array read-modify-write pairs over dense keys 0..N-1 and array
# deletions lower under the strict proof with no obligations. Kernel
# negatives (shapes the kernel verifier decides: unchecked
# dereference, out-of-bounds value access) refuse strict and
# obligate+emit under permissive proof, so both routes publish an
# object and the kernel remains the decider (R1-T2 version gates
# apply to both routes' guest verdicts). Tagged kinds (hash, percpu,
# LRU) and the combined workload stay Lane-A: they refuse here in
# both modes.
# ---------------------------------------------------------------------------

MAP_PAIR_SOURCES = [
    ('tests/compile/maps_rmw2.mojo', 2),
    ('tests/compile/maps_rmw3.mojo', 3),
    ('tests/compile/maps_rmw4.mojo', 4),
]

MAP_DELETE_SOURCES = [
    ('tests/compile/maps_delete1.mojo', 1),
    ('tests/compile/maps_delete2.mojo', 2),
    ('tests/compile/maps_delete3.mojo', 3),
    ('tests/compile/maps_delete4.mojo', 4),
]

MAP_KERNEL_NEGATIVES = [
    ('tests/compile/map_unchecked.mojo', 'MBPF314'),
    ('tests/compile/map_oob.mojo', 'MBPF314'),
    ('tests/compile/subset/subset_oob_store.mojo', 'MBPF314'),
]

MAP_TAGGED_SOURCES = [
    'tests/compile/percpu_combined.mojo',
]

HASH_PAIR_SOURCES = [
    ('tests/compile/hash_rmw1.mojo', 1),
    ('tests/compile/hash_rmw2.mojo', 2),
    ('tests/compile/hash_rmw3.mojo', 3),
    ('tests/compile/hash_rmw4.mojo', 4),
]

HASH_DELETE_SOURCES = [
    ('tests/compile/hash_delete1.mojo', 1),
    ('tests/compile/hash_delete2.mojo', 2),
    ('tests/compile/hash_delete3.mojo', 3),
    ('tests/compile/hash_delete4.mojo', 4),
]

HASH_KERNEL_NEGATIVES = [
    ('tests/compile/hash_unchecked.mojo', 'MBPF314'),
    ('tests/compile/hash_oob.mojo', 'MBPF314'),
]


def map_spec(entries=1):
    request = spec(has_map=True)
    request['map'] = dict(request['map'], max_entries=entries)
    return request


@pytest.mark.parametrize('source,entries', MAP_PAIR_SOURCES)
def test_map_multi_pair_lowers_strict(tmp_path, source, entries):
    # Dense keys 0..N-1 lower under the strict proof: a proof
    # extension over the single-pair slice, not a downgrade.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, output = lower(tmp_path, raw, map_spec(entries))
    lower_success(result, report, output)
    assert report.get('unproved', []) == [], report
    assert report.get('unproved_total', 0) == 0, report


@pytest.mark.parametrize('source,entries', MAP_DELETE_SOURCES)
def test_map_delete_lowers_strict(tmp_path, source, entries):
    # Array deletions over dense keys lower under the strict
    # proof with the delete helper call lowered.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, output = lower(tmp_path, raw, map_spec(entries))
    lower_success(result, report, output)
    assert report.get('unproved', []) == [], report
    assert report.get('unproved_total', 0) == 0, report
    assert 'inttoptr (i64 3 to ptr)' in output.read_text(), 'delete call not lowered'


@pytest.mark.parametrize('source,code', MAP_KERNEL_NEGATIVES)
def test_map_kernel_negative_strict_refuses(tmp_path, source, code):
    # Regression guard for proof strength: the strict proof still
    # refuses each kernel-negative shape with the diagnosed code.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, _output = lower(tmp_path, raw, map_spec())
    refusal(result, report, code)


@pytest.mark.parametrize('source,code', MAP_KERNEL_NEGATIVES)
def test_map_kernel_negative_permissive_obligates(tmp_path, source, code):
    # Kernel negatives obligate+emit under permissive proof: the
    # build publishes an object (like Lane-A) so the kernel
    # verifier remains the decider, and the unproved property is
    # recorded with its proof code and a warning severity.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, output = lower(tmp_path, raw, map_spec(), permissive=True)
    lower_success(result, report, output)
    unproved = report.get('unproved')
    assert isinstance(unproved, list) and unproved, report
    assert report.get('unproved_total', 0) >= len(unproved), report
    assert code in {entry['code'] for entry in unproved}, (source, unproved)
    for entry in unproved:
        assert set(entry) == {'code', 'stage', 'severity', 'explanation',
                              'location', 'remedy'}, entry
        assert entry['severity'] == 'warning', entry
        assert entry['explanation'] and entry['location'], entry
        assert entry['remedy'], entry


@pytest.mark.parametrize('source', MAP_TAGGED_SOURCES)
def test_map_tagged_kind_refuses_both_modes(tmp_path, source):
    # Boundary pin: the combined workload refuses under the
    # array contract (cross-kind, MBPF314). Under its own
    # percpu contract it lowers (the length rule admits
    # same-origin end-minus-data as Scalar): covered by the
    # combined positives below. Hash, LRU, and percpu flipped
    # to the parsed slice below.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, _output = lower(tmp_path, raw, map_spec())
    refusal(result, report, 'MBPF314')
    result, report, _output = lower(tmp_path, raw, map_spec(), permissive=True)
    refusal(result, report, 'MBPF314')


# ---------------------------------------------------------------------------
# T4a-3 hash kind.
#
# Hash read-modify-write pairs over dense keys 0..N-1 and hash
# deletions are structurally identical to the array slice
# modulo the hash tag on each map address and the map type
# bound: they lower under the strict proof with no
# obligations. Hash kernel negatives mirror the array M4/M5
# shapes (same strict codes, same permissive obligations).
# ---------------------------------------------------------------------------

def hash_spec(entries=1):
    request = spec(has_map=True)
    request['map'] = dict(request['map'], type=1, max_entries=entries)
    return request


@pytest.mark.parametrize('source,entries', HASH_PAIR_SOURCES)
def test_hash_pair_lowers_strict(tmp_path, source, entries):
    # Dense-keyed hash pairs lower under the strict proof: the
    # tag marks the map operand's kind, the multiplicity rule
    # is unchanged.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, output = lower(tmp_path, raw, hash_spec(entries))
    lower_success(result, report, output)
    assert report.get('unproved', []) == [], report
    assert report.get('unproved_total', 0) == 0, report


@pytest.mark.parametrize('source,entries', HASH_DELETE_SOURCES)
def test_hash_delete_lowers_strict(tmp_path, source, entries):
    # Hash deletions over dense keys lower under the strict
    # proof with the delete helper call lowered.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, output = lower(tmp_path, raw, hash_spec(entries))
    lower_success(result, report, output)
    assert report.get('unproved', []) == [], report
    assert report.get('unproved_total', 0) == 0, report
    assert 'inttoptr (i64 3 to ptr)' in output.read_text(), 'delete call not lowered'


@pytest.mark.parametrize('source,code', HASH_KERNEL_NEGATIVES)
def test_hash_kernel_negative_strict_refuses(tmp_path, source, code):
    # Regression guard for proof strength: the strict proof
    # still refuses each hash kernel-negative shape with the
    # diagnosed code.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, _output = lower(tmp_path, raw, hash_spec())
    refusal(result, report, code)


@pytest.mark.parametrize('source,code', HASH_KERNEL_NEGATIVES)
def test_hash_kernel_negative_permissive_obligates(tmp_path, source, code):
    # Hash kernel negatives obligate+emit under permissive
    # proof, mirroring the array M4/M5 shapes.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, output = lower(tmp_path, raw, hash_spec(), permissive=True)
    lower_success(result, report, output)
    unproved = report.get('unproved')
    assert isinstance(unproved, list) and unproved, report
    assert report.get('unproved_total', 0) >= len(unproved), report
    assert code in {entry['code'] for entry in unproved}, (source, unproved)
    for entry in unproved:
        assert set(entry) == {'code', 'stage', 'severity', 'explanation',
                              'location', 'remedy'}, entry
        assert entry['severity'] == 'warning', entry
        assert entry['explanation'] and entry['location'], entry
        assert entry['remedy'], entry


HASH_PROFILE = 'linux-bpfel-v3-hash'


def hash_profile_spec(entries=1):
    request = hash_spec(entries)
    request['profile_id'] = HASH_PROFILE
    return request


@pytest.mark.parametrize('source,entries', HASH_PAIR_SOURCES)
def test_hash_pair_lowers_under_hash_profile(tmp_path, source, entries):
    # The hash capability profile validates on the parsed
    # route: the spec carries the true profile (mirroring the
    # tc -net admission), never a normalized base.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, output = lower(
        tmp_path, raw, hash_profile_spec(entries))
    lower_success(result, report, output)
    assert report.get('unproved', []) == [], report
    assert report.get('unproved_total', 0) == 0, report


# ---------------------------------------------------------------------------
# T4a-3 LRU kind.
#
# LRU read-modify-write pairs over dense keys 0..N-1 and LRU
# deletions mirror the hash slice modulo the LRU tag on each
# map address (the memory-clobbered tag shape) and the map
# type bound: they lower under the strict proof with no
# obligations. LRU kernel negatives mirror the hash shapes
# (same strict codes, same permissive obligations).
# ---------------------------------------------------------------------------

LRU_PAIR_SOURCES = [
    ('tests/compile/lru_rmw1.mojo', 1),
    ('tests/compile/lru_rmw2.mojo', 2),
    ('tests/compile/lru_rmw3.mojo', 3),
    ('tests/compile/lru_rmw4.mojo', 4),
]

LRU_DELETE_SOURCES = [
    ('tests/compile/lru_delete1.mojo', 1),
    ('tests/compile/lru_delete2.mojo', 2),
    ('tests/compile/lru_delete3.mojo', 3),
    ('tests/compile/lru_delete4.mojo', 4),
]

LRU_KERNEL_NEGATIVES = [
    ('tests/compile/lru_unchecked.mojo', 'MBPF314'),
    ('tests/compile/lru_oob.mojo', 'MBPF314'),
]


def lru_spec(entries=1):
    request = spec(has_map=True)
    request['map'] = dict(request['map'], type=9, max_entries=entries)
    return request


@pytest.mark.parametrize('source,entries', LRU_PAIR_SOURCES)
def test_lru_pair_lowers_strict(tmp_path, source, entries):
    # Dense-keyed LRU pairs lower under the strict proof: the
    # tag marks the map operand's kind, the multiplicity rule
    # is unchanged.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, output = lower(tmp_path, raw, lru_spec(entries))
    lower_success(result, report, output)
    assert report.get('unproved', []) == [], report
    assert report.get('unproved_total', 0) == 0, report


@pytest.mark.parametrize('source,entries', LRU_DELETE_SOURCES)
def test_lru_delete_lowers_strict(tmp_path, source, entries):
    # LRU deletions over dense keys lower under the strict
    # proof with the delete helper call lowered.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, output = lower(tmp_path, raw, lru_spec(entries))
    lower_success(result, report, output)
    assert report.get('unproved', []) == [], report
    assert report.get('unproved_total', 0) == 0, report
    assert 'inttoptr (i64 3 to ptr)' in output.read_text(), 'delete call not lowered'


@pytest.mark.parametrize('source,code', LRU_KERNEL_NEGATIVES)
def test_lru_kernel_negative_strict_refuses(tmp_path, source, code):
    # Regression guard for proof strength: the strict proof
    # still refuses each LRU kernel-negative shape with the
    # diagnosed code.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, _output = lower(tmp_path, raw, lru_spec())
    refusal(result, report, code)


@pytest.mark.parametrize('source,code', LRU_KERNEL_NEGATIVES)
def test_lru_kernel_negative_permissive_obligates(tmp_path, source, code):
    # LRU kernel negatives obligate+emit under permissive
    # proof, mirroring the hash shapes.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, output = lower(tmp_path, raw, lru_spec(), permissive=True)
    lower_success(result, report, output)
    unproved = report.get('unproved')
    assert isinstance(unproved, list) and unproved, report
    assert report.get('unproved_total', 0) >= len(unproved), report
    assert code in {entry['code'] for entry in unproved}, (source, unproved)
    for entry in unproved:
        assert set(entry) == {'code', 'stage', 'severity', 'explanation',
                              'location', 'remedy'}, entry
        assert entry['severity'] == 'warning', entry
        assert entry['explanation'] and entry['location'], entry
        assert entry['remedy'], entry


LRU_PROFILE = 'linux-bpfel-v3-lru'


def lru_profile_spec(entries=1):
    request = lru_spec(entries)
    request['profile_id'] = LRU_PROFILE
    return request


@pytest.mark.parametrize('source,entries', LRU_PAIR_SOURCES)
def test_lru_pair_lowers_under_lru_profile(tmp_path, source, entries):
    # The LRU capability profile validates on the parsed
    # route: the spec carries the true profile (mirroring the
    # hash admission), never a normalized base.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, output = lower(
        tmp_path, raw, lru_profile_spec(entries))
    lower_success(result, report, output)
    assert report.get('unproved', []) == [], report
    assert report.get('unproved_total', 0) == 0, report


# ---------------------------------------------------------------------------
# T4a-3 percpu kind.
#
# Percpu read-modify-write pairs over dense keys 0..N-1 and
# percpu deletions mirror the LRU slice modulo the percpu tag
# on each map address (the sideeffect-free tag shape) and the
# map type bound: they lower under the strict proof with no
# obligations. Percpu builds under the base profile (no
# capability profile exists for it), so no profile test is
# needed; percpu has no kernel-negative fixtures.
# ---------------------------------------------------------------------------

PERCPU_PAIR_SOURCES = [
    ('tests/compile/percpu_rmw1.mojo', 1),
    ('tests/compile/percpu_rmw2.mojo', 2),
    ('tests/compile/percpu_rmw3.mojo', 3),
    ('tests/compile/percpu_rmw4.mojo', 4),
]

PERCPU_DELETE_SOURCES = [
    ('tests/compile/percpu_delete1.mojo', 1),
    ('tests/compile/percpu_delete2.mojo', 2),
    ('tests/compile/percpu_delete3.mojo', 3),
    ('tests/compile/percpu_delete4.mojo', 4),
]


def percpu_spec(entries=1):
    request = spec(has_map=True)
    request['map'] = dict(request['map'], type=6, max_entries=entries)
    return request


@pytest.mark.parametrize('source,entries', PERCPU_PAIR_SOURCES)
def test_percpu_pair_lowers_strict(tmp_path, source, entries):
    # Dense-keyed percpu pairs lower under the strict proof:
    # the tag marks the map operand's kind, the multiplicity
    # rule is unchanged.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, output = lower(tmp_path, raw, percpu_spec(entries))
    lower_success(result, report, output)
    assert report.get('unproved', []) == [], report
    assert report.get('unproved_total', 0) == 0, report


@pytest.mark.parametrize('source,entries', PERCPU_DELETE_SOURCES)
def test_percpu_delete_lowers_strict(tmp_path, source, entries):
    # Percpu deletions over dense keys lower under the strict
    # proof with the delete helper call lowered.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, output = lower(tmp_path, raw, percpu_spec(entries))
    lower_success(result, report, output)
    assert report.get('unproved', []) == [], report
    assert report.get('unproved_total', 0) == 0, report
    assert 'inttoptr (i64 3 to ptr)' in output.read_text(), 'delete call not lowered'


@pytest.mark.parametrize('source', TC_SOURCES)
def test_tc_source_lowers_strict(tmp_path, source):
    # The tc family (context words at bytes 76/80, classifier
    # section, -net profile) lowers under the strict proof with
    # no obligations: a proof extension, not a downgrade.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, output = lower(tmp_path, raw, tc_spec())
    lower_success(result, report, output)
    assert report.get('unproved', []) == [], report
    assert report.get('unproved_total', 0) == 0, report


def test_tc_section_mismatch_refuses(tmp_path):
    # The (program, section) pair gates: tc with an xdp section
    # is a contract mismatch, a usage failure before any output.
    raw = capture(tmp_path, ROOT/'examples/tc_classifier/tc.mojo', 'llvm')
    request = tc_spec()
    request['section'] = 'xdp'
    request_path = tmp_path/'spec.json'
    request_path.write_text(json.dumps(request))
    output = tmp_path/'lowered.ll'
    report_path = tmp_path/'lower.report.json'
    result = run([lower_tool(), '--mode', 'lower', '--input', raw,
                  '--spec', request_path, '--report', report_path,
                  '--output', output])
    assert result.returncode == 2, result.stdout + result.stderr
    assert 'MBPF202' in result.stderr, result.stderr
    assert not output.exists() and not report_path.exists()


# ---------------------------------------------------------------------------
# T4a-3 combined workload (packet length stored into map values).
#
# Both combined fixtures compute the packet length as
# sub(zext(data_end), zext(data)) over the same context origin
# and add it to a map value. The difference of two same-origin
# addresses is slide-invariant (the ASLR slide cancels even
# under wrap), so it is pure scalar data: the proof admits
# exactly this shape as Scalar. Sums, raw words, the reversed
# order, and cross shapes stay refused (MBPF316): they carry
# address material. The admission is strict (a proved rule, not
# a downgrade) and kind-orthogonal; the route flip stays
# evidence-gated per kind (array and percpu have fixtures).
# ---------------------------------------------------------------------------

COMBINED_SOURCES = [
    ('examples/packet_counter/packet_counter.mojo', 'array', 2),
    ('tests/compile/percpu_combined.mojo', 'percpu', 2),
]

COMBINED_VALUE_ADDS = {
    'examples/packet_counter/packet_counter.mojo': 'add i64 %41, %7',
    'tests/compile/percpu_combined.mojo': 'add i64 %44, %7',
}


def combined_spec(kind, entries):
    if kind == 'array':
        return map_spec(entries)
    assert kind == 'percpu'
    return percpu_spec(entries)


@pytest.mark.parametrize('source,kind,entries', COMBINED_SOURCES)
def test_combined_length_lowers_strict(tmp_path, source, kind, entries):
    # The packet length (same-origin end-minus-data) is pure
    # scalar data: combined fixtures lower under the strict
    # proof with no obligations.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, output = lower(
        tmp_path, raw, combined_spec(kind, entries))
    lower_success(result, report, output)
    assert report.get('unproved', []) == [], report
    assert report.get('unproved_total', 0) == 0, report


def mutate_combined(tmp_path, raw, find, replace):
    # One-shape mutation probe: the replaced text must occur
    # exactly once, so the probe cannot silently go stale.
    text = Path(raw).read_text()
    assert text.count(find) == 1, (find, text.count(find))
    mutated = tmp_path/'mutated.ll'
    mutated.write_text(text.replace(find, replace))
    return mutated


@pytest.mark.parametrize('source,kind,entries', COMBINED_SOURCES)
def test_combined_length_sum_still_refuses(tmp_path, source, kind, entries):
    # The sum of two addresses keeps the slide (2*slide +
    # const): it stays refused in both modes.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    mutated = mutate_combined(
        tmp_path, raw, 'sub i64 %6, %4', 'add i64 %6, %4')
    result, report, _output = lower(
        tmp_path, mutated, combined_spec(kind, entries))
    refusal(result, report, 'MBPF316')
    result, report, _output = lower(
        tmp_path, mutated, combined_spec(kind, entries), permissive=True)
    refusal(result, report, 'MBPF316')


@pytest.mark.parametrize('source,kind,entries', COMBINED_SOURCES)
def test_combined_length_reversed_still_refuses(tmp_path, source, kind, entries):
    # Only the observed order (end minus data) is admitted; the
    # reversed subtraction stays refused in both modes.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    mutated = mutate_combined(
        tmp_path, raw, 'sub i64 %6, %4', 'sub i64 %4, %6')
    result, report, _output = lower(
        tmp_path, mutated, combined_spec(kind, entries))
    refusal(result, report, 'MBPF316')
    result, report, _output = lower(
        tmp_path, mutated, combined_spec(kind, entries), permissive=True)
    refusal(result, report, 'MBPF316')


@pytest.mark.parametrize('source,kind,entries', COMBINED_SOURCES)
def test_combined_raw_word_still_refuses(tmp_path, source, kind, entries):
    # A raw context address word added into the stored payload
    # is address material: it stays refused in both modes.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    find = COMBINED_VALUE_ADDS[source]
    mutated = mutate_combined(
        tmp_path, raw, find, find.replace(', %7', ', %6'))
    result, report, _output = lower(
        tmp_path, mutated, combined_spec(kind, entries))
    refusal(result, report, 'MBPF316')
    result, report, _output = lower(
        tmp_path, mutated, combined_spec(kind, entries), permissive=True)
    refusal(result, report, 'MBPF316')


# ---------------------------------------------------------------------------
# T4a-4 tracepoint shape (filter read + PID/TID call + count pair).
#
# The tracepoint counter reads a TID filter (key 0), calls helper
# 14 (__mojobpf_get_pid_tgid_v1), masks the low 32 bits, and on a
# match runs a read-modify-write pair (key 1). The context
# pointer stays unused (tracepoint payload layouts are a
# separate unimplemented capability): any context use refuses
# MBPF317 in both modes, matching the Lane-A audit. The
# count-two attempt is audit-clean (its +2 is spill-gate
# scope); the tgid mutant is shape-identical (its TGID
# confusion is guest-behavior scope).
# ---------------------------------------------------------------------------

TRACEPOINT_SECTION = 'tracepoint/syscalls/sys_enter_getpid'

TRACEPOINT_SOURCES = [
    'examples/tracepoint_counter/counter.mojo',
    'tests/compile/tracepoint_count_two_attempt.mojo',
    'examples/tracepoint_counter/counter_tgid_mutated.mojo',
]


def tracepoint_spec(entries=2):
    request = spec(has_map=True, entry='trace_entry')
    request['map'] = dict(request['map'], max_entries=entries)
    request.update({'program_type': 'tracepoint',
                    'section': TRACEPOINT_SECTION})
    return request


@pytest.mark.parametrize('source', TRACEPOINT_SOURCES)
def test_tracepoint_lowers_strict(tmp_path, source):
    # The tracepoint vector (filter read, helper-14 call,
    # masked compare, count pair) lowers under the strict
    # proof with no obligations.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, output = lower(
        tmp_path, raw, tracepoint_spec())
    lower_success(result, report, output)
    assert report.get('unproved', []) == [], report
    assert report.get('unproved_total', 0) == 0, report


def test_tracepoint_ctx_attempt_refuses_both_modes(tmp_path):
    # The context-probing attempt refuses MBPF317 in both
    # modes: tracepoint programs must not read context
    # payload fields (verdict parity with the Lane-A audit).
    raw = capture(
        tmp_path, ROOT/'tests/compile/tracepoint_ctx_attempt.mojo',
        'llvm')
    result, report, _output = lower(
        tmp_path, raw, tracepoint_spec())
    refusal(result, report, 'MBPF317')
    result, report, _output = lower(
        tmp_path, raw, tracepoint_spec(), permissive=True)
    refusal(result, report, 'MBPF317')


# ---------------------------------------------------------------------------
# T4a-4 event shape (filter read + PID/TID/CPU/clock/output + three pairs).
#
# The event emitter reads a TID filter (key 0), takes a sequence
# number (key 1), reads the CPU (helper 8) and the monotonic
# clock (helper 5), stamps the 32-byte record through the event
# slot views, emits it with the copy-output call (helper 130)
# through the ring-buffer companion, and counts the outcome
# (key 2 on success, key 3 on failure). All four sources share
# the vector; the small emitter differs only in ring size
# (4096 vs 131072), the mutants only in record literals.
# ---------------------------------------------------------------------------

EVENT_SOURCES = [
    'examples/tracepoint_events/emitter.mojo',
    'examples/tracepoint_events/emitter_small.mojo',
    'examples/tracepoint_events/emitter_tgid_mutated.mojo',
    'examples/tracepoint_events/emitter_v2_mutated.mojo',
]


def event_spec(entries=4):
    request = spec(has_map=True, entry='trace_entry')
    request['map'] = dict(request['map'], max_entries=entries)
    request.update({'program_type': 'tracepoint',
                    'section': TRACEPOINT_SECTION})
    return request


@pytest.mark.parametrize('source', EVENT_SOURCES)
def test_event_lowers_strict(tmp_path, source):
    # The event vector (filter read, helper calls, record
    # stores, output call, three pairs) lowers under the
    # strict proof with no obligations.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, output = lower(
        tmp_path, raw, event_spec())
    lower_success(result, report, output)
    assert report.get('unproved', []) == [], report
    assert report.get('unproved_total', 0) == 0, report


def mutate_event(tmp_path, raw, find, replace, *, count=1):
    # One-shape mutation probe: the replaced text must occur
    # exactly the expected times (the first only is swapped),
    # so the probe cannot silently go stale.
    text = Path(raw).read_text()
    assert text.count(find) == count, (find, text.count(find))
    mutated = tmp_path/'mutated.ll'
    mutated.write_text(text.replace(find, replace, 1))
    return mutated


def test_event_output_size_still_refuses(tmp_path):
    # Only the 32-byte record submission is admitted; any
    # other size stays refused in both modes.
    raw = capture(tmp_path, ROOT/EVENT_SOURCES[0], 'llvm')
    find = 'ringbuf_output_v1(i64 %48, ptr %46, i64 32, i64 0)'
    mutated = mutate_event(
        tmp_path, raw, find, find.replace('i64 32', 'i64 16'))
    result, report, _output = lower(
        tmp_path, mutated, event_spec())
    refusal(result, report, 'MBPF314')
    result, report, _output = lower(
        tmp_path, mutated, event_spec(), permissive=True)
    refusal(result, report, 'MBPF314')


def test_event_output_flags_still_refuse(tmp_path):
    # Only the zero-flags submission is admitted; any other
    # flags stay refused in both modes.
    raw = capture(tmp_path, ROOT/EVENT_SOURCES[0], 'llvm')
    find = 'ringbuf_output_v1(i64 %48, ptr %46, i64 32, i64 0)'
    mutated = mutate_event(
        tmp_path, raw, find, find.replace('i64 0)', 'i64 1)'))
    result, report, _output = lower(
        tmp_path, mutated, event_spec())
    refusal(result, report, 'MBPF314')
    result, report, _output = lower(
        tmp_path, mutated, event_spec(), permissive=True)
    refusal(result, report, 'MBPF314')


def test_event_untagged_output_still_refuses(tmp_path):
    # The output call takes the size-tagged companion
    # address; the bare map address stays refused in both
    # modes.
    raw = capture(tmp_path, ROOT/EVENT_SOURCES[0], 'llvm')
    mutated = mutate_event(
        tmp_path, raw, 'ringbuf_output_v1(i64 %48',
        'ringbuf_output_v1(i64 %47')
    result, report, _output = lower(
        tmp_path, mutated, event_spec())
    refusal(result, report, 'MBPF314')
    result, report, _output = lower(
        tmp_path, mutated, event_spec(), permissive=True)
    refusal(result, report, 'MBPF314')


def test_event_output_slot_still_refuses(tmp_path):
    # The output data is the prepared record base; any other
    # scratch pointer stays refused in both modes.
    raw = capture(tmp_path, ROOT/EVENT_SOURCES[0], 'llvm')
    mutated = mutate_event(
        tmp_path, raw, ', ptr %46, i64 32,', ', ptr %2, i64 32,')
    result, report, _output = lower(
        tmp_path, mutated, event_spec())
    refusal(result, report, 'MBPF314')
    result, report, _output = lower(
        tmp_path, mutated, event_spec(), permissive=True)
    refusal(result, report, 'MBPF314')


def test_event_bad_ring_size_still_refuses(tmp_path):
    # Only the qualified ring-buffer sizes tag the
    # companion; any other size stays refused in both modes.
    raw = capture(tmp_path, ROOT/EVENT_SOURCES[0], 'llvm')
    mutated = mutate_event(
        tmp_path, raw, '(i64 %47, i64 131072)',
        '(i64 %47, i64 8192)')
    result, report, _output = lower(
        tmp_path, mutated, event_spec())
    refusal(result, report, 'MBPF314')
    result, report, _output = lower(
        tmp_path, mutated, event_spec(), permissive=True)
    refusal(result, report, 'MBPF314')


def test_event_tag_on_keyed_map_still_refuses(tmp_path):
    # The size tag wraps the ring-buffer companion; a tag on
    # the keyed state map stays refused in both modes.
    raw = capture(tmp_path, ROOT/EVENT_SOURCES[0], 'llvm')
    mutated = mutate_event(
        tmp_path, raw, '(i64 %47, i64 131072)',
        '(i64 %3, i64 131072)')
    result, report, _output = lower(
        tmp_path, mutated, event_spec())
    refusal(result, report, 'MBPF314')
    result, report, _output = lower(
        tmp_path, mutated, event_spec(), permissive=True)
    refusal(result, report, 'MBPF314')


def test_event_view_offset_still_refuses(tmp_path):
    # Only the seven record field offsets spell views; any
    # other slot stays unrecognized in both modes.
    raw = capture(tmp_path, ROOT/EVENT_SOURCES[0], 'llvm')
    mutated = mutate_event(
        tmp_path, raw, 'r0 += -40', 'r0 += -41')
    result, report, _output = lower(
        tmp_path, mutated, event_spec())
    refusal(result, report, 'MBPF306')
    result, report, _output = lower(
        tmp_path, mutated, event_spec(), permissive=True)
    refusal(result, report, 'MBPF306')


def test_event_key_density_still_refuses(tmp_path):
    # The event vector covers dense keys [0,1,1,2,2,3,3]; a
    # skewed preparation stays refused in both modes.
    raw = capture(tmp_path, ROOT/EVENT_SOURCES[0], 'llvm')
    mutated = mutate_event(
        tmp_path, raw, '(i32 3)', '(i32 1)', count=2)
    result, report, _output = lower(
        tmp_path, mutated, event_spec())
    refusal(result, report, 'MBPF314')
    result, report, _output = lower(
        tmp_path, mutated, event_spec(), permissive=True)
    refusal(result, report, 'MBPF314')


# ---------------------------------------------------------------------------
# T4a-4 uprobe shape (filter read + pinned register read + count pair).
#
# The uprobe register counter reads the expected argument (key
# 0), reads the probed call's first argument from the pinned
# x86-64 register word (pt_regs word 14, rdi at byte 112), and
# pairs key 1 on a match. Both sources share the vector; the
# inverted mutant differs only in branch polarity.
# ---------------------------------------------------------------------------

UPROBE_SECTION = 'uprobe'
UPROBE_PROFILE = 'linux-bpfel-v3-uprobe'

UPROBE_SOURCES = [
    'examples/uprobe_counter/counter.mojo',
    'examples/uprobe_counter/counter_inverted_mutated.mojo',
]


def uprobe_spec(entries=2):
    request = spec(has_map=True, entry='uprobe_entry',
                   profile=UPROBE_PROFILE)
    request['map'] = dict(request['map'], max_entries=entries)
    request.update({'program_type': 'uprobe',
                    'section': UPROBE_SECTION})
    return request


@pytest.mark.parametrize('source', UPROBE_SOURCES)
def test_uprobe_lowers_strict(tmp_path, source):
    # The uprobe vector (filter read, pinned register read,
    # count pair) lowers under the strict proof with no
    # obligations.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, output = lower(
        tmp_path, raw, uprobe_spec())
    lower_success(result, report, output)
    assert report.get('unproved', []) == [], report
    assert report.get('unproved_total', 0) == 0, report


def mutate_uprobe(tmp_path, raw, find, replace, *, count=1):
    # One-shape mutation probe: the replaced text must occur
    # exactly the expected times (the first only is swapped),
    # so the probe cannot silently go stale.
    text = Path(raw).read_text()
    assert text.count(find) == count, (find, text.count(find))
    mutated = tmp_path/'mutated.ll'
    mutated.write_text(text.replace(find, replace, 1))
    return mutated


def insert_uprobe_line(tmp_path, raw, anchor, line):
    # Line-duplication probe: the anchor line must occur
    # exactly once; the new line follows it, so the probe
    # cannot silently go stale.
    text = Path(raw).read_text()
    assert text.count(anchor) == 1, (anchor, text.count(anchor))
    mutated = tmp_path/'mutated.ll'
    mutated.write_text(text.replace(anchor, anchor + line, 1))
    return mutated


def test_uprobe_wrong_register_still_refuses(tmp_path):
    # Only context word 14 (rdi) is admitted; any other
    # register index stays refused in both modes.
    raw = capture(tmp_path, ROOT/UPROBE_SOURCES[0], 'llvm')
    mutated = mutate_uprobe(
        tmp_path, raw, 'i32 14', 'i32 13', count=1)
    result, report, _output = lower(
        tmp_path, mutated, uprobe_spec())
    refusal(result, report, 'MBPF317')
    result, report, _output = lower(
        tmp_path, mutated, uprobe_spec(), permissive=True)
    refusal(result, report, 'MBPF317')


def test_uprobe_unbounded_gep_still_refuses(tmp_path):
    # The pinned address computation is inbounds; dropping
    # the bound stays refused in both modes.
    raw = capture(tmp_path, ROOT/UPROBE_SOURCES[0], 'llvm')
    mutated = mutate_uprobe(
        tmp_path, raw, 'inbounds i64, ptr %0', 'i64, ptr %0',
        count=1)
    result, report, _output = lower(
        tmp_path, mutated, uprobe_spec())
    refusal(result, report, 'MBPF317')
    result, report, _output = lower(
        tmp_path, mutated, uprobe_spec(), permissive=True)
    refusal(result, report, 'MBPF317')


def test_uprobe_second_address_still_refuses(tmp_path):
    # The entry parameter feeds one address computation
    # only; a second stays refused in both modes.
    raw = capture(tmp_path, ROOT/UPROBE_SOURCES[0], 'llvm')
    anchor = '  %2 = getelementptr inbounds i64, ptr %0, i32 14\n'
    mutated = insert_uprobe_line(
        tmp_path, raw, anchor,
        '  %extra = getelementptr inbounds i64, ptr %0, i32 14\n')
    result, report, _output = lower(
        tmp_path, mutated, uprobe_spec())
    refusal(result, report, 'MBPF317')
    result, report, _output = lower(
        tmp_path, mutated, uprobe_spec(), permissive=True)
    refusal(result, report, 'MBPF317')


def test_uprobe_second_load_still_refuses(tmp_path):
    # The pinned register word loads exactly once; a
    # second load stays refused in both modes.
    raw = capture(tmp_path, ROOT/UPROBE_SOURCES[0], 'llvm')
    anchor = '  %3 = load i64, ptr %2, align 8\n'
    mutated = insert_uprobe_line(
        tmp_path, raw, anchor,
        '  %extra = load i64, ptr %2, align 8\n')
    result, report, _output = lower(
        tmp_path, mutated, uprobe_spec())
    refusal(result, report, 'MBPF317')
    result, report, _output = lower(
        tmp_path, mutated, uprobe_spec(), permissive=True)
    refusal(result, report, 'MBPF317')


def test_uprobe_key_density_still_refuses(tmp_path):
    # The uprobe vector covers dense keys [0,1,1]; a
    # skewed preparation stays refused in both modes.
    raw = capture(tmp_path, ROOT/UPROBE_SOURCES[0], 'llvm')
    mutated = mutate_uprobe(
        tmp_path, raw, '(i32 1)', '(i32 0)', count=2)
    result, report, _output = lower(
        tmp_path, mutated, uprobe_spec())
    refusal(result, report, 'MBPF314')
    result, report, _output = lower(
        tmp_path, mutated, uprobe_spec(), permissive=True)
    refusal(result, report, 'MBPF314')


# ---------------------------------------------------------------------------
# T4a-4 reserve shape (filter read + PID/TID/CPU/clock + reserve + stores +
# terminus + three pairs).
#
# The reservation emitter reads a TID filter (key 0), takes a
# sequence number (key 1), reads the CPU (helper 8) and the
# monotonic clock (helper 5) plus the PID/TID identity word,
# reserves a 32-byte record (helper 131), stamps the seven
# record words directly into the reservation, publishes it
# with the submit terminus (helper 132) or releases it with
# the discard terminus (helper 133), and counts the outcome
# (key 2 on success, key 3 on failure). All four sources
# share the vector; the small emitter differs only in ring
# size (4096 vs 131072), the discarder only in terminus.
# ---------------------------------------------------------------------------

RESERVE_PROFILE = 'linux-bpfel-v3-reserve'

RESERVE_SOURCES = [
    'examples/ringbuf_reserve/emitter.mojo',
    'tests/compile/reserve_submit.mojo',
    'tests/compile/reserve_submit_small.mojo',
    'tests/compile/reserve_discard.mojo',
]


def reserve_spec(entries=4):
    request = spec(has_map=True, entry='trace_entry',
                   profile=RESERVE_PROFILE)
    request['map'] = dict(request['map'], max_entries=entries)
    request.update({'program_type': 'tracepoint',
                    'section': TRACEPOINT_SECTION})
    return request


@pytest.mark.parametrize('source', RESERVE_SOURCES)
def test_reserve_lowers_strict(tmp_path, source):
    # The reserve vector (filter read, helper calls, reserve,
    # record stores, terminus, three pairs) lowers under the
    # strict proof with no obligations.
    raw = capture(tmp_path, ROOT/source, 'llvm')
    result, report, output = lower(
        tmp_path, raw, reserve_spec())
    lower_success(result, report, output)
    assert report.get('unproved', []) == [], report
    assert report.get('unproved_total', 0) == 0, report


def mutate_reserve(tmp_path, raw, find, replace, *, count=1):
    # One-shape mutation probe: the replaced text must occur
    # exactly the expected times (the first only is swapped),
    # so the probe cannot silently go stale.
    text = Path(raw).read_text()
    assert text.count(find) == count, (find, text.count(find))
    mutated = tmp_path/'mutated.ll'
    mutated.write_text(text.replace(find, replace, 1))
    return mutated


def delete_reserve_line(tmp_path, raw, line):
    # Line-deletion probe: the line must occur exactly once;
    # removing it keeps the module well-formed (no dangling
    # SSA use), so the probe cannot silently go stale.
    text = Path(raw).read_text()
    assert text.count(line) == 1, (line, text.count(line))
    mutated = tmp_path/'mutated.ll'
    mutated.write_text(text.replace(line, '', 1))
    return mutated


def test_reserve_wrong_size_still_refuses(tmp_path):
    # The reservation requests exactly the 32 record bytes;
    # any other size stays refused in both modes.
    raw = capture(tmp_path, ROOT/RESERVE_SOURCES[1], 'llvm')
    mutated = mutate_reserve(
        tmp_path, raw, 'i64 32, i64 0', 'i64 64, i64 0',
        count=1)
    result, report, _output = lower(
        tmp_path, mutated, reserve_spec())
    refusal(result, report, 'MBPF314')
    result, report, _output = lower(
        tmp_path, mutated, reserve_spec(), permissive=True)
    refusal(result, report, 'MBPF314')


def test_reserve_terminus_flags_still_refuse(tmp_path):
    # The terminus takes literal flags 0; any other flags
    # stay refused in both modes.
    raw = capture(tmp_path, ROOT/RESERVE_SOURCES[1], 'llvm')
    mutated = mutate_reserve(
        tmp_path, raw, '(ptr %45, i64 0)', '(ptr %45, i64 1)',
        count=1)
    result, report, _output = lower(
        tmp_path, mutated, reserve_spec())
    refusal(result, report, 'MBPF314')
    result, report, _output = lower(
        tmp_path, mutated, reserve_spec(), permissive=True)
    refusal(result, report, 'MBPF314')


def test_reserve_untagged_map_still_refuses(tmp_path):
    # The reservation takes the size-tagged companion, not
    # the bare map address; the swap stays refused in both
    # modes.
    raw = capture(tmp_path, ROOT/RESERVE_SOURCES[1], 'llvm')
    mutated = mutate_reserve(
        tmp_path, raw, 'reserve_v1(i64 %40, i64 32, i64 0)',
        'reserve_v1(i64 %39, i64 32, i64 0)', count=1)
    result, report, _output = lower(
        tmp_path, mutated, reserve_spec())
    refusal(result, report, 'MBPF314')
    result, report, _output = lower(
        tmp_path, mutated, reserve_spec(), permissive=True)
    refusal(result, report, 'MBPF314')


def test_reserve_bad_ring_size_still_refuses(tmp_path):
    # The companion carries one of the two qualified ring
    # sizes; any other tag stays refused in both modes.
    raw = capture(tmp_path, ROOT/RESERVE_SOURCES[1], 'llvm')
    mutated = mutate_reserve(
        tmp_path, raw, '131072', '65536', count=1)
    result, report, _output = lower(
        tmp_path, mutated, reserve_spec())
    refusal(result, report, 'MBPF314')
    result, report, _output = lower(
        tmp_path, mutated, reserve_spec(), permissive=True)
    refusal(result, report, 'MBPF314')


def test_reserve_store_offset_still_refuses(tmp_path):
    # The seven stores land at their exact field offsets;
    # a skewed store stays refused in both modes.
    raw = capture(tmp_path, ROOT/RESERVE_SOURCES[1], 'llvm')
    mutated = mutate_reserve(
        tmp_path, raw, 'i32 24', 'i32 20', count=1)
    result, report, _output = lower(
        tmp_path, mutated, reserve_spec())
    refusal(result, report, 'MBPF314')
    result, report, _output = lower(
        tmp_path, mutated, reserve_spec(), permissive=True)
    refusal(result, report, 'MBPF314')


def test_reserve_missing_store_still_refuses(tmp_path):
    # The reservation stamps all seven record words; a
    # dropped store stays refused in both modes.
    raw = capture(tmp_path, ROOT/RESERVE_SOURCES[1], 'llvm')
    mutated = delete_reserve_line(
        tmp_path, raw, '  store i16 1, ptr %45, align 2\n')
    result, report, _output = lower(
        tmp_path, mutated, reserve_spec())
    refusal(result, report, 'MBPF314')
    result, report, _output = lower(
        tmp_path, mutated, reserve_spec(), permissive=True)
    refusal(result, report, 'MBPF314')


def test_reserve_second_terminus_still_refuses(tmp_path):
    # The vector carries exactly one terminus; a second
    # stays refused in both modes.
    raw = capture(tmp_path, ROOT/RESERVE_SOURCES[1], 'llvm')
    text = Path(raw).read_text()
    anchor = '  %52 = call i64 @__mojobpf_ringbuf_submit_v1(ptr %45, i64 0)\n'
    assert text.count(anchor) == 1, text.count(anchor)
    mutated = tmp_path/'mutated.ll'
    mutated.write_text(text.replace(
        anchor,
        anchor + '  %extra = call i64 @__mojobpf_ringbuf_submit_v1(ptr %45, i64 0)\n',
        1))
    result, report, _output = lower(
        tmp_path, mutated, reserve_spec())
    refusal(result, report, 'MBPF303')
    result, report, _output = lower(
        tmp_path, mutated, reserve_spec(), permissive=True)
    refusal(result, report, 'MBPF303')


# ---------------------------------------------------------------------------
# T4a-4 core shape (lookup + relocation read + existence check + select).
#
# The CO-RE probe reads one array slot (key 0, 4096-byte value),
# reads the relocated task pid out of the checked value (the
# preserve-access-index expansion), checks the relocated
# existence bit, and selects the stamped identity word. The
# profile is the CO-RE capability profile; the map contract
# carries the 4096-byte value.
# ---------------------------------------------------------------------------

CORE_PROFILE = 'linux-bpfel-v3-core'

CORE_SOURCES = [
    'tests/core/core_read.mojo',
]


def core_spec(entries=1):
    request = spec(has_map=True, entry='xdp_entry',
                   profile=CORE_PROFILE)
    request['map'] = dict(
        request['map'], value_bits=32768, max_entries=entries)
    return request


def test_core_lowers_strict(tmp_path):
    # The core vector (lookup, relocation read, existence
    # check, select) lowers under the strict proof with no
    # obligations.
    raw = capture(tmp_path, ROOT/CORE_SOURCES[0], 'llvm')
    result, report, output = lower(
        tmp_path, raw, core_spec())
    lower_success(result, report, output)
    assert report.get('unproved', []) == [], report
    assert report.get('unproved_total', 0) == 0, report


def mutate_core(tmp_path, raw, find, replace, *, count=1):
    # One-shape mutation probe: the replaced text must occur
    # exactly the expected times (the first only is swapped),
    # so the probe cannot silently go stale.
    text = Path(raw).read_text()
    assert text.count(find) == count, (find, text.count(find))
    mutated = tmp_path/'mutated.ll'
    mutated.write_text(text.replace(find, replace, 1))
    return mutated


def test_core_second_read_still_refuses(tmp_path):
    # The probe carries exactly one relocation read; a second
    # stays refused in both modes.
    raw = capture(tmp_path, ROOT/CORE_SOURCES[0], 'llvm')
    anchor = ('  %9 = call i32 @__mojobpf_core_read_task_pid_v1'
              '(ptr %8)\n')
    mutated = mutate_core(
        tmp_path, raw, anchor,
        anchor + '  %extra = call i32 '
        '@__mojobpf_core_read_task_pid_v1(ptr %8)\n')
    result, report, _output = lower(
        tmp_path, mutated, core_spec())
    refusal(result, report, 'MBPF303')
    result, report, _output = lower(
        tmp_path, mutated, core_spec(), permissive=True)
    refusal(result, report, 'MBPF303')


def test_core_dropped_exists_still_refuses(tmp_path):
    # The probe carries exactly one existence check; a
    # dropped check stays refused in both modes.
    raw = capture(tmp_path, ROOT/CORE_SOURCES[0], 'llvm')
    text = Path(raw).read_text()
    call = '  %12 = call i32 @__mojobpf_core_exists_task_scx_v1()\n'
    use = 'icmp eq i32 %12, 0'
    assert text.count(call) == 1 and text.count(use) == 1
    mutated = tmp_path/'mutated.ll'
    mutated.write_text(
        text.replace(call, '', 1).replace(use, 'icmp eq i32 0, 0', 1))
    result, report, _output = lower(
        tmp_path, mutated, core_spec())
    refusal(result, report, 'MBPF303')
    result, report, _output = lower(
        tmp_path, mutated, core_spec(), permissive=True)
    refusal(result, report, 'MBPF303')


def test_core_read_of_key_still_refuses(tmp_path):
    # The relocation read takes the checked map value
    # pointer; the key cell stays refused in both modes.
    raw = capture(tmp_path, ROOT/CORE_SOURCES[0], 'llvm')
    mutated = mutate_core(
        tmp_path, raw,
        '@__mojobpf_core_read_task_pid_v1(ptr %8)',
        '@__mojobpf_core_read_task_pid_v1(ptr %2)')
    result, report, _output = lower(
        tmp_path, mutated, core_spec())
    refusal(result, report, 'MBPF314')
    result, report, _output = lower(
        tmp_path, mutated, core_spec(), permissive=True)
    refusal(result, report, 'MBPF314')


def test_core_forged_marker_still_refuses(tmp_path):
    # The relocation markers are synthesized; an input
    # already carrying one stays refused in both modes.
    raw = capture(tmp_path, ROOT/CORE_SOURCES[0], 'llvm')
    text = Path(raw).read_text()
    assert 'llvm.task_struct' not in text
    mutated = tmp_path/'mutated.ll'
    mutated.write_text(
        text + '@"llvm.task_struct:0:32$0:1" = external global i32\n')
    result, report, _output = lower(
        tmp_path, mutated, core_spec())
    refusal(result, report, 'MBPF309')
    result, report, _output = lower(
        tmp_path, mutated, core_spec(), permissive=True)
    refusal(result, report, 'MBPF309')


def test_core_forged_minted_name_still_refuses(tmp_path):
    # The expansion SSA names are minted; an input already
    # carrying one stays refused in both modes.
    raw = capture(tmp_path, ROOT/CORE_SOURCES[0], 'llvm')
    anchor = ('  %3 = call i64 asm sideeffect "r0 = mojobpf_map0 ll",'
              ' "={r0}"()\n')
    mutated = mutate_core(
        tmp_path, raw, anchor,
        anchor + '  %__mojobpf_core_r0 = add i32 0, 0\n')
    result, report, _output = lower(
        tmp_path, mutated, core_spec())
    refusal(result, report, 'MBPF309')
    result, report, _output = lower(
        tmp_path, mutated, core_spec(), permissive=True)
    refusal(result, report, 'MBPF309')


def test_core_u64_map_still_refuses(tmp_path):
    # The relocation helpers ride the core map contract
    # (the 4096-byte slot); the u64 map stays refused in
    # both modes.
    raw = capture(tmp_path, ROOT/CORE_SOURCES[0], 'llvm')
    request = core_spec()
    request['map'] = dict(request['map'], value_bits=64)
    result, report, _output = lower(tmp_path, raw, request)
    refusal(result, report, 'MBPF313')
    result, report, _output = lower(
        tmp_path, raw, request, permissive=True)
    refusal(result, report, 'MBPF313')


def core_lowered(tmp_path):
    raw = capture(tmp_path, ROOT/CORE_SOURCES[0], 'llvm')
    result, report, output = lower(
        tmp_path, raw, core_spec())
    lower_success(result, report, output)
    return raw, report, text_ir(output)


@pytest.mark.parametrize('bitcode', [False, True])
def test_core_post_audit_accepts_actual_lowered(tmp_path, bitcode):
    _, _, text = core_lowered(tmp_path)
    result, report = audit_lowered(
        tmp_path, text, core_spec(), bitcode=bitcode)
    assert result.returncode == 0 and report['ok'] is True, \
        result.stderr + result.stdout


CORE_POST_MUTANTS = [
    ('passthrough-constant',
     '(i32 0, i32 %__mojobpf_core_r0)',
     '(i32 2, i32 %__mojobpf_core_r0)',
     'MBPF313'),
    ('marker-swap',
     '%__mojobpf_core_r0 = load i32, ptr '
     '@"llvm.task_struct:0:32$0:1"',
     '%__mojobpf_core_r0 = load i32, ptr '
     '@"llvm.task_struct:2:1$0:4"',
     'MBPF313'),
    ('dropped-extend',
     '%__mojobpf_core_r2 = zext i32 %__mojobpf_core_r1 to i64',
     '%__mojobpf_core_r2 = add i64 0, 0',
     'MBPF313'),
    ('task-member-rename',
     '!DIDerivedType(tag: DW_TAG_member, name: "pid"',
     '!DIDerivedType(tag: DW_TAG_member, name: "pix"',
     'MBPF319'),
    ('value-size-count',
     '!DISubrange(count: 4096, lowerBound: 0)',
     '!DISubrange(count: 4095, lowerBound: 0)',
     'MBPF319'),
    ('ama-strip',
     '{ "btf_ama" }',
     '{ "btf_amx" }',
     'MBPF319'),
]


@pytest.mark.parametrize('bitcode', [False, True])
@pytest.mark.parametrize('name,before,after,code', CORE_POST_MUTANTS)
def test_core_post_audit_refuses_lowered_corruption(
        tmp_path, bitcode, name, before, after, code):
    _, _, text = core_lowered(tmp_path)
    assert text.count(before) == 1, (name, text.count(before))
    corrupt = text.replace(before, after, 1)
    result, report = audit_lowered(
        tmp_path, corrupt, core_spec(), bitcode=bitcode)
    assert result.returncode == 4 and report['ok'] is False, \
        result.stdout + result.stderr
    assert report['diagnostics'][0]['code'] == code, report


# ---------------------------------------------------------------------------
# T4a-5 net shapes (socket load, TC store, TC load-into-map).
#
# One packet-byte load plus its key slot (socket or TC entry,
# mapless), one packet-byte store plus its key-N payload slot (TC
# entry only, mapless), or one packet-byte load plus one map
# update (TC load-into-map, 2-entry array map). The profile is
# the net capability profile; the socket contract is the
# (socket, socket) program/section pair.
# ---------------------------------------------------------------------------

NET_PROFILE = 'linux-bpfel-v3-net'

SKB_SOURCES = {
    'socket': 'examples/socket_classifier/socket.mojo',
    'store': 'tests/compile/tc_store.mojo',
    'loadmap': 'tests/compile/tc_loadmap.mojo',
}


def skb_spec(kind):
    assert kind in SKB_SOURCES, kind
    entry = 'socket_entry' if kind == 'socket' else 'tc_entry'
    request = spec(has_map=(kind == 'loadmap'), entry=entry,
                   profile=NET_PROFILE)
    if kind == 'socket':
        request['program_type'] = 'socket'
        request['section'] = 'socket'
    else:
        request['program_type'] = 'tc'
        request['section'] = 'classifier'
    if kind == 'loadmap':
        request['map'] = dict(
            request['map'], max_entries=2)
    return request


def test_skb_load_lowers_strict(tmp_path):
    # The socket load (keyslot buffer, helper-26 load, verdict
    # select) lowers under the strict proof with no obligations.
    raw = capture(tmp_path, ROOT/SKB_SOURCES['socket'], 'llvm')
    result, report, output = lower(
        tmp_path, raw, skb_spec('socket'))
    lower_success(result, report, output)
    assert report.get('unproved', []) == [], report
    assert report.get('unproved_total', 0) == 0, report


def test_skb_store_lowers_strict(tmp_path):
    # The TC store (key-N payload, helper-9 store, status
    # select) lowers under the strict proof with no obligations.
    raw = capture(tmp_path, ROOT/SKB_SOURCES['store'], 'llvm')
    result, report, output = lower(
        tmp_path, raw, skb_spec('store'))
    lower_success(result, report, output)
    assert report.get('unproved', []) == [], report
    assert report.get('unproved_total', 0) == 0, report


def test_skb_loadmap_lowers_strict(tmp_path):
    # The TC load-into-map (load leg plus one array update over
    # keys 0..1) lowers under the strict proof with no
    # obligations.
    raw = capture(tmp_path, ROOT/SKB_SOURCES['loadmap'], 'llvm')
    result, report, output = lower(
        tmp_path, raw, skb_spec('loadmap'))
    lower_success(result, report, output)
    assert report.get('unproved', []) == [], report
    assert report.get('unproved_total', 0) == 0, report


def mutate_skb(tmp_path, raw, find, replace, *, count=1):
    # One-shape mutation probe: the replaced text must occur
    # exactly the expected times (the first only is swapped),
    # so the probe cannot silently go stale.
    text = Path(raw).read_text()
    assert text.count(find) == count, (find, text.count(find))
    mutated = tmp_path/'mutated.ll'
    mutated.write_text(text.replace(find, replace, 1))
    return mutated


SOCKET_KEYSLOT = (
    '  %2 = call ptr asm sideeffect "r0 = r10\\0Ar0 += -4\\0A'
    '*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 0)\n')
SOCKET_LOAD_CALL = (
    '  %3 = call i64 @__mojobpf_skb_load_bytes_v1'
    '(ptr %0, i32 14, ptr %2, i32 1)\n')
STORE_KEYSLOT = (
    '  %2 = call ptr asm sideeffect "r0 = r10\\0Ar0 += -4\\0A'
    '*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 2)\n')
STORE_CALL = (
    '  %3 = call i64 @__mojobpf_skb_store_bytes_v1'
    '(ptr %0, i32 13, ptr %2, i32 1, i64 0)\n')
LOADMAP_KEY1 = (
    '  %11 = call ptr asm sideeffect "r0 = r10\\0Ar0 += -4\\0A'
    '*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 1)\n')
LOADMAP_UPDATE_CALL = (
    '  %13 = call i64 @__mojobpf_update_v1'
    '(i64 %12, ptr %11, ptr %9, i64 0)\n')
LOADMAP_UPDATE_DECL = (
    'declare i64 @__mojobpf_update_v1(i64, ptr, ptr, i64) #0\n')


def test_skb_second_load_still_refuses(tmp_path):
    # The socket vector carries exactly one packet load; a
    # second stays refused in both modes.
    raw = capture(tmp_path, ROOT/SKB_SOURCES['socket'], 'llvm')
    mutated = mutate_skb(
        tmp_path, raw, SOCKET_LOAD_CALL,
        SOCKET_LOAD_CALL + '  %extra = call i64 '
        '@__mojobpf_skb_load_bytes_v1(ptr %0, i32 14, ptr %2, i32 1)\n')
    result, report, _output = lower(
        tmp_path, mutated, skb_spec('socket'))
    refusal(result, report, 'MBPF303')
    result, report, _output = lower(
        tmp_path, mutated, skb_spec('socket'), permissive=True)
    refusal(result, report, 'MBPF303')


def test_skb_socket_key_literal_refused(tmp_path):
    # The socket buffer is exactly keyslot 0; key 1 stays
    # refused in both modes.
    raw = capture(tmp_path, ROOT/SKB_SOURCES['socket'], 'llvm')
    mutated = mutate_skb(
        tmp_path, raw, SOCKET_KEYSLOT,
        SOCKET_KEYSLOT.replace('(i32 0)', '(i32 1)'))
    result, report, _output = lower(
        tmp_path, mutated, skb_spec('socket'))
    refusal(result, report, 'MBPF314')
    result, report, _output = lower(
        tmp_path, mutated, skb_spec('socket'), permissive=True)
    refusal(result, report, 'MBPF314')


def test_skb_socket_with_map_refuses(tmp_path):
    # The socket vector is mapless; the same body under a map
    # contract stays refused in both modes.
    raw = capture(tmp_path, ROOT/SKB_SOURCES['socket'], 'llvm')
    request = skb_spec('socket')
    request['map'] = {
        'symbol': 'mojobpf_map0', 'type': 2, 'key_bits': 32,
        'value_bits': 64, 'max_entries': 1, 'flags': 0}
    result, report, _output = lower(tmp_path, raw, request)
    refusal(result, report, 'MBPF303')
    result, report, _output = lower(
        tmp_path, raw, request, permissive=True)
    refusal(result, report, 'MBPF303')


def test_skb_store_flags_refused(tmp_path):
    # The store flags stay pinned at zero in both modes.
    raw = capture(tmp_path, ROOT/SKB_SOURCES['store'], 'llvm')
    mutated = mutate_skb(
        tmp_path, raw, STORE_CALL,
        STORE_CALL.replace('i32 1, i64 0)', 'i32 1, i64 1)'))
    result, report, _output = lower(
        tmp_path, mutated, skb_spec('store'))
    refusal(result, report, 'MBPF314')
    result, report, _output = lower(
        tmp_path, mutated, skb_spec('store'), permissive=True)
    refusal(result, report, 'MBPF314')


def test_skb_store_payload_key_refused(tmp_path):
    # The store payload sits outside the map keys; key 0 stays
    # refused in both modes.
    raw = capture(tmp_path, ROOT/SKB_SOURCES['store'], 'llvm')
    mutated = mutate_skb(
        tmp_path, raw, STORE_KEYSLOT,
        STORE_KEYSLOT.replace('(i32 2)', '(i32 0)'))
    result, report, _output = lower(
        tmp_path, mutated, skb_spec('store'))
    refusal(result, report, 'MBPF314')
    result, report, _output = lower(
        tmp_path, mutated, skb_spec('store'), permissive=True)
    refusal(result, report, 'MBPF314')


def test_skb_store_second_prep_refused(tmp_path):
    # The store vector prepares exactly one payload slot; a
    # second stays refused in both modes.
    raw = capture(tmp_path, ROOT/SKB_SOURCES['store'], 'llvm')
    mutated = mutate_skb(
        tmp_path, raw, STORE_KEYSLOT,
        STORE_KEYSLOT + STORE_KEYSLOT.replace('%2 =', '%extra =', 1))
    result, report, _output = lower(
        tmp_path, mutated, skb_spec('store'))
    refusal(result, report, 'MBPF314')
    result, report, _output = lower(
        tmp_path, mutated, skb_spec('store'), permissive=True)
    refusal(result, report, 'MBPF314')


def test_skb_loadmap_lookup_for_update_refuses(tmp_path):
    # The loadmap vector pairs the load with one update; a
    # lookup in its place stays refused in both modes.
    raw = capture(tmp_path, ROOT/SKB_SOURCES['loadmap'], 'llvm')
    mutated = mutate_skb(
        tmp_path, raw, LOADMAP_UPDATE_CALL,
        '  %13 = call i64 @__mojobpf_lookup_v1(i64 %12, ptr %11)\n')
    mutated = mutate_skb(
        tmp_path, mutated, LOADMAP_UPDATE_DECL,
        'declare i64 @__mojobpf_lookup_v1(i64, ptr) #0\n')
    result, report, _output = lower(
        tmp_path, mutated, skb_spec('loadmap'))
    refusal(result, report, 'MBPF303')
    result, report, _output = lower(
        tmp_path, mutated, skb_spec('loadmap'), permissive=True)
    refusal(result, report, 'MBPF303')


def test_skb_loadmap_without_map_refuses(tmp_path):
    # The loadmap vector needs its array map; the same body
    # mapless stays refused in both modes.
    raw = capture(tmp_path, ROOT/SKB_SOURCES['loadmap'], 'llvm')
    request = skb_spec('loadmap')
    request['map'] = None
    result, report, _output = lower(tmp_path, raw, request)
    refusal(result, report, 'MBPF313')
    result, report, _output = lower(
        tmp_path, raw, request, permissive=True)
    refusal(result, report, 'MBPF313')


def test_skb_loadmap_key_collision_refused(tmp_path):
    # The loadmap keys stay dense 0..1; two preparations of
    # key 0 stay refused in both modes.
    raw = capture(tmp_path, ROOT/SKB_SOURCES['loadmap'], 'llvm')
    mutated = mutate_skb(
        tmp_path, raw, LOADMAP_KEY1,
        LOADMAP_KEY1.replace('(i32 1)', '(i32 0)'))
    result, report, _output = lower(
        tmp_path, mutated, skb_spec('loadmap'))
    refusal(result, report, 'MBPF314')
    result, report, _output = lower(
        tmp_path, mutated, skb_spec('loadmap'), permissive=True)
    refusal(result, report, 'MBPF314')


def test_skb_load_ctx_swapped_refuses(tmp_path):
    # The load takes the entry context itself; the buffer in
    # its place stays refused in both modes.
    raw = capture(tmp_path, ROOT/SKB_SOURCES['socket'], 'llvm')
    mutated = mutate_skb(
        tmp_path, raw, SOCKET_LOAD_CALL,
        SOCKET_LOAD_CALL.replace('ptr %0, i32 14', 'ptr %2, i32 14'))
    result, report, _output = lower(
        tmp_path, mutated, skb_spec('socket'))
    refusal(result, report, 'MBPF314')
    result, report, _output = lower(
        tmp_path, mutated, skb_spec('socket'), permissive=True)
    refusal(result, report, 'MBPF314')


STORE_TAIL = (
    '  %3 = call i64 @__mojobpf_skb_store_bytes_v1'
    '(ptr %0, i32 13, ptr %2, i32 1, i64 0)\n'
    '  %4 = icmp eq i64 %3, 0\n'
    '  %5 = xor i1 %4, true\n'
    '  %6 = select i1 %5, i32 2, i32 0\n'
    '  ret i32 %6\n')


def test_skb_helperless_key_still_refuses(tmp_path):
    # A key preparation with no consuming helper is outside
    # every vector in both modes (the mapless-Key admission
    # never stands alone).
    raw = capture(tmp_path, ROOT/SKB_SOURCES['store'], 'llvm')
    mutated = mutate_skb(
        tmp_path, raw, STORE_TAIL, '  ret i32 0\n')
    result, report, _output = lower(
        tmp_path, mutated, skb_spec('store'))
    refusal(result, report, 'MBPF303')
    result, report, _output = lower(
        tmp_path, mutated, skb_spec('store'), permissive=True)
    refusal(result, report, 'MBPF303')


def skb_lowered(tmp_path, kind):
    raw = capture(tmp_path, ROOT/SKB_SOURCES[kind], 'llvm')
    result, report, output = lower(
        tmp_path, raw, skb_spec(kind))
    lower_success(result, report, output)
    return raw, report, text_ir(output)


@pytest.mark.parametrize('kind', ['socket', 'store', 'loadmap'])
@pytest.mark.parametrize('bitcode', [False, True])
def test_skb_post_audit_accepts_actual_lowered(
        tmp_path, kind, bitcode):
    _, _, text = skb_lowered(tmp_path, kind)
    result, report = audit_lowered(
        tmp_path, text, skb_spec(kind), bitcode=bitcode)
    assert result.returncode == 0 and report['ok'] is True, \
        result.stderr + result.stdout


SKB_POST_MUTANTS = [
    ('socket', 'helper-id',
     'inttoptr (i64 26 to ptr)',
     'inttoptr (i64 27 to ptr)',
     'MBPF313'),
    ('socket', 'key-literal',
     'store i32 0, ptr %mojobpf.key',
     'store i32 5, ptr %mojobpf.key',
     'MBPF314'),
    ('socket', 'dropped-prep',
     '  store i32 0, ptr %mojobpf.key, align 4\n',
     '',
     'MBPF318'),
    ('store', 'store-flags',
     'i32 1, i64 0)',
     'i32 1, i64 1)',
     'MBPF314'),
    ('store', 'key-literal',
     'store i32 2, ptr %mojobpf.key',
     'store i32 0, ptr %mojobpf.key',
     'MBPF314'),
]


@pytest.mark.parametrize('bitcode', [False, True])
@pytest.mark.parametrize('kind,name,before,after,code', SKB_POST_MUTANTS)
def test_skb_post_audit_refuses_lowered_corruption(
        tmp_path, bitcode, kind, name, before, after, code):
    _, _, text = skb_lowered(tmp_path, kind)
    assert text.count(before) == 1, (name, text.count(before))
    corrupt = text.replace(before, after, 1)
    result, report = audit_lowered(
        tmp_path, corrupt, skb_spec(kind), bitcode=bitcode)
    assert result.returncode == 4 and report['ok'] is False, \
        result.stdout + result.stderr
    assert report['diagnostics'][0]['code'] == code, report
