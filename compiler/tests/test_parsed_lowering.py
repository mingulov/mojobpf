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
