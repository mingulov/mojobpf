# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Lane ownership validation and tool-allowlist lane runner.

Every test module belongs to exactly one lane (OWNERS). The runner
collects and runs one lane per process, refuses skipped or
deselected tests, and requires the observed nodes to equal the
expected nodes exactly. On guarded lanes the tool allowlist
additionally refuses forbidden or unadmitted tool executions.
"""
import argparse
import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import guard_runtime
except ImportError:
    guard_runtime = None

OWNERS = {
    'unit': (
        'tests/harness/test_process_guardian.py',
        'tests/harness/test_tool_admission.py',
        'tests/unit/test_artifact_publication.py',
        'tests/unit/test_ci_workflow_contract.py',
        'tests/unit/test_cleanup_guest_filter.py',
        'tests/unit/test_event_decoder.py',
        'tests/unit/test_exec_chain.py',
        'tests/unit/test_helpers.py',
        'tests/unit/test_hostile_inputs.py',
        'tests/unit/test_inspect_btf.py',
        'tests/unit/test_lane_lock.py',
        'tests/unit/test_manifest.py',
        'tests/unit/test_matrix_runner.py',
        'tests/unit/test_mirror_sync.py',
        'tests/unit/test_process_guardian.py',
        'tests/unit/test_safeio.py',
        'tests/unit/test_schema_conformance.py',
        'tests/unit/test_sdk_surface.py',
        'tests/unit/test_sealed_fs.py',
        'tests/unit/test_stray_map_filter.py',
        'tests/unit/test_suite_pin_ownership.py',
        'tests/unit/test_target_bootstrap.py',
        'tests/unit/test_target_controller.py',
        'tests/unit/test_validation_contracts.py',
    ),
    'package': (
        'tests/packaging/test_sdist_distribution.py',
        'tests/packaging/test_wheel_contents.py',
    ),
    'compiler': (
        'compiler/tests/test_ir_roundtrip.py',
        'compiler/tests/test_parsed_audit.py',
        'compiler/tests/test_parsed_elf.py',
        'compiler/tests/test_parsed_lowering.py',
        'compiler/tests/test_target_model.py',
        'compiler/tests/test_target_proof_table.py',
        'tests/codegen_cost/test_collect.py',
        'tests/compile/subset/test_subset_audit.py',
        'tests/compile/test_adapter_verify.py',
        'tests/compile/test_build_pipeline.py',
        'tests/compile/test_diagnostic_catalog.py',
        'tests/compile/test_example_cli_builds.py',
        'tests/compile/test_frontend_dialect.py',
        'tests/compile/test_probe_export.py',
        'tests/compile/test_route_dispatch.py',
        'tests/compile/test_subset_rejection.py',
        'tests/core/test_core_audit.py',
        'tests/core/test_core_build.py',
        'tests/core/test_core_object.py',
        'tests/differential/test_packets.py',
        'tests/differential/test_scalars.py',
        'tests/elf/test_artifact_contract.py',
        'tests/elf/test_combined_struct.py',
        'tests/elf/test_event_struct.py',
        'tests/elf/test_generalized_maps.py',
        'tests/elf/test_layouts.py',
        'tests/elf/test_map_btf.py',
        'tests/elf/test_map_contract.py',
        'tests/elf/test_minimal_object.py',
        'tests/elf/test_mutations.py',
        'tests/elf/test_net_struct.py',
        'tests/elf/test_packet_struct.py',
        'tests/elf/test_parse_struct.py',
        'tests/elf/test_reserve_struct.py',
        'tests/elf/test_subprog_struct.py',
        'tests/elf/test_tracepoint_struct.py',
        'tests/elf/test_uprobe_struct.py',
        'tests/ir/test_adapter_validation.py',
        'tests/ir/test_audit.py',
        'tests/ir/test_helper_lowering.py',
        'tests/ir/test_optimization_invariants.py',
        'tests/ir/test_probe_abi.py',
        'tests/packaging/test_adapter_generation.py',
        'tests/packaging/test_installed_build.py',
        'tests/packaging/test_installed_diagnostics.py',
        'tests/packaging/test_sdk_compat.py',
        'tests/kernel/test_btf_dualshape_bounds.py',
        'tests/unit/test_build_commands.py',
        'tests/unit/test_capability_inventory.py',
        'tests/unit/test_frontend_cfg_oracle.py',
        'tests/unit/test_guest_proc.py',
        'tests/unit/test_lock_refresh.py',
        'tests/unit/test_native_adapter.py',
        'tests/unit/test_nm_crosscheck.py',
        'tests/unit/test_portability_locks.py',
        'tests/unit/test_subset_kernel_build.py',
        'tests/unit/test_toolchain.py',
        'tests/unit/test_verify.py',
        'tests/verifier/test_subset_doc.py',
    ),
    'guest': (
        'tests/kernel/test_arch_portability.py',
        'tests/kernel/test_array_maps.py',
        'tests/kernel/test_cleanup.py',
        'tests/kernel/test_core_layouts.py',
        'tests/kernel/test_generalized_arrays.py',
        'tests/kernel/test_hash_maps.py',
        'tests/kernel/test_joint_stack.py',
        'tests/kernel/test_lru_maps.py',
        'tests/kernel/test_map_roundtrip.py',
        'tests/kernel/test_mojo_percpu.py',
        'tests/kernel/test_mojo_xdp.py',
        'tests/kernel/test_net_classifier.py',
        'tests/kernel/test_packet_sdk.py',
        'tests/kernel/test_parse_checksum_sdk.py',
        'tests/kernel/test_percpu_maps.py',
        'tests/kernel/test_ringbuf_reserve.py',
        'tests/kernel/test_subprog_calls.py',
        'tests/kernel/test_tracepoint_counter.py',
        'tests/kernel/test_tracepoint_events.py',
        'tests/kernel/test_tracing_lifecycle.py',
        'tests/kernel/test_uprobe_register.py',
        'tests/kernel/test_xdp_accounting.py',
        'tests/packaging/test_external_consumer.py',
        'tests/packaging/test_hash_consumer.py',
        'tests/packaging/test_reserve_consumer.py',
        'tests/packaging/test_subprog_consumer.py',
        'tests/packaging/test_uprobe_consumer.py',
        'tests/verifier/test_helper_licenses.py',
        'tests/verifier/test_subset_kernel.py',
    ),
}

# Lanes whose tool executions the guard supervises. The package and
# compiler lanes build with the toolchain (admitted by
# toolchains.lock.json, not the exec guard) and the guest lane runs
# under the tool-admission lease system, so those lanes validate
# ownership only.
GUARDED_LANES = ('unit',)

HOST_TOOLS = guard_runtime.HOST_TOOLS if guard_runtime else ()
FORBIDDEN = guard_runtime.FORBIDDEN if guard_runtime else None


def install_guard(marker, fixture_root):
    if guard_runtime is None:
        raise RuntimeError('guard runtime unavailable; refusing unguarded lane')
    # A prelude-started process already runs the guard from the
    # published copy: reinstall through that same module
    # instance, or the hooks double-wrap with split-brain
    # globals (the wrapper admits by one trust set while the
    # inner hook refuses by another).
    existing = sys.modules.get('guard_runtime_child')
    if existing is not None:
        existing.install_guard(str(marker), str(fixture_root))
        return
    guard_runtime.install_guard(str(marker), str(fixture_root))


def active():
    existing = sys.modules.get('guard_runtime_child')
    if existing is not None:
        return existing.active()
    return bool(guard_runtime) and guard_runtime.active()


def validate_ownership(files, nodes, owners):
    """Map every file and node to its lane; refuse drift either way."""
    by_file = {}
    for lane, modules in owners.items():
        for module in modules:
            if module in by_file:
                raise ValueError('duplicate file ownership: %s' % module)
            by_file[module] = lane
    for found in files:
        if found not in by_file:
            raise ValueError('unowned test file: %s' % found)
    for owned in by_file:
        if owned not in set(files):
            raise ValueError('owned test file absent: %s' % owned)
    by_node = {}
    for node in nodes:
        if node in by_node:
            raise ValueError('duplicate collected node: %s' % node)
        filepart = node.split('::', 1)[0]
        if filepart not in by_file:
            raise ValueError('unowned collected node: %s' % node)
        by_node[node] = by_file[filepart]
    return by_file, by_node


def required_result(results, lanes):
    """Gate exit: 0 only when every named lane reports success."""
    for lane in lanes:
        if results.get(lane) != 'success':
            return 2
    return 0


_PLUGIN_SOURCE = '''
import json
import os

STATE = {"nodes": [], "skipped": [], "deselected": [], "passed": 0, "failed": 0}


def pytest_collection_finish(session):
    STATE["nodes"] = [item.nodeid for item in session.items]


def pytest_collectreport(report):
    if report.skipped:
        STATE["skipped"].append(report.nodeid)


def pytest_deselected(items):
    STATE["deselected"].extend(item.nodeid for item in items)


def pytest_runtest_logreport(report):
    if report.when != "call" and not report.skipped:
        return
    if report.skipped:
        STATE["skipped"].append(report.nodeid)
    elif report.passed:
        STATE["passed"] += 1
    elif report.failed:
        STATE["failed"] += 1


def pytest_sessionfinish(session, exitstatus):
    STATE["exit"] = exitstatus
    with open(os.environ["LANES_REPORT_PATH"], "w") as handle:
        json.dump(STATE, handle)
'''


def _run_pytest(paths, report_path, workdir, collect_only=False):
    plugin = os.path.join(workdir, 'lanes_pytest_plugin.py')
    if not os.path.exists(plugin):
        with open(plugin, 'w', encoding='utf-8') as handle:
            handle.write(_PLUGIN_SOURCE)
    argv = [
        sys.executable, '-B', '-m', 'pytest', '-q', '--assert=plain',
        '-p', 'no:cacheprovider', '-p', 'lanes_pytest_plugin',
        '--rootdir', str(ROOT),
        '--import-mode=importlib', '-o', 'addopts=',
    ]
    if collect_only:
        argv.append('--collect-only')
    argv.extend(paths if isinstance(paths, list) else [paths])
    env = dict(os.environ)
    env['LANES_REPORT_PATH'] = str(report_path)
    # The runner owns pytest's flags completely: inherited
    # addopts could collect without executing (or deselect),
    # and autoloaded entry-point plugins are outside the
    # reviewed lane. Scrub both; the argv above is explicit.
    env.pop('PYTEST_ADDOPTS', None)
    env.pop('PYTEST_PLUGINS', None)
    env['PYTEST_DISABLE_PLUGIN_AUTOLOAD'] = '1'
    # Sibling imports between test modules (from test_x import ...)
    # resolve through sys.path even under --import-mode=importlib.
    # Every imported sibling name is unique across the tree, so
    # exposing all owned directories cannot mis-resolve. src/ is
    # exposed for the same reason the unit conftest adds it: every
    # worker must import mojobpf without depending on which
    # subtree's conftest loads.
    sibling_dirs = sorted(
        {str(ROOT / os.path.dirname(m)) for mods in OWNERS.values() for m in mods}
    )
    env['PYTHONPATH'] = os.pathsep.join(
        [workdir, str(ROOT / 'src')] + sibling_dirs + [env.get('PYTHONPATH', '')]
    )
    proc = subprocess.run(
        argv, cwd=str(ROOT), env=env, capture_output=True, text=True,
    )
    with open(report_path, encoding='utf-8') as handle:
        state = json.load(handle)
    state['proc_returncode'] = proc.returncode
    state['proc_stdout'] = proc.stdout
    state['proc_stderr'] = proc.stderr
    return state


def collect(paths):
    """Collect node IDs for paths; skipped or deselected nodes fail."""
    if isinstance(paths, str):
        paths = [paths]
    workdir = tempfile.mkdtemp(prefix='lanes-collect-')
    try:
        report = os.path.join(workdir, 'collect.json')
        state = _run_pytest(paths, report, workdir, collect_only=True)
        if state['skipped'] or state['deselected']:
            raise ValueError(
                'collection skipped or deselected: %r %r'
                % (state['skipped'], state['deselected'])
            )
        if state['proc_returncode'] != 0:
            raise ValueError(
                'collection failed: %s%s'
                % (state['proc_stdout'][-2000:], state['proc_stderr'][-2000:])
            )
        return state['nodes']
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def run_tests(paths, report):
    """Run paths in a fresh process; write the per-module report."""
    if isinstance(paths, str):
        paths = [paths]
    workdir = os.path.dirname(os.path.abspath(report))
    state = _run_pytest(paths, report, workdir)
    outcome = {
        'nodes': state['nodes'],
        'passed': state['passed'],
        'failed': state['failed'],
        'exit': 0,
    }
    if state['skipped'] or state['deselected'] or not state['nodes']:
        outcome['exit'] = 2
    elif state['passed'] + state['failed'] != len(state['nodes']):
        # Every collected node must show a call report: a
        # collection-only run (passed=failed=0) is not a pass.
        outcome['exit'] = 2
    elif state['failed'] or state['proc_returncode'] != 0:
        outcome['exit'] = 1
    with open(report, 'w', encoding='utf-8') as handle:
        json.dump(outcome, handle)
    return outcome


def run_lane(lane, work):
    """Run one lane module-per-process; return the process exit code."""
    modules = list(OWNERS[lane])
    expected_path = os.path.join(work, 'expected.json')
    expected_nodes = collect(modules)
    with open(expected_path, 'w', encoding='utf-8') as handle:
        json.dump({'nodes': expected_nodes}, handle)
    observed = []
    module_results = {}
    for index, module in enumerate(modules):
        report = os.path.join(work, 'module-%d.json' % index)
        outcome = run_tests([module], report)
        observed.extend(outcome['nodes'])
        module_results[module] = 'success' if outcome['exit'] == 0 else 'failure'
    validate_ownership(modules, observed, {lane: tuple(modules)})
    if sorted(observed) != sorted(expected_nodes) or len(observed) != len(expected_nodes):
        print('observed nodes differ from collected nodes', file=sys.stderr)
        return 2
    summary = {
        'lane': lane,
        'modules': len(modules),
        'selected_nodes': len(expected_nodes),
        'observed_nodes': len(observed),
        'passed': sum(1 for value in module_results.values() if value == 'success'),
        'exit': required_result(module_results, tuple(modules)),
    }
    print(json.dumps(summary))
    return summary['exit']


def matrix_suites():
    """Read the VM matrix suites via AST (never import the runner)."""
    source = Path(ROOT) / 'ci' / 'run_vm_tests.py'
    tree = ast.parse(source.read_text(encoding='utf-8'))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', '') == 'SUITES':
            return ast.literal_eval(node.value)
    raise ValueError('SUITES not found in ci/run_vm_tests.py')


def inventory():
    """Closed-world report: files, nodes, matrix suites, direct mapping."""
    # The runner owns the mapping; it is not itself a mapped module.
    files = sorted(
        str(path.relative_to(ROOT))
        for path in Path(ROOT).rglob('test_*.py')
        if '__pycache__' not in path.parts and '.pixi' not in path.parts
        and path.relative_to(ROOT) != Path('ci/test_lanes.py')
    )
    owned = [module for modules in OWNERS.values() for module in modules]
    nodes = collect(owned)
    by_file, by_node = validate_ownership(files, nodes, OWNERS)
    suites = matrix_suites()
    direct = {}
    for name, path, _timeout in suites:
        if by_file.get(path) != 'guest':
            raise ValueError('matrix suite not guest-owned: %s' % path)
        direct[path] = 'matrix:%s' % name
    return {
        'files': by_file,
        'nodes': by_node,
        'direct': direct,
        'matrix_suites': [list(entry) for entry in suites],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(prog='test_lanes.py')
    parser.add_argument('--lane', default='unit')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--collect-only', action='store_true')
    parser.add_argument('--guard-tools', action='store_true')
    args = parser.parse_args(argv)
    if args.lane not in OWNERS:
        print('unknown lane: %s' % args.lane, file=sys.stderr)
        return 2
    try:
        if args.check:
            print(json.dumps(inventory()))
            return 0
        if args.collect_only:
            print(json.dumps(collect(list(OWNERS[args.lane]))))
            return 0
        work = tempfile.mkdtemp(prefix='lane-%s-' % args.lane)
        marker = os.path.join(work, 'attempts.jsonl')
        if args.guard_tools:
            if args.lane in GUARDED_LANES:
                install_guard(marker, str(ROOT))
            else:
                print(
                    'lane %s runs ownership-only under --guard-tools '
                    '(toolchain admitted by toolchains.lock.json; guest '
                    'tools by the tool-admission lease system)' % args.lane
                )
        outcome = run_lane(args.lane, work)
        if os.path.exists(marker):
            print('forbidden tool attempt(s) recorded', file=sys.stderr)
            return 1
        return outcome
    except (ValueError, OSError, RuntimeError) as exc:
        print('%s' % exc, file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
