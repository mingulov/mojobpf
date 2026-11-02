# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Executable lane ownership and tool-allowlist contract controls.

This file pins the replacement guard's real policy: which test
modules belong to which lane, and which tool executions the lane
runner admits or refuses. Dropped R11 pins are recorded inline
with a rationale, never silently.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
SELECTOR = ROOT / 'ci/test_lanes.py'


@pytest.fixture
def lanes():
    assert SELECTOR.is_file(), 'executable lane ownership is missing'
    spec = importlib.util.spec_from_file_location('ci_test_lanes_contract', SELECTOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_unknown_file_and_node_cannot_disappear(lanes):
    owners = {'unit': ('tests/unit/test_known.py',)}
    lanes.validate_ownership(['tests/unit/test_known.py'], ['tests/unit/test_known.py::test_a'], owners)
    with pytest.raises(ValueError, match='unowned'):
        lanes.validate_ownership(['tests/unit/test_known.py', 'tests/unit/test_new.py'], [], owners)
    with pytest.raises(ValueError, match='unowned'):
        lanes.validate_ownership(['tests/unit/test_known.py'], ['tests/packaging/test_new.py::test_a'], owners)


def test_duplicate_file_and_collected_node_are_rejected(lanes):
    name = 'tests/unit/test_known.py'
    with pytest.raises(ValueError, match='duplicate'):
        lanes.validate_ownership([name], [name + '::test_a'], {'unit': (name,), 'compiler': (name,)})
    with pytest.raises(ValueError, match='duplicate.*node'):
        lanes.validate_ownership([name], [name + '::test_a'] * 2, {'unit': (name,)})


def test_collection_has_exact_file_and_node_owners(lanes):
    result = subprocess.run([sys.executable, '-B', str(SELECTOR), '--check'], cwd=ROOT,
                            capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, (result.stdout, result.stderr)
    report = json.loads(result.stdout)
    assert len(report['nodes']) > 1000
    assert report['nodes']['tests/unit/test_ci_workflow_contract.py::test_unknown_file_and_node_cannot_disappear'] == 'unit'
    assert report['files']['compiler/tests/test_target_model.py'] == 'compiler'
    assert len(report['matrix_suites']) == 25
    assert report['direct']['tests/kernel/test_mojo_xdp.py'] == 'matrix:kernel-xdp'


def guarded(lanes, tmp_path, code):
    marker = tmp_path / 'attempts.jsonl'
    bootstrap = ('import importlib.util; '
                 f's=importlib.util.spec_from_file_location("guard", {str(SELECTOR)!r}); '
                 'g=importlib.util.module_from_spec(s); s.loader.exec_module(g); '
                 f'g.install_guard({str(marker)!r}, {str(tmp_path)!r});\n' + code +
                 f'\nraise SystemExit(1 if __import__("pathlib").Path({str(marker)!r}).exists() else 0)')
    result = subprocess.run([sys.executable, '-B', '-c', bootstrap], cwd=ROOT,
                            capture_output=True, text=True, timeout=60)
    return result, marker


def private_lane(tmp_path, modules):
    for name, text in modules.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    paths = sorted(modules)
    code = ('import importlib.util; from pathlib import Path; '
            f's=importlib.util.spec_from_file_location("private_lane", {str(SELECTOR)!r}); '
            'm=importlib.util.module_from_spec(s); s.loader.exec_module(m); '
            f'm.ROOT=Path({str(tmp_path)!r}); m.OWNERS={{"unit":{paths!r}}}; '
            'raise SystemExit(m.main(["--lane", "unit", "--guard-tools"]))')
    return subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True, timeout=120)


@pytest.mark.parametrize('state', ['failure', 'cancelled', 'skipped', 'missing', 'queued', 'in_progress'])
def test_full_result_requires_all_results_successful(lanes, state):
    assert lanes.required_result({'source': 'success', 'compiler': state, 'guest': 'success'}, ('source', 'compiler', 'guest')) == 2
    assert lanes.required_result({'source': 'success', 'guest': 'success'}, ('source', 'compiler', 'guest')) == 2
    assert lanes.required_result({'source': 'success', 'compiler': 'success', 'guest': 'success'}, ('source', 'compiler', 'guest')) == 0


def test_required_import_skip_cannot_pass_lane(lanes, tmp_path):
    result = private_lane(tmp_path, {
        'tests/unit/test_a.py': 'def test_pass(): pass\n',
        'tests/unit/test_b.py': 'import pytest\npytest.skip("required dependency missing", allow_module_level=True)\n',
    })
    assert result.returncode == 2, (result.stdout, result.stderr)
    assert 'skip' in (result.stdout + result.stderr).lower()


def test_required_import_skip_cannot_pass_collection(lanes, tmp_path):
    path = tmp_path / 'test_required.py'
    path.write_text('import pytest\npytest.skip("required dependency missing", allow_module_level=True)\n')
    passing = tmp_path / 'test_passing.py'
    passing.write_text('def test_pass(): pass\n')
    with pytest.raises(ValueError, match='skip'):
        lanes.collect([str(path), str(passing)])


def test_modules_do_not_share_process_global_state(lanes, tmp_path):
    result = private_lane(tmp_path, {
        'tests/unit/test_a.py': 'def test_changes_process_state():\n import os\n os.environ["CI_OWNED_PROCESS_STATE"]="changed"\n',
        'tests/unit/test_b.py': 'def test_starts_clean():\n import os\n assert "CI_OWNED_PROCESS_STATE" not in os.environ\n',
    })
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert '2' in result.stdout


# DROPPED R11 pins (ownership group), each with rationale:
# - native-preflight contract (--check-prerequisites + MOJOBPF_CI_NATIVE_CONTRACT):
#   no counterpart exists at tip; the compiler lane runs pytest with no native gate.
# - workflow executor/gate pins (pull_request_target, permissions, required gates):
#   they pin the R11 branch's workflow jobs, which do not exist at tip; workflow
#   shape is CI-owned, not guard-owned.


@pytest.mark.parametrize('tool', ['cc', 'c++', 'clang', 'llc', 'llvm-config', 'mojo', 'mojobpf-lower', 'mojobpf-frame-audit', 'vng', 'qemu-system-x86_64', 'bpftool', 'cmake'])
def test_caught_tool_attempt_still_fails(lanes, tmp_path, tool):
    result, marker = guarded(lanes, tmp_path,
        'import subprocess\ntry: subprocess.run([' + repr('/nonexistent/' + tool) + ', "--version"])\nexcept OSError: pass')
    assert result.returncode == 1, result.stderr
    assert tool in marker.read_text()


def test_absolute_real_compiler_is_refused_without_execution(lanes, tmp_path):
    compiler = shutil.which('cc') or '/usr/bin/cc'
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess\ntry: subprocess.run([{compiler!r}, "--version"])\nexcept OSError: pass')
    assert result.returncode == 1, result.stderr
    assert marker.is_file()
    assert 'gcc' not in result.stdout.lower()


@pytest.mark.parametrize('name,interpreter', [('mojo', sys.executable), ('llc', '/bin/sh'), ('bpftool', '/bin/sh')])
def test_owned_fixture_named_like_tool_is_allowed(lanes, tmp_path, name, interpreter):
    fixture = tmp_path / name
    fixture.write_text('#!' + interpreter + '\n' + ('print("fixture-owned")\n' if name == 'mojo' else 'echo fixture-owned\n'))
    fixture.chmod(0o755)
    result, marker = guarded(lanes, tmp_path, f'import subprocess\nsubprocess.run([{str(fixture)!r}], check=True)')
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'fixture-owned'
    assert not marker.exists()


def test_unowned_tool_script_is_refused(lanes, tmp_path):
    result, marker = guarded(lanes, tmp_path,
        'import subprocess\ntry: subprocess.run(["/opt/toolchain/bin/mojo"])\nexcept OSError: pass')
    assert result.returncode == 1, result.stderr
    assert marker.exists()


def test_second_install_still_refuses_tool(lanes, tmp_path):
    # R11 L1717 without the guard-digests.json assert: no digest
    # cache file exists (freshness is structural), but a second
    # install sharing the marker still refuses and journals.
    compiler = shutil.which('cc') or '/usr/bin/cc'
    result, marker = guarded(lanes, tmp_path, 'pass')
    assert result.returncode == 0, result.stderr
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess\ntry: subprocess.run([{compiler!r}, "--version"])\nexcept OSError: pass')
    assert result.returncode == 1, result.stderr
    assert compiler in marker.read_text()


def test_mixed_native_module_cannot_enter_host_lane(lanes, tmp_path):
    # R11 L172 without the 'portable lane refused tool execution'
    # message assert: that message does not exist at tip. The
    # refusal and its journal entry are the surviving policy.
    code = ('import sys,pytest; sys.path.insert(0, "src"); '
            'pytest.main(["-q", "--assert=plain", "-p", "no:cacheprovider", '
            '"tests/unit/test_native_adapter.py::test_native_runtime_closure_mapping_is_observational"])')
    result, marker = guarded(lanes, tmp_path, code)
    assert result.returncode == 1, result.stderr
    assert '/usr/bin/cc' in marker.read_text()


# DROPPED R11 pins (digest-cache group): the rewritten-same-stats
# rehash test and the changed-stats rehash test pin the
# guard-digests.json cache file, which does not exist. Freshness is
# structural: every spawn's digest is computed fresh, with no memo,
# so the staleness class cannot occur.


def test_child_python_cannot_hide_a_caught_attempt(lanes, tmp_path):
    child = 'import subprocess\ntry: subprocess.run(["/nonexistent/llc", "--version"])\nexcept OSError: pass'
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess,sys\nsubprocess.run([sys.executable, "-I", "-S", "-c", {child!r}], env={{}})')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert 'llc' in marker.read_text()


def test_guard_preserves_virtual_environment_executable(lanes, tmp_path):
    venv = tmp_path / 'venv'
    (venv / 'bin').mkdir(parents=True)
    (venv / 'pyvenv.cfg').write_text('home = ' + str(Path(sys.executable).resolve().parent) + '\ninclude-system-site-packages = false\n')
    python = venv / 'bin/python'
    python.symlink_to(sys.executable)
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess\np=subprocess.run([{str(python)!r}, "-c", "import sys; print(sys.prefix)"], check=True, capture_output=True, text=True)\nassert p.stdout.strip() == {str(venv)!r}, p.stdout')
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


def test_guard_resolution_is_independent_of_test_which_patch(lanes, tmp_path):
    result, marker = guarded(lanes, tmp_path,
        'import subprocess,shutil\nshutil.which=lambda name: "/fake/"+name\nsubprocess.run(["git", "--version"], check=True)')
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


# The shell_true variant arrives with the T4 shell gate (it needs
# -c program peeling); executable and shell_fixture pin direct and
# fixture propagation.
@pytest.mark.parametrize('launcher', ['executable', 'shell_fixture'])
def test_indirect_python_cannot_remove_guard(lanes, tmp_path, launcher):
    child = 'import subprocess\ntry: subprocess.run(["/nonexistent/llc"])\nexcept OSError: pass'
    if launcher == 'executable':
        command = f'subprocess.run(["python-control", "-c", {child!r}], executable=sys.executable)'
    else:
        import shlex
        script = shlex.join([sys.executable, '-c', child])
        if launcher == 'shell_true':
            command = f'subprocess.run({script!r}, shell=True)'
        else:
            fixture = tmp_path / 'shell-fixture'
            fixture.write_text('#!/bin/sh\n' + script + '\n')
            fixture.chmod(0o755)
            command = f'subprocess.run([{str(fixture)!r}])'
    result, marker = guarded(lanes, tmp_path, f'import subprocess,sys\ntry: {command}\nexcept OSError: pass')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()


# The bwrap variant of the wrapper test is dropped: a --ro-bind /
# remount refuses upfront (the journal cannot survive it), so the
# llc-inside-bwrap journal pin is unrepresentable. The system
# variant arrives with the T4 shell gate (os.system needs -c
# program peeling).
@pytest.mark.parametrize('launcher', ['relative'])
def test_review_child_wrappers_keep_attempt_marker(lanes, tmp_path, launcher):
    child = 'import subprocess\ntry: subprocess.run(["/nonexistent/llc"])\nexcept OSError: pass'
    (tmp_path / 'child').symlink_to(sys.executable)
    statement = f'subprocess.run(["./child", "-c", {child!r}], cwd={str(tmp_path)!r})'
    result, marker = guarded(lanes, tmp_path, f'import subprocess,sys\n{statement}')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert 'llc' in marker.read_text()


@pytest.mark.parametrize('launcher', ['assignment', 'relative-path', 'ignore-environment', 'unset',
                                      'split-string', 'split-shebang'])
def test_env_context_keeps_or_refuses_child_guard(lanes, tmp_path, launcher):
    import shlex
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    (bindir / 'child').symlink_to(sys.executable)
    child = 'import subprocess\ntry: subprocess.run(["/nonexistent/llc"])\nexcept OSError: pass'
    prefix = []
    if launcher == 'ignore-environment':
        prefix = ['-i']
        child = 'import os; assert "CI_OWNED_PARENT" not in os.environ\n' + child
    elif launcher == 'unset':
        prefix = ['-u', 'CI_OWNED_PARENT']
        child = 'import os; assert "CI_OWNED_PARENT" not in os.environ\n' + child
    path = 'bin' if launcher == 'relative-path' else str(bindir)
    argv = ['/usr/bin/env'] + prefix + ['PATH=' + path, 'child', '-c', child]
    if launcher == 'split-string':
        argv = ['/usr/bin/env', '-S', shlex.join([sys.executable, '-c', child])]
    elif launcher == 'split-shebang':
        script = tmp_path / 'env-split-script'
        script.write_text('#!/usr/bin/env -S ' + sys.executable + '\n' + child + '\n')
        script.chmod(0o755)
        argv = [str(script)]
    result, marker = guarded(lanes, tmp_path,
        'import subprocess,os\nos.environ["CI_OWNED_PARENT"]="present"\n'
        f'try: subprocess.run({argv!r}, cwd={str(tmp_path)!r}, check=True)\nexcept OSError: pass')
    assert result.returncode == 1, (result.stdout, result.stderr)
    attempts = [json.loads(line)['argv'] for line in marker.read_text().splitlines()]
    if launcher.startswith('split-'):
        assert any(argv[0] == 'unsupported-env-option' for argv in attempts)
    else:
        assert ['/nonexistent/llc'] in attempts


def test_preexec_replaced_executable_is_readmitted(lanes, tmp_path):
    prog = tmp_path / 'prog'
    prog.write_bytes(Path(shutil.which('true')).read_bytes())
    prog.chmod(0o755)
    canary = tmp_path / 'launched'
    code = ('import subprocess,os\n'
            f'prog={str(prog)!r}\n'
            f'canary={str(canary)!r}\n'
            'def hop():\n'
            '    open(prog, "w").write("#!/bin/sh\\ntouch " + canary + "\\n/nonexistent/llc --version\\n")\n'
            '    os.execv(prog, [prog])\n'
            'try: subprocess.run([prog], preexec_fn=hop)\n'
            'except Exception as exc: print("EXC", type(exc).__name__)\n')
    result, marker = guarded(lanes, tmp_path, code)
    assert 'SubprocessError' in result.stdout, (result.stdout, result.stderr)
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert 'llc' in marker.read_text()
    assert not canary.exists(), 'replaced executable launched'


def test_install_failure_shadow_stdlib_kills_payload(lanes, tmp_path):
    evil = tmp_path / 'evil'
    evil.mkdir()
    (evil / 'json.py').write_text('raise RuntimeError("evil shadow")\n')
    canary = tmp_path / 'payload-started'
    payload = f'from pathlib import Path; Path("{canary}").touch()\nprint("SHOULD-NOT-PRINT")'
    site = tmp_path / 'guard-site'
    code = ('import subprocess,os,sys\n'
            f'evil = {str(evil)!r}\n'
            f'site = {str(site)!r}\n'
            'env = dict(os.environ)\n'
            'rest = env.get("PYTHONPATH", "")\n'
            'env["PYTHONPATH"] = evil + os.pathsep + site + (os.pathsep + rest if rest else "")\n'
            f'proc = subprocess.run([sys.executable, "-c", {payload!r}], env=env)\n'
            'print("CHILD-RC", proc.returncode)\n')
    result, marker = guarded(lanes, tmp_path, code)
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert 'CHILD-RC 0' not in result.stdout, result.stdout
    assert not canary.exists(), 'poisoned child must not execute the payload'
    assert 'SHOULD-NOT-PRINT' not in result.stdout
    lines = marker.read_text().splitlines()
    assert lines, 'install failure must leave journal evidence'
    for line in lines:
        json.loads(line)


def test_install_failure_corrupt_runtime_kills_payload(lanes, tmp_path):
    canary = tmp_path / 'payload-started'
    payload = f'from pathlib import Path; Path("{canary}").touch()\nprint("SHOULD-NOT-PRINT")'
    runtime = tmp_path / 'guard-runtime.py'
    site = tmp_path / 'guard-site'
    code = ('import subprocess,os,sys\n'
            'from pathlib import Path\n'
            f'Path({str(runtime)!r}).write_text("def broken(:\\n")\n'
            f'site = {str(site)!r}\n'
            'env = dict(os.environ)\n'
            'rest = env.get("PYTHONPATH", "")\n'
            'env["PYTHONPATH"] = site + (os.pathsep + rest if rest else "")\n'
            f'proc = subprocess.run([sys.executable, "-c", {payload!r}], env=env)\n'
            'print("CHILD-RC", proc.returncode)\n')
    result, marker = guarded(lanes, tmp_path, code)
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert 'CHILD-RC 0' not in result.stdout, result.stdout
    assert not canary.exists(), 'child with corrupt runtime must not execute the payload'
    assert 'SHOULD-NOT-PRINT' not in result.stdout
    lines = marker.read_text().splitlines()
    assert lines, 'install failure must leave journal evidence'
    for line in lines:
        json.loads(line)


def test_install_publishes_runtime_and_site(lanes, tmp_path):
    result, marker = guarded(lanes, tmp_path, 'pass')
    assert result.returncode == 0, result.stderr
    assert (tmp_path / 'guard-runtime.py').is_file()
    assert (tmp_path / 'guard-site' / 'sitecustomize.py').is_file()


# DROPPED R11 pins (install/propagation machinery): torn-cache
# recovery, masked-corruption bytecode specifics, concurrent site
# restore and concurrent publication pin machinery with no
# surviving behavior; the bwrap journal-exfil pin needs the static
# analyzer; the stub-read pins need the stub model.
