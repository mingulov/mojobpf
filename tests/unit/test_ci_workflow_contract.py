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

# Trust inputs snapshotted at import (collection, before any test
# runs): every guarded child installs from these, so a test that
# mutates os.environ cannot contaminate a later child's trust.
_HELPER_PATH = os.environ.get('PATH', os.defpath)
_HELPER_TEMPS = {key: os.environ[key] for key in ('TMPDIR', 'TEMP', 'TMP') if key in os.environ}


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
    # The child installs from collection-time trust inputs: denied
    # names scrubbed, PATH and temp dirs reset. Anything else
    # (HOME, CI_OWNED_*, lane vars) inherits, so propagation tests
    # keep working and the install cannot see test mutations.
    denied = lanes.guard_runtime._denied_env_name
    env = {key: value for key, value in os.environ.items() if not denied(key)}
    env['PATH'] = _HELPER_PATH
    for key in ('TMPDIR', 'TEMP', 'TMP'):
        if key in _HELPER_TEMPS:
            env[key] = _HELPER_TEMPS[key]
        else:
            env.pop(key, None)
    result = subprocess.run([sys.executable, '-B', '-c', bootstrap], cwd=ROOT,
                            capture_output=True, text=True, timeout=60, env=env)
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


@pytest.mark.parametrize('launcher', ['executable', 'shell_true', 'shell_fixture'])
def test_indirect_python_cannot_remove_guard(lanes, tmp_path, launcher):
    # Single-line payload (no ; or newline), so the shell forms
    # reach the injection path instead of the compound refusal;
    # the journal must hold the real llc attempt argv.
    child = '__import__("subprocess").run(["/nonexistent/llc"])'
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
    if launcher == 'shell_fixture':
        # The fixture executes python outside the polyglot shape,
        # so it refuses wholesale at the screen (the quoted llc
        # is data to the shell); the other forms journal the
        # inner attempt from the guarded child.
        assert 'owned-fixture-python-execute' in marker.read_text()
    else:
        attempts = [json.loads(line)['argv'] for line in marker.read_text().splitlines()]
        assert ['/nonexistent/llc'] in attempts


# The bwrap variant of the wrapper test is dropped: a --ro-bind /
# remount refuses upfront (the journal cannot survive it), so the
# llc-inside-bwrap journal pin is unrepresentable.
@pytest.mark.parametrize('launcher', ['system', 'relative'])
def test_review_child_wrappers_keep_attempt_marker(lanes, tmp_path, launcher):
    # Single-line payload (no ; or newline), so the system form
    # reaches the injection path instead of the compound
    # refusal; the journal must hold the real llc attempt argv.
    child = '__import__("subprocess").run(["/nonexistent/llc"])'
    if launcher == 'system':
        import shlex
        statement = f'__import__("os").system({shlex.join([sys.executable, "-c", child])!r})'
    else:
        (tmp_path / 'child').symlink_to(sys.executable)
        statement = f'subprocess.run(["./child", "-c", {child!r}], cwd={str(tmp_path)!r})'
    result, marker = guarded(lanes, tmp_path, f'import subprocess,sys\n{statement}')
    assert result.returncode == 1, (result.stdout, result.stderr)
    attempts = [json.loads(line)['argv'] for line in marker.read_text().splitlines()]
    assert ['/nonexistent/llc'] in attempts


@pytest.mark.parametrize('launcher', ['system', 'shell', 'compound'])
def test_shell_python_alias_retains_or_refuses_guard(lanes, tmp_path, launcher):
    # A renamed python stays a renamed tool under shell heads:
    # strict per-name checking refuses the alias before any
    # injection could run. The compound form keeps its ';'
    # suffix and pins the launcher refusal instead.
    import shlex
    alias = tmp_path / 'child'
    alias.symlink_to(sys.executable)
    child = '__import__("subprocess").run(["/nonexistent/llc"])'
    command = shlex.join([str(alias), '-c', child])
    if launcher == 'shell':
        statement = f'subprocess.run({command!r}, shell=True)'
    else:
        command += '; :' if launcher == 'compound' else ''
        statement = f'__import__("os").system({command!r})'
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess\ntry: {statement}\nexcept OSError: pass')
    assert result.returncode == 1, (result.stdout, result.stderr)
    if launcher == 'compound':
        assert 'unsupported-python-shell-launcher' in marker.read_text()
    else:
        assert 'unadmitted-shell-head' in marker.read_text()


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
    code = ('import subprocess,os,sys\n'
            f'evil = {str(evil)!r}\n'
            'env = dict(os.environ)\n'
            'rest = env.get("PYTHONPATH", "")\n'
            'env["PYTHONPATH"] = evil + (os.pathsep + rest if rest else "")\n'
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
    code = ('import subprocess,os,sys\n'
            'from pathlib import Path\n'
            f'Path({str(runtime)!r}).write_text("def broken(:\\n")\n'
            f'proc = subprocess.run([sys.executable, "-c", {payload!r}])\n'
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


def test_install_publishes_runtime_only(lanes, tmp_path):
    # The prelude is the only propagation channel (it verifies
    # the copy and journals install failures itself); no
    # sitecustomize layer ships.
    result, marker = guarded(lanes, tmp_path, 'pass')
    assert result.returncode == 0, result.stderr
    assert (tmp_path / 'guard-runtime.py').is_file()
    assert not (tmp_path / 'guard-site').exists()


# DROPPED R11 pins (install/propagation machinery): torn-cache
# recovery, masked-corruption bytecode specifics, concurrent site
# restore and concurrent publication pin machinery with no
# surviving behavior; the bwrap journal-exfil pin needs the static
# analyzer; the stub-read pins need the stub model.


def test_shell_absolute_compiler_is_refused(lanes, tmp_path):
    result, marker = guarded(lanes, tmp_path,
        'import subprocess\ntry: subprocess.run(["/bin/sh", "-c", "/usr/bin/cc --version"])\nexcept OSError: pass')
    assert result.returncode == 1, result.stderr
    assert marker.is_file()


def test_shell_cannot_execute_unadmitted_renamed_elf(lanes, tmp_path):
    fixture = tmp_path / 'unadmitted-native-control'
    fixture.write_bytes(Path(shutil.which('true')).read_bytes() + b'owned inert identity mutation')
    fixture.chmod(0o755)
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess\ntry: subprocess.run(["/bin/sh", "-c", {str(fixture)!r}])\nexcept OSError: pass')
    assert result.returncode == 1, result.stderr
    assert 'unadmitted-native-control' in marker.read_text()


@pytest.mark.parametrize('form', ['direct', 'variable'])
def test_tilde_tool_command_is_refused(lanes, tmp_path, monkeypatch, form):
    home = tmp_path / 'owned-home'
    home.mkdir()
    (home / 'evil-cc').symlink_to(shutil.which('cc') or '/usr/bin/cc')
    monkeypatch.setenv('HOME', str(home))
    command = '~/evil-cc --version' if form == 'direct' else 'tool=~/evil-cc; $tool --version'
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess\ntry: subprocess.run(["/bin/bash", "-c", {command!r}])\nexcept OSError: pass')
    assert result.returncode == 1, (form, result.stdout, result.stderr)
    assert marker.exists(), form
    assert 'gcc' not in result.stdout.lower()


def feature_probe_driver(stage, kind):
    import shlex
    variable, requested = ('MAP_TYPE', 'array') if kind == 'map' else ('PROG_TYPE', 'xdp')
    prefix = 'map_type' if kind == 'map' else 'program_type'
    body = f'grep -F "{prefix} ${variable} is" "$STAGE/feature.txt" | head -1 || true'
    return (f'STAGE={shlex.quote(str(stage))}\n{variable}={requested}\n'
            f'line=$({body})\nprintf "%s" "$line"')


@pytest.mark.parametrize('kind', ['map', 'program'])
def test_readonly_feature_probe_substitution_keeps_outputs(lanes, tmp_path, kind):
    stage = tmp_path / 'feature sp ace-é-\'"-$HOME-`id`-;|&'
    stage.mkdir()
    (stage / 'feature.txt').write_text(
        'eBPF map_type array is available\neBPF map_type array is NOT available\n'
        'eBPF program_type xdp is available\neBPF program_type xdp is NOT available\n')
    command = feature_probe_driver(stage, kind)
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess\nsubprocess.run(["/bin/bash", "-c", {command!r}], check=True)')
    expected = 'eBPF map_type array is available' if kind == 'map' else 'eBPF program_type xdp is available'
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected
    assert not marker.exists()


@pytest.mark.parametrize('form', ['unquoted', 'double-quoted', 'nested', 'unterminated'])
def test_active_substitution_cannot_hide_caught_tool_attempt(lanes, tmp_path, form):
    import shlex
    child = 'import subprocess\ntry: subprocess.run(["/nonexistent/llc"])\nexcept OSError: pass'
    invocation = shlex.join([sys.executable, '-c', child])
    command = 'out=$(' + invocation + ')'
    if form == 'double-quoted':
        command = 'out="$(' + invocation + ')"'
    elif form == 'nested':
        command = 'out=$(printf "%s" $(' + invocation + '))'
    elif form == 'unterminated':
        command = 'out=$(' + invocation
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess\ntry: subprocess.run(["/bin/bash", "-c", {command!r}])\nexcept OSError: pass')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()


@pytest.mark.parametrize('shadow', ['owned-script', 'other-host-role', 'child-other-host-role'])
def test_readonly_probe_requires_admitted_leaf_identity(lanes, tmp_path, shadow):
    stage = tmp_path / 'feature'
    stage.mkdir()
    (stage / 'feature.txt').write_text('eBPF map_type array is available\n')
    bindir = tmp_path / 'shadow'
    bindir.mkdir()
    canary = tmp_path / 'shadow-launched'
    if shadow == 'owned-script':
        (bindir / 'grep').write_text('#!' + sys.executable + '\nfrom pathlib import Path\n'
                                   f'Path({str(canary)!r}).touch()\n')
        (bindir / 'grep').chmod(0o755)
    else:
        (bindir / 'grep').symlink_to(shutil.which('head'))
    command = feature_probe_driver(stage, 'map')
    launch = (f'subprocess.run(["/bin/bash", "-c", {command!r}], '
              f'env={{**os.environ,"PATH":{str(bindir)!r}+os.pathsep+os.environ["PATH"]}})')
    if shadow == 'child-other-host-role':
        child = 'import subprocess,os\n' + launch
        launch = (f'subprocess.run([sys.executable,"-c",{child!r}], '
                  f'env={{**os.environ,"PATH":{str(bindir)!r}+os.pathsep+os.environ["PATH"]}})')
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess,sys,os\ntry: {launch}\nexcept OSError: pass')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert not canary.exists()


ADMITTED_SHELLS = {
    'nested-printf': ('out=$(printf "%s" $(printf nested-ok))\nprintf "%s" "$out"',
                      'nested-ok'),
    'nested-timeout-mktemp': ('d=$(timeout 60 mktemp -d)\nrm -r "$d"\nprintf "%s" ok',
                              'ok'),
    'nested-quoted-inner': ('o=$(printf "%s" "$(printf deep)")\nprintf "%s" "$o"',
                            'deep'),
    'arith-basic': ('printf "%s" $((1 + 2 * 3))', '7'),
    'arith-param-default': ('n=1\nprintf "%s" $((n + ${STEP:-5}))', '6'),
    'arith-grouped': ('printf "%s" $(((_cb_dead * 1000 - 1) / 1000))', '0'),
    'arith-command': ('((x = 6 * 7))\nprintf "%s" "$x"', '42'),
    'arith-c-for': ('s=0\nfor ((i = 0; i < 3; i++)); do s=$((s + i)); done\nprintf "%s" "$s"',
                    '3'),
    'arith-shift-not-heredoc': ('((x = 1 << 4))\nprintf "%s" "$x"', '16'),
    'heredoc-literal': ('cat <<\'EOF\'\nliteral `x` $(y) "q" \'s\'\nEOF',
                        'literal `x` $(y) "q" \'s\'\n'),
    'heredoc-piped': ('cat <<\'E\' | tr a b\na\nE', 'b\n'),
    'heredoc-in-substitution': ('out=$(cat <<\'EOF\'\ndata $(x) `y`\nEOF\n)\nprintf "%s" "$out"',
                                'data $(x) `y`'),
    'heredoc-strip-tabs': ('cat <<-\'E\'\n\tindented\nE', 'indented\n'),
    'timeout-python-leaf': ('v=$(timeout 60 python3 -c \'print(40 + 2)\')\nprintf "%s" "$v"',
                            '42'),
    'pipe-python-leaf': ('printf \'a\\n\' | python3 -c \'import sys; print("b")\'',
                         'b\n'),
    'pipe-python-leaf-env': ('printf \'a\\n\' | TAG=x python3 -c \'print("t")\'',
                             't\n'),
    'tool-name-in-string-is-data': ('printf "%s" "bpftool v0.0-fixture"',
                                    'bpftool v0.0-fixture'),
}


@pytest.mark.parametrize('name', sorted(ADMITTED_SHELLS))
def test_guarded_execution_admits_bounded_shells(lanes, tmp_path, name):
    command, expected = ADMITTED_SHELLS[name]
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess\nsubprocess.run(["/bin/bash", "-c", {command!r}], check=True)')
    assert result.returncode == 0, (name, result.stderr)
    assert result.stdout == expected, name
    assert not marker.exists(), name


REFUSED_SHELLS = [
    'out=$(printf "%s" $(/usr/bin/cc --version))',
    'out=`printf hi`',
    'out=$(printf "%s" `printf hi`)',
    'printf "%s" $((1 + `printf 2`))',
    'cat <<EOF\ntext\nEOF',
    'printf "%s" $((1 + $(printf 2)))',
    'printf "%s" $((1; 2))',
    'printf "%s" $((a + "b"))',
    "printf '%s' $((a + 'b'))",
    'printf "%s" $((1 + (2))',
    '((x = $(printf 1)))',
    'out=$(echo (hi))',
    'python3 -c \'print("p")\' | cat',
    'false || python3 -c \'print("p")\'',
    'python3 -c \'print("p")\'; echo done',
    'timeout 60 python3 -c \'import subprocess;subprocess.run(["/nonexistent/llc"])\'',
    'printf hi\r\n',
]


@pytest.mark.parametrize('command', REFUSED_SHELLS)
def test_guarded_execution_refuses_unbounded_shells(lanes, tmp_path, command):
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess\ntry: subprocess.run(["/bin/bash", "-c", {command!r}])\nexcept OSError: pass')
    assert result.returncode == 1, (command, result.stdout, result.stderr)
    assert marker.exists(), command


def test_arith_inherited_evil_expansion_is_refused(lanes, tmp_path, monkeypatch):
    monkeypatch.setenv('R11_ARITH_X', 'a[$(/usr/bin/cc --version >&2)]')
    command = 'printf "%s" "$((R11_ARITH_X))"'
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess\ntry: subprocess.run(["/bin/bash", "-c", {command!r}])\nexcept OSError: pass')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert 'gcc' not in (result.stdout + result.stderr).lower()


def test_fixture_shell_launcher_expands_owned_target(lanes, tmp_path):
    target = tmp_path / 'real/mojo'
    target.parent.mkdir()
    target.write_text('#!/bin/sh\necho owned-target\n')
    target.chmod(0o755)
    launcher = tmp_path / 'mojo'
    launcher.write_text('#!/bin/sh\nTC=' + str(target.parent) + '\nexec "$TC/mojo" "$@"\n')
    launcher.chmod(0o755)
    result, marker = guarded(lanes, tmp_path, f'import subprocess\nsubprocess.run([{str(launcher)!r}], check=True)')
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'owned-target'
    assert not marker.exists()


def test_arith_r15_argv0_login_inspected(lanes, tmp_path):
    home = tmp_path / 'argvhome'
    home.mkdir()
    alias_file = ("shopt -s expand_aliases\nalias bash=/bin/bash\n")
    (home / '.bash_profile').write_text(alias_file)
    stubdir = tmp_path / 'argvstubbin'
    stubdir.mkdir()
    stub = stubdir / 'bash'
    stub.write_text('#!' + sys.executable + '\npass\n')
    stub.chmod(0o755)
    evil = tmp_path / 'argv-evil.sh'
    evil.write_text('#!/bin/bash\n/usr/bin/cc --version\n')
    evil.chmod(0o755)
    command = f'bash {evil}'
    result, marker = guarded(lanes, tmp_path,
        f'import os, subprocess\nenv = dict(os.environ)\nenv["PATH"] = {str(stubdir)!r} + os.pathsep + env["PATH"]\nenv["HOME"] = {str(home)!r}\n'
        f'try: subprocess.run(["-bash", "-c", {command!r}], executable="/bin/bash", env=env)\nexcept OSError: pass')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert 'forbidden-execution' in marker.read_text()
    assert 'gcc' not in result.stdout.lower()


def test_arith_r15_argv0_login_execv_inspected(lanes, tmp_path):
    home = tmp_path / 'exechome'
    home.mkdir()
    alias_file = ("shopt -s expand_aliases\nalias bash=/bin/bash\n")
    (home / '.bash_profile').write_text(alias_file)
    stubdir = tmp_path / 'execstubbin'
    stubdir.mkdir()
    stub = stubdir / 'bash'
    stub.write_text('#!' + sys.executable + '\npass\n')
    stub.chmod(0o755)
    evil = tmp_path / 'exec-evil.sh'
    evil.write_text('#!/bin/bash\n/usr/bin/cc --version\n')
    evil.chmod(0o755)
    command = f'bash {evil}'
    kid = ('import importlib.util, os; '
           f's=importlib.util.spec_from_file_location("g", {str(SELECTOR)!r}); '
           'g=importlib.util.module_from_spec(s); s.loader.exec_module(g); '
           f'g.install_guard({str(tmp_path / "attempts.jsonl")!r}, {str(tmp_path)!r}); '
           'env = dict(os.environ); '
           f'env["PATH"] = {str(stubdir)!r} + os.pathsep + env["PATH"]; '
           f'env["HOME"] = {str(home)!r}; '
           f'os.execve("/bin/bash", ["-bash", "-c", {command!r}], env)')
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess, sys\n'
        f'subprocess.run([sys.executable, "-B", "-c", {kid!r}])')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert 'forbidden-execution' in marker.read_text()
    assert 'gcc' not in result.stdout.lower()


def test_arith_r15_argv0_plain_divergent_still_runs(lanes, tmp_path):
    command = 'echo hi'
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess\nsubprocess.run(["custom0", "-c", {command!r}], executable="/bin/bash", check=True)')
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout == 'hi\n'
    assert not marker.exists()


def test_arith_r15_argv0_login_benign_still_runs(lanes, tmp_path):
    home = tmp_path / 'argvbenignhome'
    home.mkdir()
    command = 'echo hi'
    result, marker = guarded(lanes, tmp_path,
        f'import os, subprocess\nenv = dict(os.environ)\nenv["HOME"] = {str(home)!r}\n'
        f'subprocess.run(["-bash", "-c", {command!r}], executable="/bin/bash", check=True, env=env)')
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout == 'hi\n'
    assert not marker.exists()


def test_arith_r15_argv0_nested_exec_a_benign_still_runs(lanes, tmp_path):
    command = 'exec -a custom0 bash -c "echo hi"'
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess\nsubprocess.run(["/bin/bash", "-c", {command!r}], check=True)')
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout == 'hi\n'
    assert not marker.exists()


def _screen_r22_script(zone, name, body):
    target = zone / name
    target.write_text(body)
    target.chmod(0o755)
    return target


def _screen_r22_refused(result, marker):
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert 'forbidden-execution' in marker.read_text()
    assert 'gcc' not in result.stdout.lower()
    assert 'cc (ubuntu' not in result.stdout.lower()


def test_screen_r22_env_wrapper_refuses(lanes, tmp_path):
    zone = tmp_path / 'sw'
    zone.mkdir()
    script = _screen_r22_script(zone, 'helper.sh',
                                '#!/bin/sh\n/usr/bin/cc --version\n')
    command = f'env {script} --version'
    result, marker = guarded(lanes, tmp_path,
        'import subprocess\ntry: subprocess.run(["/bin/bash", "-c", '
        + repr(command) + '], env={"PATH": "/usr/bin:/bin"})'
        '\nexcept OSError: pass')
    _screen_r22_refused(result, marker)


def test_screen_r22_timeout_wrapper_refuses(lanes, tmp_path):
    zone = tmp_path / 'st'
    zone.mkdir()
    script = _screen_r22_script(zone, 'helper.sh',
                                '#!/bin/sh\n/usr/bin/cc --version\n')
    command = f'timeout 10 {script} --version'
    result, marker = guarded(lanes, tmp_path,
        'import subprocess\ntry: subprocess.run(["/bin/bash", "-c", '
        + repr(command) + '], env={"PATH": "/usr/bin:/bin"})'
        '\nexcept OSError: pass')
    _screen_r22_refused(result, marker)


def test_screen_r22_sudo_wrapper_refuses(lanes, tmp_path):
    zone = tmp_path / 'ss'
    zone.mkdir()
    script = _screen_r22_script(zone, 'helper.sh',
                                '#!/bin/sh\n/usr/bin/cc --version\n')
    command = f'sudo -n {script} --version'
    result, marker = guarded(lanes, tmp_path,
        'import subprocess\ntry: subprocess.run(["/bin/bash", "-c", '
        + repr(command) + '], env={"PATH": "/usr/bin:/bin"})'
        '\nexcept OSError: pass')
    _screen_r22_refused(result, marker)


def test_screen_r22_find_exec_refuses(lanes, tmp_path):
    zone = tmp_path / 'sf'
    zone.mkdir()
    (zone / 'hay').mkdir()
    script = _screen_r22_script(zone, 'helper.sh',
                                '#!/bin/sh\n/usr/bin/cc --version\n')
    command = f'find {zone}/hay -exec {script} --version \\;'
    result, marker = guarded(lanes, tmp_path,
        'import subprocess\ntry: subprocess.run(["/bin/bash", "-c", '
        + repr(command) + '], env={"PATH": "/usr/bin:/bin"})'
        '\nexcept OSError: pass')
    _screen_r22_refused(result, marker)


def test_screen_r22_xargs_refuses(lanes, tmp_path):
    zone = tmp_path / 'sx'
    zone.mkdir()
    script = _screen_r22_script(zone, 'helper.sh',
                                '#!/bin/sh\n/usr/bin/cc --version\n')
    command = f'echo hi | xargs {script} --version'
    result, marker = guarded(lanes, tmp_path,
        'import subprocess\ntry: subprocess.run(["/bin/bash", "-c", '
        + repr(command) + '], env={"PATH": "/usr/bin:/bin"})'
        '\nexcept OSError: pass')
    _screen_r22_refused(result, marker)


def test_screen_r22_innocent_direct_evil_refuses(lanes, tmp_path):
    zone = tmp_path / 'sde'
    zone.mkdir()
    script = _screen_r22_script(zone, 'helper.sh',
                                '#!/bin/sh\n/usr/bin/cc --version\n')
    result, marker = guarded(lanes, tmp_path,
        'import subprocess\ntry: subprocess.run([' + repr(str(script)) + ']'
        ', env={"PATH": "/usr/bin:/bin"})'
        '\nexcept OSError: pass')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert 'forbidden-execution' in marker.read_text()
    assert 'gcc' not in result.stdout.lower()


def test_arith_xargs_unmodeled_boundary_is_refused(lanes, tmp_path, tmp_path_factory):
    # The shadow rides the per-spawn PATH (untrusted by design);
    # the install samples the clean helper PATH, so this pins
    # resolution-time shadowing rather than install contamination.
    compiler = shutil.which('cc') or '/usr/bin/cc'
    shadow = tmp_path_factory.mktemp('r9ext-xargs')
    shutil.copy(compiler, shadow / 'xargs')
    command = 'printf a | xargs echo'
    result, marker = guarded(lanes, tmp_path,
        'import subprocess,os\n'
        f'shadow = {str(shadow)!r}\n'
        'env = dict(os.environ)\n'
        'env["PATH"] = shadow + os.pathsep + "/usr/bin" + os.pathsep + "/bin"\n'
        f'try: subprocess.run(["/bin/bash", "-c", {command!r}], env=env)\nexcept OSError: pass')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert 'xargs' in marker.read_text()


def test_arith_r12_eq_word_native_command_is_refused(lanes, tmp_path):
    tool = shutil.which('objcopy') or '/usr/bin/objcopy'
    payload = tmp_path / 'payload=tool'
    shutil.copy(tool, payload)
    payload.chmod(0o755)
    src = tmp_path / 'src'
    src.write_text('x')
    canary = tmp_path / 'canary'
    command = f'{payload} -I binary -O binary "{src}" "{canary}"'
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess\ntry: subprocess.run(["/bin/bash", "-c", {command!r}])\nexcept OSError: pass')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert str(payload) in marker.read_text()
    assert not canary.exists()


def test_digest_cache_survives_shadowed_stdlib_json(lanes, tmp_path):
    evil = tmp_path / 'evil'
    evil.mkdir()
    (evil / 'json.py').write_text(
        f"open({str(tmp_path / 'SHADOW.marker')!r}, 'w').write('shadow')\n")
    code = ('import subprocess,sys,os\n'
            'env=dict(os.environ)\n'
            f'env["PYTHONPATH"]={str(evil)!r}\n'
            'proc=subprocess.run([sys.executable, "-P", "-c", "import json"], env=env)\n'
            'assert proc.returncode == 0, proc.returncode\n')
    result, marker = guarded(lanes, tmp_path, code)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (tmp_path / 'SHADOW.marker').is_file(), 'shadow must have executed'
    assert not marker.exists()


def test_bwrap_cannot_hide_required_guard_journal(lanes, tmp_path):
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess,sys\ntry: subprocess.run(["bwrap", "--ro-bind", "/", "/", "--tmpfs", {str(tmp_path)!r}, "--", sys.executable, "-c", "pass"])\nexcept OSError: pass')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert 'bwrap-guard-journal-overlap' in marker.read_text()


def test_route_r23_noshebang_owned_refuses(lanes, tmp_path):
    # Owned-fixture allowlist requires #!: an owned, executable,
    # regular file under the fixture root WITHOUT a shebang line
    # is not an owned fixture, so a direct spawn refuses with a
    # forbidden-execution journal entry and PermissionError (no
    # shell-fallback execution).
    script = tmp_path / 'nosheb'
    script.write_text('/usr/bin/cc --version\n')
    script.chmod(0o755)
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess\n'
        f'try: subprocess.run([{str(script)!r}, "--version"])\n'
        f'except PermissionError: print("REFUSED-PermissionError")')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert 'REFUSED-PermissionError' in result.stdout, (result.stdout, result.stderr)
    assert marker.exists()
    events = [json.loads(line)['event'] for line in marker.read_text().splitlines() if line.strip()]
    assert 'forbidden-execution' in events, marker.read_text()
    assert 'gcc' not in result.stdout.lower()
    assert 'cc (ubuntu' not in result.stdout.lower()


def test_route_r23_noshebang_explicit_runs(lanes, tmp_path):
    # Explicit-interpreter twin: invoking shebangless text through
    # an explicit shell with non--c argv runs marker-free; the
    # script operand is argv data, never routed.
    script = tmp_path / 'plain'
    script.write_text('echo EXPLICIT-OK\n')
    script.chmod(0o755)
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess\nsubprocess.run(["/bin/bash", {str(script)!r}], check=True)')
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert 'EXPLICIT-OK' in result.stdout, result.stdout
    assert not marker.exists()


@pytest.mark.parametrize('behavior', ['normal', 'caught'])
def test_owned_pip_shell_entrypoint_keeps_python_guard(lanes, tmp_path, behavior):
    import shlex
    wrapper = tmp_path / 'owned-entrypoint'
    body = ('import sys; print("owned-entrypoint", sys.argv[1])\n' if behavior == 'normal' else
            'import subprocess\ntry: subprocess.run(["/nonexistent/llc"])\nexcept OSError: pass\n')
    wrapper.write_text("#!/bin/sh\n'''exec' " + shlex.quote(sys.executable)
                       + ' "$0" "$@"\n' + "' '''\n" + body)
    wrapper.chmod(0o755)
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess\nsubprocess.run([{str(wrapper)!r}, "argument"], check=True)')
    if behavior == 'normal':
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == 'owned-entrypoint argument'
        assert not marker.exists()
    else:
        # R11 expected the inner llc spawn journaled; without a
        # shell-semantics engine the wrapper refuses wholesale:
        # its bytes statically name a forbidden tool.
        assert result.returncode == 1, (result.stdout, result.stderr)
        assert marker.exists()
        events = [json.loads(line) for line in marker.read_text().splitlines()]
        refused = [e for e in events if e.get('event') == 'forbidden-execution']
        assert refused, events
        assert any(e.get('argv') == [str(wrapper)] for e in refused), events
        assert any(e.get('reason') == 'owned-fixture-forbidden-token' for e in refused), events


def test_renamed_wrapper_keeps_peel_and_inject(lanes, tmp_path):
    # A renamed copy of env must peel like env (dispatch by
    # digest, not spelling): the python child stays guarded.
    renamed = tmp_path / 'renamed-env'
    shutil.copy('/usr/bin/env', renamed)
    renamed.chmod(0o755)
    child = 'import subprocess\ntry: subprocess.run(["/nonexistent/llc"])\nexcept OSError: pass'
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess,sys\nsubprocess.run([{str(renamed)!r}, sys.executable, "-c", {child!r}], check=True)')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert 'llc' in marker.read_text()


def test_private_scratch_script_is_owned(lanes, tmp_path):
    # A script under an euid-owned 0700 scratch dir outside the
    # fixture root is test-owned: screened like any other fixture.
    import tempfile
    scratch = Path(tempfile.mkdtemp(prefix='owned-scratch-'))
    script = scratch / 'helper.sh'
    script.write_text('#!/bin/sh\necho scratch-owned\n')
    script.chmod(0o755)
    try:
        result, marker = guarded(lanes, tmp_path,
            f'import subprocess\nsubprocess.run(["/bin/sh", {str(script)!r}], check=True)')
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'scratch-owned'
    assert not marker.exists()


def test_private_home_script_is_unowned(lanes, tmp_path):
    # Scratch ownership applies only under real scratch roots: an
    # euid-private home directory does not make its scripts
    # test-owned (otherwise every pipx/pixi binary under a 0700
    # home would shadow admitted heads).
    probe = Path.home() / ('guard-home-probe-%d' % os.getpid())
    probe.mkdir(mode=0o700, exist_ok=True)
    script = probe / 'helper.sh'
    script.write_text('#!/bin/sh\necho should-not-run\n')
    script.chmod(0o755)
    try:
        result, marker = guarded(lanes, tmp_path,
            f'import subprocess\ntry: subprocess.run(["/bin/sh", {str(script)!r}])\nexcept OSError: pass')
    finally:
        try:
            script.unlink()
            probe.rmdir()
        except OSError:
            pass
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert 'should-not-run' not in result.stdout


def test_shared_tmp_top_level_script_is_unowned(lanes, tmp_path):
    # /tmp itself is world-writable: a script placed directly in
    # it is not test-owned and refuses.
    import tempfile
    fd, name = tempfile.mkstemp(prefix='unowned-top-')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write('#!/bin/sh\necho should-not-run\n')
        os.chmod(name, 0o755)
        result, marker = guarded(lanes, tmp_path,
            f'import subprocess\ntry: subprocess.run(["/bin/sh", {name!r}])\nexcept OSError: pass')
    finally:
        try:
            os.unlink(name)
        except OSError:
            pass
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert 'should-not-run' not in result.stdout


def test_lane_program_echo_hello_exit_runs(lanes, tmp_path):
    # Real unit-lane program (guest_proc owned-runner shape): pinned
    # here so the exact admission survives data refactors.
    result, marker = guarded(lanes, tmp_path,
        'import subprocess\np = subprocess.run(["bash", "-c", "echo hello; exit 3"])\nassert p.returncode == 3, p.returncode')
    assert result.returncode == 0, result.stderr
    assert result.stdout == 'hello\n', repr(result.stdout)
    assert not marker.exists()


def test_sequence_shell_command_runs_without_double_wrap(lanes, tmp_path):
    # shell=True with a sequence joins like CPython ([sh, -c] +
    # args); the guard checks that argv and must not join again.
    result, marker = guarded(lanes, tmp_path,
        'import subprocess\nsubprocess.run(["printf seq-shell-ok"], shell=True, check=True)')
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout == 'seq-shell-ok'
    assert not marker.exists()


def test_sequence_shell_forbidden_command_is_refused(lanes, tmp_path):
    # Checking a shell=True sequence as a direct spawn would pass
    # it through (the joined words resolve to nothing) while the
    # shell parses and runs the compiler.
    result, marker = guarded(lanes, tmp_path,
        'import subprocess\ntry: subprocess.run(["cc --version"], shell=True)\nexcept OSError: pass')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert 'cc' in marker.read_text()
    assert 'gcc' not in result.stdout.lower()


def test_str_shell_command_runs_without_double_wrap(lanes, tmp_path):
    # shell=True with a string must run the command once: joining
    # the guard's already-joined argv a second time would execute
    # a bare shell on stdin instead of the program.
    result, marker = guarded(lanes, tmp_path,
        'import subprocess\nsubprocess.run("printf wrap-probe-ok", shell=True, check=True)')
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout == 'wrap-probe-ok'
    assert not marker.exists()


def test_system_python_launcher_stays_guarded(lanes, tmp_path):
    # os.system must execute the checked argv, not the raw
    # command: a python launcher needs its prelude injection.
    # Single-line payload (no ; or newline), so the shell gate
    # reaches the injection path instead of the compound
    # refusal; the journal must hold the real llc attempt argv.
    import shlex
    child = '__import__("subprocess").run(["/nonexistent/llc"])'
    statement = f'__import__("os").system({shlex.join([sys.executable, "-c", child])!r})'
    result, marker = guarded(lanes, tmp_path, f'import subprocess\n{statement}')
    assert result.returncode == 1, (result.stdout, result.stderr)
    attempts = [json.loads(line)['argv'] for line in marker.read_text().splitlines()]
    assert ['/nonexistent/llc'] in attempts


def test_system_basic_output_and_status_parity(lanes, tmp_path):
    result, marker = guarded(lanes, tmp_path,
        'import os\nr1 = os.system("printf sys-ok")\nr2 = os.system("false")\nprint("RC", r1, r2)')
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout == 'sys-okRC 0 256\n', repr(result.stdout)
    assert not marker.exists()


def test_str_pathlike_bytes_direct_spawn_runs(lanes, tmp_path):
    result, marker = guarded(lanes, tmp_path,
        'import subprocess\nfrom pathlib import Path\n'
        'assert subprocess.run("/bin/true").returncode == 0\n'
        'assert subprocess.run(Path("/bin/true")).returncode == 0\n'
        'assert subprocess.run(b"/bin/true").returncode == 0\n')
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert not marker.exists()


def test_str_form_forbidden_tool_is_refused(lanes, tmp_path):
    result, marker = guarded(lanes, tmp_path,
        'import subprocess\ntry: subprocess.run("/usr/bin/cc")\nexcept OSError: pass')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert 'forbidden-name' in marker.read_text()


def test_empty_path_entry_resolves_cwd_and_screens(lanes, tmp_path):
    # An empty PATH entry means cwd to execvp; the guard must
    # resolve (and screen) the same bytes the kernel runs.
    import tempfile
    zone = Path(tempfile.mkdtemp(prefix='empty-path-'))
    zone.chmod(0o755)
    script = zone / 'pwn'
    script.write_text('#!/bin/sh\necho should-not-run\n')
    script.chmod(0o755)
    try:
        result, marker = guarded(lanes, tmp_path,
            'import subprocess,os\n'
            f'os.chdir({str(zone)!r})\n'
            'env = dict(os.environ)\n'
            'env["PATH"] = "" + os.pathsep + "/usr/bin" + os.pathsep + "/bin"\n'
            'try: subprocess.run(["pwn"], env=env)\nexcept OSError: pass')
    finally:
        shutil.rmtree(zone, ignore_errors=True)
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert 'should-not-run' not in result.stdout


def test_shell_stdin_program_is_refused(lanes, tmp_path):
    # -s reads the program from stdin, invisible to argv rules.
    result, marker = guarded(lanes, tmp_path,
        'import subprocess\ntry: subprocess.run(["sh", "-s", "positional"])\nexcept OSError: pass')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert 'stdin-program' in marker.read_text()


@pytest.mark.parametrize('name', ['BASH_ENV', 'ENV', 'GCONV_PATH'])
def test_stage_loader_delegation_assignment_is_refused(lanes, tmp_path, name):
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess\ntry: subprocess.run(["sh", "-c", {name + "=/evil printf ok"!r}])\nexcept OSError: pass')
    assert result.returncode == 1, (name, result.stdout, result.stderr)
    assert marker.exists()


def test_direct_env_loader_assignment_is_refused(lanes, tmp_path):
    result, marker = guarded(lanes, tmp_path,
        'import subprocess\ntry: subprocess.run(["/usr/bin/env", "LD_PRELOAD=/evil.so", "printf", "ok"])\nexcept OSError: pass')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert 'ok' not in result.stdout


def test_spawn_env_loader_addition_is_refused(lanes, tmp_path):
    result, marker = guarded(lanes, tmp_path,
        'import subprocess,os\n'
        'env = dict(os.environ)\n'
        'env["LD_PRELOAD"] = "/evil.so"\n'
        'try: subprocess.run(["printf", "ok"], env=env)\nexcept OSError: pass')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert 'ok' not in result.stdout


def test_inherited_env_loader_mutation_is_refused(lanes, tmp_path):
    result, marker = guarded(lanes, tmp_path,
        'import subprocess,os\n'
        'os.environ["BASH_ENV"] = "/evil.sh"\n'
        'try: subprocess.run(["printf", "ok"])\nexcept OSError: pass')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()


def test_spawn_env_pythonpath_passes(lanes, tmp_path):
    # Lane workers need PYTHONPATH; the prelude resolves its
    # runtime by absolute path, so the name stays exempt.
    result, marker = guarded(lanes, tmp_path,
        'import subprocess,os,sys\n'
        'env = dict(os.environ)\n'
        f'env["PYTHONPATH"] = {str(tmp_path)!r}\n'
        'subprocess.run([sys.executable, "-c", "pass"], env=env, check=True)')
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert not marker.exists()


def test_env_shebang_loader_assignment_is_refused(lanes, tmp_path):
    fixture = tmp_path / 'ld-preload-fixture'
    fixture.write_text(f'#!/usr/bin/env LD_PRELOAD=/evil.so {sys.executable}\nprint("should-not-run")\n')
    fixture.chmod(0o755)
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess\ntry: subprocess.run([{str(fixture)!r}])\nexcept OSError: pass')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert 'should-not-run' not in result.stdout


def test_oversize_fixture_refuses_without_partial_screen(lanes, tmp_path):
    fixture = tmp_path / 'oversize-fixture.sh'
    with open(fixture, 'w', encoding='utf-8') as handle:
        handle.write('#!/bin/sh\n')
        for _ in range(20000):
            handle.write('# padding-padding-padding-padding-padding-padding-pad\n')
        handle.write('/usr/bin/cc --version\n')
    fixture.chmod(0o755)
    assert fixture.stat().st_size > 1048576
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess\ntry: subprocess.run([{str(fixture)!r}])\nexcept OSError: pass')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert 'owned-fixture-too-large' in marker.read_text()
    assert 'gcc' not in result.stdout.lower()


def test_deep_wrapper_nesting_refuses_cleanly(lanes, tmp_path):
    # Wrapper chains terminate in a journaled refusal, never a
    # bare RecursionError without evidence.
    result, marker = guarded(lanes, tmp_path,
        'import subprocess\ntry: subprocess.run(["env"] * 25 + ["printf", "ok"])\nexcept OSError: pass')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert 'nesting-too-deep' in marker.read_text()
    assert 'RecursionError' not in result.stderr


def test_shallow_wrapper_nesting_runs(lanes, tmp_path):
    result, marker = guarded(lanes, tmp_path,
        'import subprocess\nsubprocess.run(["timeout", "60", "/usr/bin/env", "FOO=bar", "printf", "nest-ok"], check=True)')
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout == 'nest-ok'
    assert not marker.exists()


def test_reinstall_resets_verdicts_and_trust(lanes, tmp_path):
    # A plant trusted under one install must refuse after a
    # reinstall that no longer samples it: neither the verdict
    # memo nor the python digest set may survive. Both spawns
    # share one explicit spawn PATH, so only the reinstall
    # distinguishes them.
    plantdir = tmp_path / 'plant-reinstall'
    plantdir.mkdir()
    planted = plantdir / 'python3'
    shutil.copy('/usr/bin/sed', planted)
    planted.chmod(0o755)
    code = (
        'import os,subprocess\n'
        f'plant = {str(planted)!r}\n'
        f'pdir = {str(plantdir)!r}\n'
        f'root = {str(tmp_path)!r}\n'
        'os.environ["PATH"] = pdir + os.pathsep + "/usr/bin" + os.pathsep + "/bin"\n'
        'g.install_guard(root + "/m2.jsonl", root)\n'
        'fixed = {"PATH": "/usr/bin" + os.pathsep + "/bin"}\n'
        'first = subprocess.run([plant, "-c", "pass"], env=fixed)\n'
        'print("FIRST-RC", first.returncode)\n'
        'os.environ["PATH"] = "/usr/bin" + os.pathsep + "/bin"\n'
        'g.install_guard(root + "/m3.jsonl", root)\n'
        'try: subprocess.run([plant, "-c", "pass"], env=fixed)\n'
        'except OSError: print("SECOND-REFUSED")\n'
    )
    result, marker = guarded(lanes, tmp_path, code)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert 'SECOND-REFUSED' in result.stdout, (result.stdout, result.stderr)
    assert (tmp_path / 'm3.jsonl').is_file()


def test_propagated_install_inherits_parent_trust(lanes, tmp_path):
    # A grandchild installs from the parent's baked trust, never
    # from its own (test-mutated) environment: a planted python3
    # on a mutated PATH refuses instead of joining the trust set.
    plantdir = tmp_path / 'plant-inherit'
    plantdir.mkdir()
    planted = plantdir / 'python3'
    shutil.copy('/usr/bin/sed', planted)
    planted.chmod(0o755)
    grandchild = (
        'import subprocess\n'
        'try: subprocess.run(["python3", "-c", "pass"])\n'
        'except OSError: print("GRANDCHILD-REFUSED")\n'
    )
    code = (
        'import os,subprocess,sys\n'
        f'pdir = {str(plantdir)!r}\n'
        'os.environ["PATH"] = pdir + os.pathsep + os.environ["PATH"]\n'
        f'subprocess.run([sys.executable, "-c", {grandchild!r}], check=True)\n'
    )
    result, marker = guarded(lanes, tmp_path, code)
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert 'GRANDCHILD-REFUSED' in result.stdout


def test_scratch_roots_snapshot_at_install(lanes, tmp_path):
    # A TMPDIR set after install must not widen ownership: the
    # scratch roots are install-time trust, inherited downhill.
    probe = Path.home() / ('guard-tmpdir-probe-%d' % os.getpid())
    for temp in _HELPER_TEMPS.values():
        if str(probe).startswith(temp + os.sep):
            pytest.skip('probe directory overlaps the install temp dir')
    probe.mkdir(mode=0o700, exist_ok=True)
    try:
        result, marker = guarded(lanes, tmp_path,
            'import os,subprocess,tempfile\n'
            f'os.environ["TMPDIR"] = {str(probe)!r}\n'
            'tempfile.tempdir = None\n'
            'zone = tempfile.mkdtemp(prefix="evil-")\n'
            'script = os.path.join(zone, "helper.sh")\n'
            'open(script, "w").write("#!/bin/sh\\\\necho should-not-run\\\\n")\n'
            'os.chmod(script, 0o755)\n'
            'try: subprocess.run(["/bin/sh", script])\n'
            'except OSError: print("TMPDIR-REFUSED")\n')
    finally:
        shutil.rmtree(probe, ignore_errors=True)
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert 'should-not-run' not in result.stdout


def test_tampered_runtime_copy_kills_grandchild(lanes, tmp_path):
    # The prelude verifies the published copy before loading it:
    # a neutered install-guard replacement dies 99 with journal
    # evidence instead of running the payload unguarded.
    payload = 'import subprocess\nsubprocess.run(["cc", "--version"])\nprint("PAYLOAD-RAN")\n'
    code = (
        'import subprocess,sys\n'
        'from pathlib import Path\n'
        f'runtime = Path({str(tmp_path / "guard-runtime.py")!r})\n'
        'text = runtime.read_text()\n'
        'text = text.replace("subprocess.Popen.__init__ = _guarded_init", "pass  # neutered")\n'
        'text = text.replace("sys.addaudithook(_audit_hook)", "pass  # neutered")\n'
        'assert "neutered" in text\n'
        'runtime.write_text(text)\n'
        f'proc = subprocess.run([sys.executable, "-c", {payload!r}])\n'
        'print("GC-RC", proc.returncode)\n'
    )
    result, marker = guarded(lanes, tmp_path, code)
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert 'guard-install-failure' in marker.read_text()
    assert 'GC-RC 99' in result.stdout
    assert 'PAYLOAD-RAN' not in result.stdout


def test_bwrap_symlink_dest_refuses_overlap(lanes, tmp_path):
    link = tmp_path / 'guardlink'
    link.symlink_to(tmp_path, target_is_directory=True)
    result, marker = guarded(lanes, tmp_path,
        f'import subprocess\ntry: subprocess.run(["bwrap", "--bind", "/bin/sh", {str(link)!r}, "--", "true"])\nexcept OSError: pass')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert 'bwrap-guard-journal-overlap' in marker.read_text()


def test_bwrap_relative_dest_refuses(lanes, tmp_path):
    result, marker = guarded(lanes, tmp_path,
        'import subprocess\ntry: subprocess.run(["bwrap", "--bind", "/bin/sh", "relative-dest", "--", "true"])\nexcept OSError: pass')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert 'unsupported-bwrap-option' in marker.read_text()


def test_awk_spliced_system_call_is_refused(lanes, tmp_path):
    # A backslash-newline between 'system' and its paren splices
    # before awk lexes (gawk executes it); the rule normalizes
    # splices before matching.
    result, marker = guarded(lanes, tmp_path,
        'import subprocess\ntry: subprocess.run(["awk", "BEGIN{system\\\\\\n(\\"id\\")}"])\nexcept OSError: pass')
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert marker.exists()
    assert 'command-pipe' in marker.read_text()


def test_guarded_child_install_ignores_test_path_mutation(lanes, tmp_path, monkeypatch):
    # A test-mutated PATH must not reach a later child's install
    # sample: the helper resets PATH to the import-time value.
    bindir = tmp_path / 'helperbin'
    bindir.mkdir()
    (bindir / 'python3').symlink_to(shutil.which('sed'))
    monkeypatch.setenv('PATH', str(bindir) + os.pathsep + os.environ['PATH'])
    result, marker = guarded(lanes, tmp_path,
        'import subprocess\nsubprocess.run(["python3", "-c", "import sys; print(sys.version_info[0])"], check=True)')
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout.strip() == '3'
    assert not marker.exists()


# DROPPED R11 pins (shell-emulation group): the arith/fork/source/
# route/setter/export/piped/perf/digit/screen/delivery/nested/
# substitution/timeout/outer_env/heredoc/preexec mechanism tests pin
# the shell-semantics engine, which is deleted by design; the 7
# wall-clock tests (including the 12s branch-fanout bound) violate
# the load-independent-budget constraint; multicall link-head,
# native-argument, stub-read, and env/body-analysis verdicts have no
# argv-level expression. Each surviving policy above pins the same
# allow/refuse verdict through the replacement's rules.
