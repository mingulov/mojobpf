# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Setuptools build-hook shim: regenerate packaged adapter resources.

All project metadata lives in ``pyproject.toml``; this file only
wires ``tools/generate_adapter_resources.py`` into the setuptools
commands that package the tree (``build_py`` and ``sdist``), so
wheel AND sdist builds regenerate
``src/mojobpf/resources/adapter/*`` from ``compiler/`` (plus the
admission descriptor from the capability registry) before
packaging. The hook fails closed: a missing generator or a
failed generation aborts the build, never packages stale bytes.
The sdist carries the generator and the authoritative sources
(see ``MANIFEST.in``), so a wheel built from the sdist
regenerates from them.
"""

import importlib.util
import os

from setuptools import setup
from setuptools.command.build_py import build_py as _BuildPy
from setuptools.command.sdist import sdist as _Sdist

_HERE = os.path.dirname(os.path.abspath(__file__))
_GENERATOR = os.path.join(
    _HERE, "tools", "generate_adapter_resources.py"
)


def _regenerate() -> None:
    if not os.path.isfile(_GENERATOR):
        raise SystemExit(
            "mojobpf: adapter generator is missing: %s; refusing "
            "to package adapter copies without regenerating them"
            % _GENERATOR
        )
    spec = importlib.util.spec_from_file_location(
        "mojobpf_adapter_generator", _GENERATOR
    )
    if spec is None or spec.loader is None:
        raise SystemExit(
            "mojobpf: cannot load adapter generator: %s" % _GENERATOR
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    code = module.main(["--root", _HERE])
    if code != 0:
        raise SystemExit(
            "mojobpf: adapter generation failed (exit %d)" % code
        )


class _GenerateBuildPy(_BuildPy):
    """``build_py`` that regenerates adapter resources first."""

    def run(self) -> None:
        _regenerate()
        super().run()


class _GenerateSdist(_Sdist):
    """``sdist`` that regenerates adapter resources first."""

    def run(self) -> None:
        _regenerate()
        super().run()


setup(
    cmdclass={
        "build_py": _GenerateBuildPy,
        "sdist": _GenerateSdist,
    }
)
