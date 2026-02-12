"""Tests for QEMU runner CLI options."""

import subprocess
import sys
from pathlib import Path


def test_qemu_runner_help_includes_riscv_demo():
    script = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "runners"
        / "run_qemu_trace.py"
    )
    result = subprocess.run(
        [sys.executable, str(script), "--help"],
        check=True,
        capture_output=True,
        text=True,
    )

    help_text = result.stdout
    assert "riscv_min" in help_text
    assert "qsort" in help_text
    assert "sve" in help_text
    assert "pthread" in help_text


def test_qemu_runner_has_pthread_demo_config():
    script = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "runners"
        / "run_qemu_trace.py"
    )
    module_name = "run_qemu_trace"
    import importlib.util

    spec = importlib.util.spec_from_file_location(module_name, script)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    pthread_config = module.DEMOS["pthread"]
    assert pthread_config["src_file"] == "pthread_demo.c"
    assert "-pthread" in pthread_config["compile_flags"]
