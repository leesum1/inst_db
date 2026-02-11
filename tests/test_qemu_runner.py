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
