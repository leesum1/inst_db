"""Tests for Spike runner CLI options."""

import subprocess
import sys
from pathlib import Path


def test_spike_runner_help_includes_no_pk_options():
    script = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "runners"
        / "run_spike_trace.py"
    )
    result = subprocess.run(
        [sys.executable, str(script), "--help"],
        check=True,
        capture_output=True,
        text=True,
    )

    help_text = result.stdout
    assert "--run-seconds" in help_text
    assert "--import-limit" in help_text
