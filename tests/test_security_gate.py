"""
Policy-as-code tests. These are what CI runs to prove the security gate
itself works - not just that today's Terraform happens to be clean.
"""
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from scan_report import ROOT, failed_ids, run_checkov


@pytest.fixture(scope="module")
def insecure():
    return run_checkov(ROOT / "terraform" / "insecure")


@pytest.fixture(scope="module")
def hardened():
    return run_checkov(ROOT / "terraform" / "hardened")


def test_hardened_stack_has_zero_failed_checks(hardened):
    assert hardened["summary"]["failed"] == 0, failed_ids(hardened)


def test_insecure_stack_is_caught(insecure):
    assert insecure["summary"]["failed"] >= 15


def test_insecure_stack_trips_the_critical_controls(insecure):
    must_catch = {
        "CKV_AWS_20": "public-read S3 ACL",
        "CKV_AWS_24": "SSH open to 0.0.0.0/0",
        "CKV_AWS_62": "wildcard admin IAM policy",
        "CKV_AWS_7": "KMS key rotation disabled",
        "CKV_AWS_145": "S3 not encrypted with KMS",
    }
    missing = {k: v for k, v in must_catch.items() if k not in failed_ids(insecure)}
    assert not missing, f"scanner failed to flag: {missing}"


def test_custom_organisation_policy_runs(insecure, hardened):
    ran_on_insecure = failed_ids(insecure)
    passed_on_hardened = {c["check_id"] for c in hardened["results"]["passed_checks"]}
    assert "CKV2_CUSTOM_1" in ran_on_insecure
    assert "CKV2_CUSTOM_1" in passed_on_hardened


def test_every_skip_has_a_written_justification(hardened):
    skipped = hardened["results"]["skipped_checks"]
    assert skipped, "expected the hardened stack to contain documented skips"
    for c in skipped:
        reason = c["check_result"].get("suppress_comment", "").strip()
        assert reason and reason != "No comment provided", f"{c['check_id']} has no reason"
        assert len(reason) >= 15, f"{c['check_id']} reason is too thin: {reason!r}"


def test_a_bad_pull_request_would_be_blocked(tmp_path):
    """Simulates the PR the gate exists for: someone opens SSH to the world."""
    copy = tmp_path / "hardened"
    shutil.copytree(ROOT / "terraform" / "hardened", copy)
    tf = copy / "main.tf"
    text = tf.read_text()
    assert 'default     = "10.0.0.0/24"' in text or 'default = "10.0.0.0/24"' in text
    tf.write_text(re.sub(r'"10\.0\.0\.0/24"', '"0.0.0.0/0"', text))

    result = run_checkov(copy)
    assert result["summary"]["failed"] > 0
    assert "CKV_AWS_24" in failed_ids(result)


def _detect_secrets(cwd: Path, *extra: str) -> dict:
    """Scan `cwd` by running detect-secrets from INSIDE it with a relative '.'.

    Deliberately not given an absolute path: detect-secrets silently returns
    zero findings when pointed at an absolute directory outside the current
    working directory, which would make every secrets test pass vacuously.
    """
    cmd = [sys.executable, "-m", "detect_secrets", "scan", "--all-files", *extra, "."]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", cwd=cwd)
    return json.loads(proc.stdout)["results"]


def test_repository_contains_no_secrets():
    results = _detect_secrets(
        ROOT, "--exclude-files", r"(\.venv|\.git/|\.secrets\.baseline|__pycache__|\.pytest_cache|REPORT\.md)"
    )
    assert results == {}, f"possible secrets found: {list(results)}"


def test_secret_scanner_actually_detects_a_planted_key(tmp_path):
    """Positive control - a scanner that never fires proves nothing."""
    fake_key = "AKIA" + "IOSFODNN7EXAMPLE"  # AWS's documented example key, split so repo scans stay clean
    (tmp_path / "config.py").write_text(f'AWS_ACCESS_KEY_ID = "{fake_key}"\n')
    results = _detect_secrets(tmp_path)
    assert results, "detect-secrets failed to flag a planted AWS key"
