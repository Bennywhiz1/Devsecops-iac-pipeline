"""
Runs checkov against the insecure and hardened Terraform stacks and prints a
before/after comparison. Also writes REPORT.md so the numbers in the README
can be regenerated, not hand-typed.

Usage:  python scripts/scan_report.py
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run_checkov(target: Path) -> dict:
    """Run checkov on a directory and return its parsed JSON result.

    checkov exits non-zero when checks fail. That is the expected outcome for
    the insecure stack, so the exit code is deliberately not treated as an
    error - an empty stdout is.
    """
    cmd = [
        sys.executable, "-m", "checkov.main",
        "-d", str(target),
        "--config-file", str(ROOT / ".checkov.yaml"),
        "-o", "json",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", cwd=ROOT)
    if not proc.stdout.strip():
        raise RuntimeError(f"checkov produced no output:\n{proc.stderr}")
    return json.loads(proc.stdout)


def failed_ids(result: dict) -> set:
    return {c["check_id"] for c in result["results"]["failed_checks"]}


def main() -> None:
    rows = []
    details = {}
    for name in ("insecure", "hardened"):
        result = run_checkov(ROOT / "terraform" / name)
        s = result["summary"]
        rows.append((name, s["resource_count"], s["passed"], s["failed"], s["skipped"]))
        details[name] = result

    lines = [
        "# Scan report",
        "",
        "| Stack | Resources | Passed | Failed | Skipped |",
        "|---|---|---|---|---|",
    ]
    lines += [f"| {n} | {r} | {p} | {f} | {s} |" for n, r, p, f, s in rows]

    lines += ["", "## Controls the insecure stack fails", ""]
    seen = {}
    for c in details["insecure"]["results"]["failed_checks"]:
        seen.setdefault(c["check_id"], c["check_name"])
    lines += [f"- `{cid}` - {name}" for cid, name in sorted(seen.items())]

    lines += ["", "## Justified skips in the hardened stack", ""]
    for c in details["hardened"]["results"]["skipped_checks"]:
        reason = c["check_result"].get("suppress_comment", "")
        lines.append(f"- `{c['check_id']}` on `{c['resource']}` - {reason}")

    report = "\n".join(lines) + "\n"
    (ROOT / "REPORT.md").write_text(report, encoding="utf-8")
    print(report)


if __name__ == "__main__":
    main()
