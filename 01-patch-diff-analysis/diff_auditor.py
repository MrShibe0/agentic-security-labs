#!/usr/bin/env python3
"""
Lab 1: Automated Patch-Diff Security Triage Auditor
Parses unified git diffs to classify security-relevant patch hunks and flag
potentially brittle remediation patterns (inspired by GTIG exploit_agent analysis).
"""
import re
import sys
from pathlib import Path
from typing import List, Tuple

RULES: List[Tuple[str, str, str, str]] = [
    (
        "AUTHZ_GUARD_ADDED",
        "HIGH",
        r"(current_user_can|is_user_logged_in|has_permission|require_auth|@login_required|check_admin_referer)",
        "New authorization/authentication guard added -> prior version likely exposed unauthenticated or low-priv access.",
    ),
    (
        "FRAGILE_URI_MATCH",
        "MEDIUM",
        r"(REQUEST_URI|strpos|str_contains|startswith|endswith).*(/wp/|/api/|/admin/|rest_route)",
        "Patch matches raw URI string instead of canonical router/permission callback -> audit for encoding, case, or query-param bypasses.",
    ),
    (
        "SINK_HARDENING",
        "HIGH",
        r"(sanitize_|esc_|htmlspecialchars|shlex\.quote|subprocess\.run|prepare\(|eval\(|exec\()",
        "Input sanitization or execution sink modified -> check pre-patch code for injection or RCE.",
    ),
    (
        "ERROR_DENIAL_ADDED",
        "LOW",
        r"(WP_Error|rest_forbidden|HTTPException|403|PermissionDenied)",
        "Explicit denial path introduced -> trace which endpoint or role triggered this boundary.",
    ),
]


def audit_diff(diff_path: Path) -> int:
    if not diff_path.exists():
        print(f"[ERROR] File not found: {diff_path}")
        return 1

    current_file = "unknown"
    findings = []

    for line_no, raw_line in enumerate(diff_path.read_text(encoding="utf-8").splitlines(), start=1):
        if raw_line.startswith("+++ b/"):
            current_file = raw_line[6:].strip()
            continue

        # Inspect only added lines in the patch (excluding +++ header)
        if not raw_line.startswith("+") or raw_line.startswith("+++"):
            continue

        code_line = raw_line[1:].strip()
        for rule_id, severity, pattern, guidance in RULES:
            if re.search(pattern, code_line, re.IGNORECASE):
                findings.append((severity, rule_id, current_file, line_no, code_line, guidance))

    print(f"=== Patch-Diff Security Audit: {diff_path.name} ===")
    if not findings:
        print("No high-signal security patch patterns matched.")
        return 0

    for sev, rule_id, fname, lno, snippet, guidance in findings:
        print(f"\n[{sev}] {rule_id} ({fname}:diff-line {lno})")
        print(f"  + {snippet}")
        print(f"  -> {guidance}")

    print(f"\nTotal signals flagged: {len(findings)}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python diff_auditor.py <path-to-unified.diff>")
        sys.exit(2)
    sys.exit(audit_diff(Path(sys.argv[1])))
