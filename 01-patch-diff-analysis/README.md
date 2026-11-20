# Lab 1: Patch Differential Analysis

## Objective
Practice deriving vulnerability classes and auditing patch completeness directly from unified code diffs before reading CVE writeups—the core mechanism documented in GTIG's November 2026 `exploit_agent` analysis.

## Case Study: Spectra v2.19.25 (`restrict_popup_rest_access`)
- **Added Guard Signal:** Introducing `is_user_logged_in() && current_user_can('manage_options')` indicates prior versions did not restrict `/wp/v2/spectra-popup` to administrators.
- **Incomplete-Fix Audit:** Checking raw `$_SERVER['REQUEST_URI']` via `strpos()` instead of registering a `permission_callback` on the WordPress REST route is a classic brittle pattern worth auditing for URL encoding, casing, or alternate query-route (`?rest_route=`) discrepancies.

## Usage
```bash
python diff_auditor.py samples/spectra_v2_19_25.diff
@'
# Lab 1: Patch Differential Analysis

## Objective
Practice deriving vulnerability classes and auditing patch completeness directly from unified code diffs before reading CVE writeups—the core mechanism documented in GTIG's November 2026 `exploit_agent` analysis.

## Case Study: Spectra v2.19.25 (`restrict_popup_rest_access`)
- **Added Guard Signal:** Introducing `is_user_logged_in() && current_user_can('manage_options')` indicates prior versions did not restrict `/wp/v2/spectra-popup` to administrators.
- **Incomplete-Fix Audit:** Checking raw `$_SERVER['REQUEST_URI']` via `strpos()` instead of registering a `permission_callback` on the WordPress REST route is a classic brittle pattern worth auditing for URL encoding, casing, or alternate query-route (`?rest_route=`) discrepancies.

## Usage
```bash
python diff_auditor.py samples/spectra_v2_19_25.diff
```
