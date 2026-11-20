# Agentic Security Labs

Hands-on defensive engineering and architecture research exploring autonomous multi-agent security frameworks (`exploit_agent`, `CAIRN`, `ARTEX`, `PentAGI`) based on late-2026 threat intelligence disclosures.

> **Scope & Ethics:** All code, benchmarks, and detection rules in this repository are built strictly for authorized local lab environments and defensive security engineering.

## Lab Modules
1. **`01-patch-diff-analysis/`** — Pre/post-patch differential analysis methodology and non-destructive verification checks.
2. **`02-blackboard-supervisor/`** — Python implementation of shared-blackboard state coordination (`CAIRN` pattern) and anti-loop Mentor supervision (`PentAGI` pattern).
3. **`03-pentagi-benchmark/`** — Isolated Docker lab setup and false-positive/false-negative scoring rubrics (Assistant vs. Automation mode).
4. **`04-volumetric-detections/`** — Sigma and SIEM detection rules targeting machine-speed command bursts, EDR coverage-gap recon, and rotating webhook C2 (`ARTEX` patterns).
