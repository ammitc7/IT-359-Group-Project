# Final Writeup — Project Title
**Course:** …  
**Team Members:** …  
**Date:** …

## 1. Introduction & Purpose (The What)
- Problem statement (what are you solving?)
- Goals of the project
- Scope (authorized, lab-only; parsing focus)

## 2. Technical Implementation (The How)
- High-level architecture diagram and flow (tools output ➜ parsers ➜ storage ➜ alerts ➜ reports)
- Tech stack (Python, lxml, JSON/SQLite, pytest, GitHub Actions)
- Key components and responsibilities:
  - Orchestrator (CLI)
  - Parsers (nmap XML, later masscan JSON, optional nc text)
  - Storage (JSON files, optional SQLite)
  - Alerts (unexpected open ports using expected_ports config)
  - Optional UI/reporting
- Security/safety controls (dry-run by default, auth file, allowed CIDRs, audit log)

## 3. Justification & Analysis (The Why)
- Why post-scan parsing vs. direct tool output?
- Trade-offs (simplicity, safety, reproducibility)
- Ethics & legal guardrails (why they matter)
- Limitations & future work (better enrichment, asset inventory, UI)

## 4. Results & Evaluation
- What does the demo show?
- Example findings (from sample outputs)
- Testing (pytest & CI overview)
- Success criteria against rubric

## 5. Conclusion
- What you learned
- What worked well / what didn’t
- Next steps

## Appendix
- How to reproduce demo (commands)
- Data model JSON example
- Screenshots of outputs (optional)
