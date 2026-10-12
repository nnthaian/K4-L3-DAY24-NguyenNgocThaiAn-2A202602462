# Verification — điền trước khi nộp

- OS / Python / Gitleaks version: Windows (`win32`), Python 3.13.4, Gitleaks v8.30.1.
- `python -m pytest tests/ -q`: `33 passed in 2.57s`.
- `pre-commit run --all-files`: `Passed` — hook `gitleaks-system`.
- Ledger verify: `True` for `reports/ledger.jsonl`.
- Gitleaks current-tree scan: `INF no leaks found`. Historical scan intentionally reports 1 synthetic finding at commit `1bdd849`, rule `lab24-synthetic-token`.
- Các lỗi còn lại: Không còn lỗi đã biết.
