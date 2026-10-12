# Compliance mapping — điền trong checkpoint 5

| Nguồn / yêu cầu | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|
| Luật 91/2025/QH15 | PII gate, policy trước tool call, phân loại `restricted`, ledger và redaction. | `agent/pii.py:73-91`; `agent/policy.py:81-98`; `agent/ledger.py:63-98` | Chưa đối chiếu văn bản gốc nên không khẳng định tuân thủ điều khoản cụ thể. Đây chỉ là mapping kỹ thuật trong lab. |
| NĐ 356/2025/NĐ-CP | Giảm dữ liệu qua split: Run B chỉ dùng ticket ID từ tên file và mapping `related_tickets`; không tin customer ID trong free text. | `agent/runner.py:47-57`, `agent/runner.py:148-174`; `tests/test_split.py` | Mock không thay thế DPIA, kiểm soát truy cập thật, retention hoặc quy trình vận hành. Chưa đối chiếu điều khoản gốc. |
| Luật AI 134/2025/QH15 | Có audit trail cho allow/deny, định danh principal mô phỏng và bằng chứng chặn egress. | `agent/runner.py:131-145`; `reports/ledger.jsonl`; `reports/attack-after.log` | `--as` chỉ mô phỏng principal; chưa phải authentication, monitoring hay đánh giá rủi ro production. Chưa đối chiếu điều khoản gốc. |
| OWASP ASI01, ASI03, ASI04 | Chống prompt injection bằng split/containment, OBO scope check, PII redaction và PEP chặn `restricted` + egress. | `agent/runner.py:115-199`; `agent/policy.py:81-98`; `agent/pii.py:73-91`; `reports/ledger.jsonl` | Mapping OWASP ở mức khái niệm cho lab; cần review threat model và kiểm thử production đầy đủ. |

Chỉ ghi điều khoản cụ thể khi đã đối chiếu văn bản gốc. Mô phỏng kỹ thuật không tự chứng minh tuân thủ pháp luật.
