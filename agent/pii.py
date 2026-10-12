"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations


def _stub_detect(text: str) -> list[dict]:
    raise NotImplementedError("BƯỚC 3a: implement PII detection")


def _stub_redact(text: str) -> str:
    raise NotImplementedError("BƯỚC 3a: implement PII redaction")


import re

_CCCD_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
_PHONE_RE = re.compile(r"(?<!\d)(0(?:[ .-]?\d){8,9})(?!\d)")
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@"
    r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9.-])"
)
_BANK_RE = re.compile(
    r"(?i)(?:stk|số\s+tài\s+khoản|so\s+tai\s+khoan)"
    r"\s*(?:[:#-]\s*)?(?P<value>\d{8,16})(?!\d)"
)


def _candidate_entities(text: str) -> list[dict]:
    entities: list[dict] = []
    for match in _CCCD_RE.finditer(text):
        entities.append({"type": "VN_CCCD", "start": match.start(), "end": match.end()})
    for match in _PHONE_RE.finditer(text):
        entities.append({"type": "VN_PHONE", "start": match.start(), "end": match.end()})
    for match in _EMAIL_RE.finditer(text):
        entities.append({"type": "EMAIL", "start": match.start(), "end": match.end()})
    for match in _BANK_RE.finditer(text):
        entities.append({
            "type": "VN_BANK_ACCOUNT",
            "start": match.start("value"),
            "end": match.end("value"),
        })
    return entities


def detect(text: str) -> list[dict]:
    priority = {"EMAIL": 0, "VN_CCCD": 1, "VN_BANK_ACCOUNT": 2, "VN_PHONE": 3}
    candidates = sorted(
        _candidate_entities(text),
        key=lambda item: (item["start"], -(item["end"] - item["start"]), priority[item["type"]]),
    )
    selected: list[dict] = []
    for entity in candidates:
        if any(entity["start"] < other["end"] and other["start"] < entity["end"] for other in selected):
            continue
        selected.append(entity)
    return sorted(selected, key=lambda item: (item["start"], item["end"]))


def redact(text: str) -> str:
    redacted = text
    for entity in reversed(detect(text)):
        replacement = f"[REDACTED_{entity['type']}]"
        redacted = redacted[:entity["start"]] + replacement + redacted[entity["end"]:]
    return redacted
