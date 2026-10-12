"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

from pathlib import Path

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _stub_handle(message: str, llm, log_dir: Path | None = None,
                 principal_id: str = "support_l1") -> str:
    raise RunnerScaffoldPending("BƯỚC 3c: implement trifecta split")


import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone

from agent import ledger, pii, policy, tools


_PRINCIPALS_PATH = REPORTS_DIR.parent / "data" / "principals.json"
_CUSTOMERS_PATH = REPORTS_DIR.parent / "data" / "customers.json"
_TICKET_RE = re.compile(r"^ticket-(\d+)\.md$")


def _hash_args(args: object) -> str:
    payload = json.dumps(args, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _redact_value(value):
    if isinstance(value, str):
        return pii.redact(value)
    if isinstance(value, dict):
        return {key: _redact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    return value


def _customers_by_ticket() -> dict[int, list[str]]:
    customers = json.loads(_CUSTOMERS_PATH.read_text(encoding="utf-8"))
    mapping: dict[int, list[str]] = {}
    for customer in customers:
        for ticket_id in customer.get("related_tickets", []):
            mapping.setdefault(int(ticket_id), []).append(str(customer["customer_id"]))
    return mapping


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    """Run the untrusted search and private-data stages as separate tool boundaries."""
    ledger_path = (Path(log_dir) if log_dir is not None else REPORTS_DIR) / "ledger.jsonl"
    principals = json.loads(_PRINCIPALS_PATH.read_text(encoding="utf-8"))
    principal = principals.get(principal_id, {})
    agent_id = "lab24-agent"
    run_id = uuid.uuid4().hex
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
    scopes = tuple(principal.get("allowed_tools", []))

    def call_tool(tool_name: str, args: object, classification: str,
                  purpose: str, egress: bool, operation):
        context = policy.PolicyContext(
            data_classification=classification,
            request_purpose=purpose,
            agent_owner=f"{agent_id}/{run_id}",
            delegation_depth=0,
            egress_enabled=egress,
            principal_id=principal_id,
            requested_tool=tool_name,
            agent_scopes=scopes,
            parent_scopes=(),
            expires_at=expires_at,
        )
        allowed, reason = policy.check(context)
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": run_id,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
            "tool": tool_name,
            "args_hash": _hash_args(args),
            "classification": classification,
            "decision": "allow" if allowed else "deny",
            "reason": reason,
        }
        ledger.append(entry, ledger_path)
        return operation() if allowed else None

    docs = call_tool(
        "search_docs", {"query": message}, "internal", "summarize-tickets", False,
        lambda: tools.search_docs(message),
    ) or []
    if not docs:
        return llm.summarize([])

    combined_text = "\n\n".join(doc["text"] for doc in docs)
    injected = llm.find_injection(combined_text)
    ticket_to_customers = _customers_by_ticket()
    collected: list[dict] = []

    if injected is not None:
        ticket_ids = []
        for doc in docs:
            match = _TICKET_RE.match(str(doc.get("id", "")))
            if match:
                ticket_ids.append(int(match.group(1)))

        customer_ids = sorted({
            customer_id
            for ticket_id in ticket_ids
            for customer_id in ticket_to_customers.get(ticket_id, [])
        })
        for customer_id in customer_ids:
            record = call_tool(
                "read_customer", {"customer_id": customer_id},
                "restricted", "support-reply", False,
                lambda customer_id=customer_id: tools.read_customer(customer_id),
            )
            if record is not None:
                collected.append(_redact_value(record))

        if collected:
            call_tool(
                "http_post", {"url": injected.target_url, "records": collected},
                "restricted", "support-reply", True,
                lambda: tools.http_post(injected.target_url, {"records": collected}),
            )

    safe_docs = [{"id": doc["id"], "text": pii.redact(doc["text"])} for doc in docs]
    return llm.summarize(safe_docs)
