from __future__ import annotations
from app.agent_parser import parse_with_groq
from app.crypto_utils import encrypt_text, decrypt_text
import hashlib
import json
import os
import re
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from the project root
load_dotenv(BASE_DIR / ".env")
REVIEWER_API_KEY = os.getenv("REVIEWER_API_KEY", "")

DB_PATH = Path(os.getenv("DATABASE_PATH", str(BASE_DIR / "broker.db")))
TOKEN_TTL_MINUTES = int(os.getenv("CAPABILITY_TOKEN_TTL_MINUTES", "120"))
STATIC_DIR = Path(__file__).resolve().parent / "static"

ActionName = Literal[
    "calendar.create_event",
    "email.draft",
    "email.send",
    "wallet.transfer",
    "files.read",
    "files.send",
]

app = FastAPI(
    title="Intent-Aware Zero-Trust Authorization Broker",
    description="Educational prototype: action proposals are checked before mock tool execution.",
    version="0.1.0",
)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime | None = None) -> str:
    return (dt or utcnow()).isoformat()


def encrypt_json(value: Any) -> str:
    """Encrypt JSON data before storing it in SQLite."""
    plaintext = json.dumps(value)
    return "enc:v1:" + encrypt_text(plaintext)


def decrypt_json(value: str | None) -> Any:
    """Read encrypted JSON and support older plaintext records."""
    if value is None:
        return None

    if value.startswith("enc:v1:"):
        encrypted_value = value[len("enc:v1:"):]
        plaintext = decrypt_text(encrypted_value)
        return json.loads(plaintext)

    # Backward compatibility for records created before encryption.
    return json.loads(value)


def connect_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with connect_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                trusted_intent TEXT NOT NULL,
                allowed_actions TEXT NOT NULL,
                created_at TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS capability_tokens (
                token_hash TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                scopes TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(session_id) REFERENCES sessions(session_id)
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL UNIQUE,
                session_id TEXT NOT NULL,
                action TEXT NOT NULL,
                parameters TEXT NOT NULL,
                decision TEXT NOT NULL,
                reason TEXT NOT NULL,
                execution_status TEXT NOT NULL,
                tool_result TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(session_id) REFERENCES sessions(session_id)
            );
            CREATE TABLE IF NOT EXISTS review_queue (
                request_id TEXT PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'PENDING',
                reviewer_note TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(request_id) REFERENCES audit_logs(request_id)
            );
            """
        )


init_db()


class SessionCreate(BaseModel):
    trusted_intent: str = Field(min_length=8, max_length=1000)
    allowed_actions: list[ActionName] = Field(min_length=1)


class SessionCreated(BaseModel):
    session_id: str
    capability_token: str
    expires_at: str
    allowed_actions: list[str]


class ActionRequest(BaseModel):
    session_id: str
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action: ActionName
    parameters: dict[str, Any] = Field(default_factory=dict)


class NaturalRequest(BaseModel):
    session_id: str
    text: str = Field(min_length=3, max_length=2000)


class ReviewRequest(BaseModel):
    decision: Literal["APPROVE", "REJECT"]
    note: str = Field(default="", max_length=500)


def authenticate_reviewer(reviewer_key: str | None) -> None:
    if not REVIEWER_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="Reviewer authentication is not configured.",
        )

    if not reviewer_key or not secrets.compare_digest(
        reviewer_key, REVIEWER_API_KEY
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing reviewer credentials.",
        )


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def get_session(session_id: str) -> sqlite3.Row:
    with connect_db() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
    if not row or not row["active"]:
        raise HTTPException(status_code=404, detail="Session not found or inactive.")
    return row


def validate_capability(token: str | None, session_id: str) -> list[str]:
    if not token:
        raise HTTPException(status_code=401, detail="Missing X-Capability-Token header.")
    with connect_db() as conn:
        row = conn.execute(
            "SELECT * FROM capability_tokens WHERE token_hash = ?",
            (token_hash(token),),
        ).fetchone()
    if not row or row["revoked"]:
        raise HTTPException(status_code=401, detail="Invalid or revoked capability token.")
    if row["session_id"] != session_id:
        raise HTTPException(status_code=403, detail="Token is not bound to this session.")
    if datetime.fromisoformat(row["expires_at"]) <= utcnow():
        raise HTTPException(status_code=401, detail="Capability token has expired.")
    return json.loads(row["scopes"])


def parse_natural_request(text: str) -> tuple[str, dict[str, Any]]:
    """Small deterministic demo parser. It is intentionally not presented as an LLM."""
    s = text.strip()
    low = s.lower()

    if any(word in low for word in ["confidential file", "send file", "share file", "email file"]):
        return "files.send", {"file_name": "confidential_file.pdf", "recipient": "external"}
    if any(word in low for word in ["transfer", "send money", "pay "]):
        amount_match = re.search(r"(?:₹|\$)?\s*(\d+(?:\.\d{1,2})?)", s)
        amount = float(amount_match.group(1)) if amount_match else 100.0
        recipient_match = re.search(r"\bto\s+([A-Za-z][A-Za-z ]{0,40})", s, re.I)
        recipient = recipient_match.group(1).strip() if recipient_match else "unspecified"
        return "wallet.transfer", {"amount": amount, "recipient": recipient}
    if any(word in low for word in ["send an email", "send email", "email to"]):
        recipient_match = re.search(r"\bto\s+([A-Za-z][A-Za-z ]{0,40})", s, re.I)
        recipient = recipient_match.group(1).strip() if recipient_match else "unspecified"
        return "email.send", {"recipient": recipient, "subject": "Meeting update", "body": s}
    if any(word in low for word in ["draft an email", "draft email", "write an email"]):
        recipient_match = re.search(r"\bto\s+([A-Za-z][A-Za-z ]{0,40})", s, re.I)
        recipient = recipient_match.group(1).strip() if recipient_match else "unspecified"
        return "email.draft", {"recipient": recipient, "subject": "Draft email", "body": s}
    if any(word in low for word in ["read file", "open file", "view file"]):
        return "files.read", {"file_name": "sample.txt"}
    if any(word in low for word in ["schedule", "calendar", "meeting", "appointment"]):
        person_match = re.search(r"\bwith\s+([A-Za-z][A-Za-z ]{0,40})", s, re.I)
        time_match = re.search(r"\b(?:at\s+)?(\d{1,2}(?::\d{2})?\s*(?:AM|PM))\b", s, re.I)
        date_match = re.search(r"\b(today|tomorrow|monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b", s, re.I)
        return "calendar.create_event", {
            "title": "Meeting" + (f" with {person_match.group(1).strip()}" if person_match else ""),
            "attendee": person_match.group(1).strip() if person_match else "unspecified",
            "date": date_match.group(1).lower() if date_match else "tomorrow",
            "time": time_match.group(1).strip() if time_match else "10 AM",
        }
    return "email.draft", {"recipient": "unspecified", "subject": "Needs clarification", "body": s, "_ambiguous": True}


def validate_parameters(action: str, params: dict[str, Any]) -> str | None:
    if action == "calendar.create_event":
        if not str(params.get("title", "")).strip():
            return "Calendar event title is required."
        if not str(params.get("date", "")).strip() or not str(params.get("time", "")).strip():
            return "Calendar event date and time are required."
    elif action in ("email.send", "email.draft"):
        recipient = str(params.get("recipient", "")).strip()
        if not recipient or recipient.lower() == "unspecified":
            return "Email recipient is missing or ambiguous."
        if action == "email.send" and not str(params.get("body", "")).strip():
            return "Email body is required."
    elif action == "wallet.transfer":
        try:
            amount = float(params.get("amount", 0))
        except (TypeError, ValueError):
            return "Transfer amount must be numeric."
        if amount <= 0:
            return "Transfer amount must be greater than zero."
        if amount > 500:
            return "Transfer exceeds the demo limit of 500 and requires denial."
    elif action in ("files.read", "files.send"):
        name = str(params.get("file_name", "")).strip()
        if not name:
            return "File name is required."
        if ".." in name or name.startswith(("/", "\\")):
            return "Unsafe file path rejected."
    return None



def intent_matches(trusted_intent: str, action: str, params: dict[str, Any]) -> bool:
    intent = trusted_intent.lower()

    if action == "calendar.create_event":
        return any(
            word in intent
            for word in ["meeting", "calendar", "schedule", "appointment"]
        )

    if action == "email.draft":
        return any(
            word in intent
            for word in ["email", "draft", "message"]
        )

    if action == "email.send":
        # Sending must be explicitly covered by trusted intent.
        return any(
            phrase in intent
            for phrase in [
                "send email",
                "send emails",
                "send email messages",
                "send messages",
                "email communication",
            ]
        )

    if action == "wallet.transfer":
        return any(
            word in intent
            for word in ["transfer money", "wallet", "payment", "pay"]
        )

    if action == "files.read":
        return any(
            phrase in intent
            for phrase in ["read files", "access files", "open files", "file access"]
        )

    if action == "files.send":
        return any(
            phrase in intent
            for phrase in ["send files", "share files", "upload files"]
        )

    return False



def tool_execute(action: str, params: dict[str, Any]) -> dict[str, Any]:
    """Mock tools only. No real emails, transfers, or file operations occur."""
    if action == "calendar.create_event":
        return {"tool": "MockCalendar", "result": "Event created in demo calendar", "event": params}
    if action == "email.draft":
        return {"tool": "MockEmail", "result": "Email draft created (not sent)", "draft": params}
    if action == "email.send":
        return {"tool": "MockEmail", "result": "Mock email sent", "recipient": params.get("recipient")}
    if action == "wallet.transfer":
        return {"tool": "MockWallet", "result": "Mock transfer completed", "amount": params.get("amount")}
    if action == "files.read":
        return {"tool": "MockFiles", "result": "Sample file read in simulation", "file_name": params.get("file_name")}
    if action == "files.send":
        return {"tool": "MockFiles", "result": "File sharing simulated", "file_name": params.get("file_name")}
    raise HTTPException(status_code=400, detail="Unknown action.")


def decide(session: sqlite3.Row, action: str, params: dict[str, Any], token_scopes: list[str]) -> tuple[str, str]:
    allowed = json.loads(session["allowed_actions"])
    intent = session["trusted_intent"]

    if action not in token_scopes:
        return "DENY", "Action is outside the capability token scope."

    if params.get("_ambiguous"):
        return "REVIEW", "The request is ambiguous and needs human clarification."
    param_error = validate_parameters(action, params)
    if param_error:
        return "DENY", param_error
    if action not in allowed:
        return "DENY", "Action is not included in the session's granted action scope."
    if not intent_matches(intent, action, params):
        return "DENY", "Proposed action does not match the trusted user intent."
    if action == "email.send":
        return "REVIEW", "Sending an email is a consequential action and requires human approval."
    if action == "wallet.transfer":
        return "REVIEW", "Financial transfers require explicit human approval."
    return "ALLOW", "Action matches the trusted intent, parameters, and granted scope."


def audit(request_id: str, session_id: str, action: str, params: dict[str, Any],
          decision: str, reason: str, execution_status: str, result: dict | None = None) -> None:
    now = iso()
    with connect_db() as conn:
        conn.execute(
            """INSERT INTO audit_logs
            (request_id, session_id, action, parameters, decision, reason, execution_status, tool_result, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
       (request_id, session_id, action, encrypt_json(params), decision, reason,
 execution_status, encrypt_json(result) if result is not None else None, now),
        )
        if decision == "REVIEW":
            conn.execute(
                "INSERT INTO review_queue (request_id, status, updated_at) VALUES (?, 'PENDING', ?)",
                (request_id, now),
            )


def process_action(req: ActionRequest, token: str | None) -> dict[str, Any]:
    session = get_session(req.session_id)
    token_scopes = validate_capability(token, req.session_id)
    params = dict(req.parameters)

    with connect_db() as conn:
        duplicate = conn.execute(
            "SELECT request_id FROM audit_logs WHERE request_id = ?", (req.request_id,)
        ).fetchone()
    if duplicate:
        raise HTTPException(status_code=409, detail="Duplicate request_id rejected.")

    decision, reason = decide(session, req.action, params, token_scopes)
    result = None
    execution_status = "NOT_EXECUTED"
    if decision == "ALLOW":
        result = tool_execute(req.action, params)
        execution_status = "EXECUTED"
    audit(req.request_id, req.session_id, req.action, params, decision, reason, execution_status, result)
    return {
        "request_id": req.request_id,
        "action": req.action,
        "decision": decision,
        "reason": reason,
        "execution_status": execution_status,
        "tool_result": result,
    }


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health():
    return {"status": "healthy", "database": str(DB_PATH.name)}


@app.post("/api/sessions", response_model=SessionCreated)
def create_session(req: SessionCreate):
    session_id = str(uuid.uuid4())
    token = secrets.token_urlsafe(32)
    expires = utcnow() + timedelta(minutes=TOKEN_TTL_MINUTES)
    with connect_db() as conn:
        conn.execute(
            "INSERT INTO sessions (session_id, trusted_intent, allowed_actions, created_at) VALUES (?, ?, ?, ?)",
            (session_id, req.trusted_intent, json.dumps(req.allowed_actions), iso()),
        )
        conn.execute(
            "INSERT INTO capability_tokens (token_hash, session_id, scopes, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
            (token_hash(token), session_id, json.dumps(req.allowed_actions), iso(expires), iso()),
        )
    return SessionCreated(
        session_id=session_id,
        capability_token=token,
        expires_at=iso(expires),
        allowed_actions=req.allowed_actions,
    )


@app.post("/api/actions")
def submit_action(req: ActionRequest, x_capability_token: str | None = Header(default=None)):
    return process_action(req, x_capability_token)



@app.post("/api/chat")
def chat(req: NaturalRequest, x_capability_token: str | None = Header(default=None)):
    try:
        proposal = parse_with_groq(req.text)
    except Exception:
        raise HTTPException(
            status_code=502,
            detail="The LLM could not produce an action proposal. Please try again.",
        )

    action = proposal["action"]
    params = proposal["parameters"]

    action_req = ActionRequest(
        session_id=req.session_id,
        request_id=str(uuid.uuid4()),
        action=action,
        parameters=params,
    )

    return {
        "parsed_proposal": proposal,
        "authorization": process_action(action_req, x_capability_token),
        "note": "The LLM proposes actions; the Zero Trust broker independently enforces authorization.",
    }



@app.get("/api/audit")
def get_audit(session_id: str | None = None, limit: int = 100):
    limit = max(1, min(limit, 500))
    with connect_db() as conn:
        if session_id:
            rows = conn.execute(
                "SELECT * FROM audit_logs WHERE session_id = ? ORDER BY id DESC LIMIT ?",
                (session_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
    return {"items": [
        {
            "id": r["id"], "request_id": r["request_id"], "session_id": r["session_id"],
            "action": r["action"], "parameters": decrypt_json(r["parameters"]),
            "decision": r["decision"], "reason": r["reason"],
            "execution_status": r["execution_status"],
            "tool_result":decrypt_json(r["tool_result"]) if r["tool_result"] else None,
            "created_at": r["created_at"],
        } for r in rows
    ]}


@app.get("/api/reviews")
def get_reviews(session_id: str | None = None):
    query = """SELECT q.request_id, q.status, q.reviewer_note, q.updated_at,
                      a.session_id, a.action, a.parameters, a.reason
               FROM review_queue q JOIN audit_logs a ON q.request_id = a.request_id"""
    args: tuple = ()
    if session_id:
        query += " WHERE a.session_id = ?"
        args = (session_id,)
    query += " ORDER BY q.updated_at DESC"
    with connect_db() as conn:
        rows = conn.execute(query, args).fetchall()
    return {"items": [{
        "request_id": r["request_id"], "status": r["status"], "reviewer_note": r["reviewer_note"],
        "updated_at": r["updated_at"], "session_id": r["session_id"], "action": r["action"],
        "parameters":decrypt_json(r["parameters"]), "reason": r["reason"]
    } for r in rows]}



@app.post("/api/reviews/{request_id}")
def review_action(
    request_id: str,
    req: ReviewRequest,
    x_reviewer_key: str | None = Header(default=None),
):
    authenticate_reviewer(x_reviewer_key)

    with connect_db() as conn:
        row = conn.execute(
            "SELECT status FROM review_queue WHERE request_id = ?",
            (request_id,),
        ).fetchone()

        if not row:
            raise HTTPException(
                status_code=404,
                detail="Review request not found.",
            )

        now = iso()
        cursor = conn.execute(
            """UPDATE review_queue
               SET status = ?, reviewer_note = ?, updated_at = ?
               WHERE request_id = ? AND status = 'PENDING'""",
            (req.decision, req.note, now, request_id),
        )

        if cursor.rowcount != 1:
            raise HTTPException(
                status_code=409,
                detail="Review request has already been decided.",
            )

        execution_status = (
            "APPROVED_PENDING_EXECUTION"
            if req.decision == "APPROVE"
            else "REJECTED_BY_REVIEWER"
        )

        conn.execute(
            """UPDATE audit_logs
               SET execution_status = ?
               WHERE request_id = ?""",
            (execution_status, request_id),
        )

    return {
        "request_id": request_id,
        "review_decision": req.decision,
        "status": "recorded",
        "message": (
            "Review decision recorded. "
            "This demo does not auto-execute a reviewed action."
        ),
    }


@app.post("/api/tokens/revoke")
def revoke_token(session_id: str, x_capability_token: str | None = Header(default=None)):
    if not x_capability_token:
        raise HTTPException(status_code=401, detail="Missing X-Capability-Token header.")
    with connect_db() as conn:
        row = conn.execute(
            "SELECT session_id FROM capability_tokens WHERE token_hash = ?",
            (token_hash(x_capability_token),),
        ).fetchone()
        if not row or row["session_id"] != session_id:
            raise HTTPException(status_code=401, detail="Invalid token for this session.")
        conn.execute(
            "UPDATE capability_tokens SET revoked = 1 WHERE token_hash = ?",
            (token_hash(x_capability_token),),
        )
    return {"status": "revoked", "session_id": session_id}
