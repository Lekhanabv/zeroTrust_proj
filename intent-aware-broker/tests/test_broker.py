import os
import tempfile
from pathlib import Path

# Use a unique DB for tests before importing the app.
TEST_DB = Path(tempfile.gettempdir()) / "intent_broker_test.db"
if TEST_DB.exists():
    TEST_DB.unlink()
os.environ["DATABASE_PATH"] = str(TEST_DB)

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def create_session(scopes=None, intent=None):
    payload = {
        "trusted_intent": intent or "Schedule meetings, draft emails, and send email messages. Never send files or transfer money.",
        "allowed_actions": scopes or ["calendar.create_event", "email.draft", "email.send", "wallet.transfer"],
    }
    response = client.post("/api/sessions", json=payload)
    assert response.status_code == 200, response.text
    data = response.json()
    return data["session_id"], data["capability_token"]


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_calendar_allowed_and_executed():
    sid, token = create_session()
    response = client.post(
        "/api/actions",
        headers={"X-Capability-Token": token},
        json={"session_id": sid, "action": "calendar.create_event",
              "parameters": {"title": "Meeting with Rahul", "date": "tomorrow", "time": "10 AM"}},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "ALLOW"
    assert data["execution_status"] == "EXECUTED"


def test_email_send_requires_review_and_does_not_execute():
    sid, token = create_session()
    response = client.post(
        "/api/actions",
        headers={"X-Capability-Token": token},
        json={"session_id": sid, "action": "email.send",
              "parameters": {"recipient": "Rahul", "subject": "Meeting", "body": "Confirmed"}},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "REVIEW"
    assert data["execution_status"] == "NOT_EXECUTED"


def test_out_of_scope_action_denied():
    sid, token = create_session(scopes=["calendar.create_event"])
    response = client.post(
        "/api/actions",
        headers={"X-Capability-Token": token},
        json={"session_id": sid, "action": "wallet.transfer",
              "parameters": {"amount": 100, "recipient": "Alex"}},
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "DENY"
    assert response.json()["execution_status"] == "NOT_EXECUTED"


def test_file_send_denied_by_scope():
    sid, token = create_session()
    response = client.post(
        "/api/actions",
        headers={"X-Capability-Token": token},
        json={"session_id": sid, "action": "files.send",
              "parameters": {"file_name": "confidential.pdf", "recipient": "external"}},
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "DENY"
    assert response.json()["execution_status"] == "NOT_EXECUTED"


def test_duplicate_request_id_rejected():
    sid, token = create_session()
    payload = {"session_id": sid, "request_id": "same-request-id",
               "action": "calendar.create_event",
               "parameters": {"title": "Meeting", "date": "tomorrow", "time": "10 AM"}}
    first = client.post("/api/actions", headers={"X-Capability-Token": token}, json=payload)
    second = client.post("/api/actions", headers={"X-Capability-Token": token}, json=payload)
    assert first.status_code == 200
    assert second.status_code == 409


def test_missing_token_rejected():
    sid, _ = create_session()
    response = client.post(
        "/api/actions",
        json={"session_id": sid, "action": "calendar.create_event",
              "parameters": {"title": "Meeting", "date": "tomorrow", "time": "10 AM"}},
    )
    assert response.status_code == 401
