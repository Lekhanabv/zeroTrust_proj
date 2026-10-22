import os
import tempfile
import secrets
from pathlib import Path

from fastapi.testclient import TestClient

# Use a separate database for tests.
TEST_DB = Path(tempfile.gettempdir()) / "intent_broker_test.db"

if TEST_DB.exists():
    TEST_DB.unlink()

os.environ["DATABASE_PATH"] = str(TEST_DB)

# Create a reviewer key specifically for tests.
# Set it before importing the FastAPI app.
REVIEWER_TEST_KEY = secrets.token_urlsafe(32)
os.environ["REVIEWER_API_KEY"] = REVIEWER_TEST_KEY

from app.main import app

client = TestClient(app)


def create_session(scopes=None, intent=None):
    payload = {
        "trusted_intent": intent or (
            "Schedule meetings, draft emails, and send email messages. "
            "Never send files or transfer money."
        ),
        "allowed_actions": scopes or [
            "calendar.create_event",
            "email.draft",
            "email.send",
            "wallet.transfer",
        ],
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
        json={
            "session_id": sid,
            "action": "calendar.create_event",
            "parameters": {
                "title": "Meeting with Rahul",
                "date": "tomorrow",
                "time": "10 AM",
            },
        },
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
        json={
            "session_id": sid,
            "action": "email.send",
            "parameters": {
                "recipient": "Rahul",
                "subject": "Meeting",
                "body": "Confirmed",
            },
        },
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
        json={
            "session_id": sid,
            "action": "wallet.transfer",
            "parameters": {"amount": 100, "recipient": "Alex"},
        },
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "DENY"
    assert response.json()["execution_status"] == "NOT_EXECUTED"


def test_file_send_denied_by_scope():
    sid, token = create_session()

    response = client.post(
        "/api/actions",
        headers={"X-Capability-Token": token},
        json={
            "session_id": sid,
            "action": "files.send",
            "parameters": {
                "file_name": "confidential.pdf",
                "recipient": "external",
            },
        },
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "DENY"
    assert response.json()["execution_status"] == "NOT_EXECUTED"


def test_duplicate_request_id_rejected():
    sid, token = create_session()

    payload = {
        "session_id": sid,
        "request_id": "same-request-id",
        "action": "calendar.create_event",
        "parameters": {
            "title": "Meeting",
            "date": "tomorrow",
            "time": "10 AM",
        },
    }

    first = client.post(
        "/api/actions",
        headers={"X-Capability-Token": token},
        json=payload,
    )
    second = client.post(
        "/api/actions",
        headers={"X-Capability-Token": token},
        json=payload,
    )

    assert first.status_code == 200
    assert second.status_code == 409


def test_missing_token_rejected():
    sid, _ = create_session()

    response = client.post(
        "/api/actions",
        json={
            "session_id": sid,
            "action": "calendar.create_event",
            "parameters": {
                "title": "Meeting",
                "date": "tomorrow",
                "time": "10 AM",
            },
        },
    )

    assert response.status_code == 401


def test_review_approval_does_not_execute_action():
    sid, token = create_session()

    action_response = client.post(
        "/api/actions",
        headers={"X-Capability-Token": token},
        json={
            "session_id": sid,
            "request_id": "review-approve-test",
            "action": "email.send",
            "parameters": {
                "recipient": "rahul@example.com",
                "subject": "Meeting",
                "body": "Meeting confirmed",
            },
        },
    )

    assert action_response.status_code == 200
    assert action_response.json()["decision"] == "REVIEW"
    assert action_response.json()["execution_status"] == "NOT_EXECUTED"

    review_response = client.post(
        "/api/reviews/review-approve-test",
        headers={"X-Reviewer-Key": REVIEWER_TEST_KEY},
        json={"decision": "APPROVE", "note": "Approved for testing"},
    )

    assert review_response.status_code == 200
    assert review_response.json()["review_decision"] == "APPROVE"

    audit_response = client.get("/api/audit")
    assert audit_response.status_code == 200

    item = next(
        item
        for item in audit_response.json()["items"]
        if item["request_id"] == "review-approve-test"
    )

    assert item["execution_status"] == "APPROVED_PENDING_EXECUTION"


def test_review_rejection_is_recorded():
    sid, token = create_session()

    action_response = client.post(
        "/api/actions",
        headers={"X-Capability-Token": token},
        json={
            "session_id": sid,
            "request_id": "review-reject-test",
            "action": "email.send",
            "parameters": {
                "recipient": "rahul@example.com",
                "subject": "Meeting",
                "body": "Meeting confirmed",
            },
        },
    )

    assert action_response.status_code == 200
    assert action_response.json()["decision"] == "REVIEW"

    review_response = client.post(
        "/api/reviews/review-reject-test",
        headers={"X-Reviewer-Key": REVIEWER_TEST_KEY},
        json={"decision": "REJECT", "note": "Rejected for testing"},
    )

    assert review_response.status_code == 200
    assert review_response.json()["review_decision"] == "REJECT"

    audit_response = client.get("/api/audit")
    assert audit_response.status_code == 200

    item = next(
        item
        for item in audit_response.json()["items"]
        if item["request_id"] == "review-reject-test"
    )

    assert item["execution_status"] == "REJECTED_BY_REVIEWER"


def test_review_cannot_be_decided_twice():
    sid, token = create_session()

    action_response = client.post(
        "/api/actions",
        headers={"X-Capability-Token": token},
        json={
            "session_id": sid,
            "request_id": "review-double-test",
            "action": "email.send",
            "parameters": {
                "recipient": "rahul@example.com",
                "subject": "Meeting",
                "body": "Meeting confirmed",
            },
        },
    )

    assert action_response.status_code == 200
    assert action_response.json()["decision"] == "REVIEW"

    first_review = client.post(
        "/api/reviews/review-double-test",
        headers={"X-Reviewer-Key": REVIEWER_TEST_KEY},
        json={"decision": "APPROVE", "note": "First decision"},
    )

    second_review = client.post(
        "/api/reviews/review-double-test",
        headers={"X-Reviewer-Key": REVIEWER_TEST_KEY},
        json={"decision": "REJECT", "note": "Second decision"},
    )

    assert first_review.status_code == 200
    assert second_review.status_code == 409
