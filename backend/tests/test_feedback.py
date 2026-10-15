import pytest
from starlette.testclient import TestClient

from app.main import app
from app.models.schemas import RiskLevel
from app.services.text_detector import text_detector
from app.database import (
    create_feedback,
    get_feedbacks,
    get_feedback_by_id,
    update_feedback_review,
    export_curated_feedback,
    redact_sensitive_pii
)

client = TestClient(app)

# ============================================================================
# 1. TEXT SCAM CONTEXTUAL REGRESSION TESTS (FALSE POSITIVE PREVENTION)
# ============================================================================

def test_text_context_legitimate_police_notice():
    """Legitimate community notice mentioning police without coercion must be LOW_RISK."""
    sample = "The local police department is hosting a neighborhood watch and crime prevention meeting this Friday at 6 PM."
    res = text_detector.analyze(sample)
    assert res.risk_level == RiskLevel.LOW_RISK
    assert not any(e.title == "Arrest / Criminal Warrant Threat" for e in res.evidence)

def test_text_context_legitimate_congratulations():
    """Benign congratulatory message without prize/courier fee lure must be LOW_RISK."""
    sample = "Congratulations on finishing your master's degree, Michael! We are all so proud of you."
    res = text_detector.analyze(sample)
    assert res.risk_level == RiskLevel.LOW_RISK
    assert not any(e.title == "Unsolicited Prize / Advance-Fee Lottery Lure" for e in res.evidence)

def test_text_context_legitimate_ceo_announcement():
    """CEO speaking about company quarterly metrics without gift card or wire request is LOW_RISK."""
    sample = "Our CEO announced the Q3 financial results during this morning's all-hands company meeting."
    res = text_detector.analyze(sample)
    assert res.risk_level == RiskLevel.LOW_RISK
    assert not any(e.title == "Executive Impersonation / Gift Card Lure" for e in res.evidence)

def test_text_context_legitimate_otp_defensive_warning():
    """Authentic automated SMS warning recipient NOT to share code must be LOW_RISK."""
    sample = "592810 is your Microsoft security code. We will never ask for your code. Do not share this code with anyone."
    res = text_detector.analyze(sample)
    assert res.risk_level == RiskLevel.LOW_RISK
    assert not any(e.title == "MFA / OTP Token Theft Solicitation" for e in res.evidence)

def test_text_context_adversarial_ceo_gift_card():
    """CEO impersonation demanding urgent gift cards must be HIGH_RISK with evidence."""
    sample = "Hi, this is Mark, your CEO. I am trapped in a confidential board meeting. Buy three $200 Apple gift cards and text me the codes."
    res = text_detector.analyze(sample)
    assert res.risk_level == RiskLevel.HIGH_RISK
    assert any("Gift Card" in e.title for e in res.evidence)

def test_text_context_adversarial_arrest_warrant():
    """Authority impersonation threatening arrest warrant must be HIGH_RISK."""
    sample = "IRS Final Warning: A federal warrant has been issued for your immediate arrest. Call federal marshals right now to settle your arrears."
    res = text_detector.analyze(sample)
    assert res.risk_level == RiskLevel.HIGH_RISK
    assert any("Arrest" in e.title or "Law Enforcement" in e.title for e in res.evidence)


# ============================================================================
# 2. FEEDBACK SUBMISSION AND DEDUPLICATION TESTS
# ============================================================================

def test_feedback_submission_endpoint():
    """Submit valid feedback and verify pending status and database persistence."""
    payload = {
        "analysis_id": "test_scan_001",
        "detection_module": "text",
        "predicted_verdict": "SCAM",
        "predicted_risk_level": "HIGH_RISK",
        "user_correction": "false_positive",
        "corrected_risk_level": "LOW_RISK",
        "explanation": "This was a routine flight status notification from United Airlines.",
        "target_content": "United flight UA104 is on time to Denver."
    }
    res = client.post("/api/feedback", json=payload)
    assert res.status_code in (200, 201)
    data = res.json()
    assert data["id"].startswith("fb_")
    assert data["detection_module"] == "text"
    assert data["user_correction"] == "false_positive"
    assert data["review_status"] == "pending"
    assert data["dataset_eligible"] is False

import uuid

def test_feedback_deduplication():
    """Submitting the exact same correction for an analysis_id within short window returns existing record."""
    unique_analysis_id = f"test_scan_dup_{uuid.uuid4().hex[:8]}"
    payload = {
        "analysis_id": unique_analysis_id,
        "detection_module": "url",
        "predicted_verdict": "SCAM",
        "predicted_risk_level": "HIGH_RISK",
        "user_correction": "false_positive",
        "explanation": "Official internal company wiki link.",
        "target_content": "https://wiki.corp.internal/handbook"
    }
    res1 = client.post("/api/feedback", json=payload)
    assert res1.status_code == 201
    id1 = res1.json()["id"]

    # Immediate re-submission
    res2 = client.post("/api/feedback", json=payload)
    assert res2.status_code == 200
    id2 = res2.json()["id"]
    assert id1 == id2 # Same feedback record returned, duplicate avoided

def test_feedback_invalid_module_rejection():
    """Invalid module name must be rejected with 400 Bad Request."""
    payload = {
        "detection_module": "invalid_telepathy_detector",
        "user_correction": "false_positive"
    }
    res = client.post("/api/feedback", json=payload)
    assert res.status_code == 400
    assert "Invalid detection module" in res.json()["detail"]


# ============================================================================
# 3. FEEDBACK REVIEW TRANSITIONS AND PERMISSION GATES
# ============================================================================

def test_feedback_review_lifecycle():
    """Verify state transitions: pending -> accepted (eligible) / rejected (ineligible)."""
    # 1. Create a feedback with unique analysis ID
    fb_data = {
        "analysis_id": f"scan_review_test_{uuid.uuid4().hex[:8]}",
        "detection_module": "text",
        "predicted_verdict": "BENIGN",
        "predicted_risk_level": "LOW_RISK",
        "user_correction": "false_negative",
        "corrected_risk_level": "HIGH_RISK",
        "explanation": "This was an advanced spear phishing invoice lure with bank wire instructions.",
        "target_content": "Please wire $15,000 for overdue invoice INV-9921 to account 09817234."
    }
    created, _ = create_feedback(fb_data)
    fb_id = created["id"]
    assert created["review_status"] == "pending"
    assert created["dataset_eligible"] is False

    # 2. Review: Accept feedback
    review_res = client.patch(
        f"/api/feedback/{fb_id}/review",
        json={
            "review_status": "accepted",
            "reviewer_notes": "Verified against threat intelligence: confirmed malicious wire destination."
        }
    )
    assert review_res.status_code == 200
    updated = review_res.json()
    assert updated["review_status"] == "accepted"
    assert updated["dataset_eligible"] is True
    assert "Verified against threat intelligence" in updated["reviewer_notes"]

    # 3. Review: Reject feedback
    reject_res = client.patch(
        f"/api/feedback/{fb_id}/review",
        json={
            "review_status": "rejected",
            "reviewer_notes": "Sample re-evaluated: user claims are contradicted by internal auth logs."
        }
    )
    assert reject_res.status_code == 200
    rejected = reject_res.json()
    assert rejected["review_status"] == "rejected"
    assert rejected["dataset_eligible"] is False


# ============================================================================
# 4. CURATED DATASET EXPORT AND PII REDACTION
# ============================================================================

def test_pii_redaction_utility():
    """Ensure emails, phone numbers, credit cards, and IP addresses are securely redacted."""
    raw = "Contact support@phishing-target.com or call +1 555-019-2834. Card 4111 2222 3333 4444 on IP 192.168.1.100."
    redacted = redact_sensitive_pii(raw)
    assert "[REDACTED_EMAIL]" in redacted
    assert "support@phishing-target.com" not in redacted
    assert "[REDACTED_PHONE]" in redacted
    assert "555-019-2834" not in redacted
    assert "[REDACTED_CARD]" in redacted
    assert "4111 2222 3333 4444" not in redacted
    assert "[REDACTED_IP]" in redacted
    assert "192.168.1.100" not in redacted

def test_curated_export_filters_and_formats():
    """Curated export must only include accepted items, redact PII, and support JSON/JSONL."""
    # Ensure at least one accepted feedback exists
    fb_data = {
        "analysis_id": "scan_curated_export_1",
        "detection_module": "text",
        "predicted_risk_level": "HIGH_RISK",
        "user_correction": "false_positive",
        "corrected_risk_level": "LOW_RISK",
        "explanation": "Internal dev announcement sent to admin@company.com.",
        "target_content": "Deploy complete on server 10.0.0.1. Call 555-123-4567 for rollback."
    }
    rec, _ = create_feedback(fb_data)
    update_feedback_review(rec["id"], review_status="accepted", reviewer_notes="Approved for training dataset")

    # Test JSON export
    res_json = client.get("/api/feedback/export?format=json")
    assert res_json.status_code == 200
    data = res_json.json()
    assert data["version"] == "v1.2.0"
    assert len(data["records"]) > 0
    # Verify PII is redacted in exported target
    for record in data["records"]:
        assert "@company.com" not in record["target_content"]
        assert "10.0.0.1" not in record["target_content"]

    # Test JSONL export
    res_jsonl = client.get("/api/feedback/export?format=jsonl")
    assert res_jsonl.status_code == 200
    assert res_jsonl.headers["content-type"].startswith("application/x-ndjson")
    lines = res_jsonl.text.strip().split("\n")
    assert len(lines) > 0


# ============================================================================
# 5. FEEDBACK STATS AND AGGREGATION
# ============================================================================

def test_feedback_stats_endpoint():
    """Retrieve operational feedback statistics."""
    res = client.get("/api/feedback/stats")
    assert res.status_code == 200
    stats = res.json()
    assert "total_feedback" in stats
    assert "by_module" in stats
    assert "by_status" in stats
    assert "by_correction" in stats
    assert stats["total_feedback"] >= 1
    assert stats["active_detector_version"] == "v1.2.0"
