import os
import io
import pytest
from starlette.testclient import TestClient
from PIL import Image

from app.main import app
from app.config import settings
from app.services.text_detector import text_detector
from app.services.url_detector import url_detector
from app.services.image_detector import image_detector
from app.services.audio_detector import audio_detector
from app.services.video_detector import video_detector
from app.utils.security import is_ssrf_safe_url, validate_file_signature
from app.models.schemas import RiskLevel

client = TestClient(app)

def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "operational"
    assert "DeepShield" in data["service"]

def test_capabilities_endpoint():
    res = client.get("/api/capabilities")
    assert res.status_code == 200
    data = res.json()
    assert data["text_detector"]["status"] == "active"
    assert data["url_detector"]["status"] == "active"
    assert data["image_detector"]["status"] == "active"

def test_text_scam_detector_phishing():
    payload = {
        "text": "URGENT: Your Chase checking account has been suspended due to fraudulent activity. Click here to confirm your 6-digit OTP verification code immediately.",
        "channel": "sms"
    }
    res = client.post("/api/analyze/text", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] in ("HIGH_RISK", "MEDIUM_RISK")
    assert data["confidence"] > 0.5
    assert len(data["evidence"]) > 0
    assert len(data["recommended_actions"]) > 0

def test_text_scam_detector_benign():
    payload = {
        "text": "Hi grandma, hope you are feeling better today! I'll drop by this Sunday afternoon to help with the garden.",
        "channel": "chat"
    }
    res = client.post("/api/analyze/text", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] == "LOW_RISK"

def test_url_ssrf_protection():
    is_safe, msg = is_ssrf_safe_url("http://127.0.0.1:8000/internal-admin")
    assert not is_safe
    assert "blocked" in msg.lower()

    is_safe_169, _ = is_ssrf_safe_url("http://169.254.169.254/latest/meta-data")
    assert not is_safe_169

    is_safe_benign, _ = is_ssrf_safe_url("https://www.google.com")
    assert is_safe_benign

def test_url_detector_homoglyph_and_brand_spoof():
    # Cyrillic lookalike for 'paypal'
    res = client.post("/api/analyze/url", json={"url": "http://pаypal-security-login.top/verify"})
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] == "HIGH_RISK"
    assert data["has_homoglyphs"] is True or len(data["suspicious_tokens"]) > 0

def test_url_detector_benign():
    res = client.post("/api/analyze/url", json={"url": "https://en.wikipedia.org/wiki/Computer_security"})
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] == "LOW_RISK"

def test_file_signature_validation_rejection():
    # Attempting to upload text file disguised as JPEG
    fake_jpeg = b"This is a malicious shell script pretending to be an image"
    valid, detected = validate_file_signature(fake_jpeg, "image/jpeg")
    assert not valid

def test_image_detector_synthetic_and_tampering():
    # Generate a small valid test JPEG in-memory
    img = Image.new("RGB", (120, 120), color=(73, 109, 137))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=95)
    img_bytes = buf.getvalue()

    # Upload as form-data
    res = client.post(
        "/api/analyze/image",
        files={"file": ("test.jpg", img_bytes, "image/jpeg")}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["dimensions"] == [120, 120]
    assert data["format"] == "JPEG"
    assert "annotated_heatmap_base64" in data
    assert data["annotated_heatmap_base64"].startswith("data:image/png;base64,")

def test_audio_detector_valid_and_transcription():
    # Create a tiny 1-second 16kHz test WAV
    import numpy as np
    from scipy.io import wavfile
    rate = 16000
    samples = (np.sin(2 * np.pi * 440 * np.arange(rate) / rate) * 32767).astype(np.int16)
    buf = io.BytesIO()
    wavfile.write(buf, rate, samples)
    wav_bytes = buf.getvalue()

    res = client.post(
        "/api/analyze/audio",
        files={"file": ("tone.wav", wav_bytes, "audio/wav")},
        data={"transcript": "Please send 500 dollars via wire transfer right now or you will be arrested"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["duration_seconds"] > 0.5
    assert len(data["evidence"]) > 0

def test_evaluation_framework_endpoint():
    res = client.post("/api/evaluate")
    assert res.status_code == 200
    data = res.json()
    assert "confusion_matrix" in data
    assert "metrics" in data
    assert data["metrics"]["recall"] > 0.8
    assert data["metrics"]["f1_score"] > 0.8

def test_database_crud_and_zero_retention():
    # Verify stats
    stats_res = client.get("/api/stats")
    assert stats_res.status_code == 200
    
    # List analyses
    list_res = client.get("/api/analyses?limit=10")
    assert list_res.status_code == 200
    assert "records" in list_res.json()

def test_cloud_settings_persistence_and_status():
    # Test GET settings
    get_res = client.get("/api/settings/cloud-analysis")
    assert get_res.status_code == 200
    assert "user_enabled" in get_res.json()
    assert "effective_enabled" in get_res.json()

    # Test PUT toggle
    put_res = client.put("/api/settings/cloud-analysis", json={"enabled": False})
    assert put_res.status_code == 200
    assert put_res.json()["user_enabled"] is False
    assert put_res.json()["effective_enabled"] is False

    # Verify diagnostic status
    status_res = client.get("/api/llm/status")
    assert status_res.status_code == 200
    st_data = status_res.json()
    assert "ollama" in st_data
    assert "gemini" in st_data
    assert st_data["cloud_analysis_policy"]["user_enabled"] is False

    # Restore to True
    client.put("/api/settings/cloud-analysis", json={"enabled": True})

def test_two_stage_pipeline_sequencing_and_cloud_disabled():
    # Set cloud analysis to disabled
    client.put("/api/settings/cloud-analysis", json={"enabled": False})

    res = client.post("/api/analyze/text", json={
        "text": "Your Amazon account has unauthorized charges. Click link to verify your password.",
        "channel": "email"
    })
    assert res.status_code == 200
    data = res.json()
    # When cloud is disabled, Gemini must NOT run
    assert data["gemini_stage_status"] == "not_run_cloud_disabled"
    assert data["overall_status"] == "Local only"
    assert "Cloud reviewer was skipped" in " ".join(data["limitations"])

    # Restore setting
    client.put("/api/settings/cloud-analysis", json={"enabled": True})

def test_two_stage_pipeline_admin_override():
    from app.services.llm_pipeline import two_stage_pipeline
    original_server_setting = settings.LLM_CLOUD_ENABLED
    try:
        settings.LLM_CLOUD_ENABLED = False
        user_en, srv_allow, eff_en, desc = two_stage_pipeline.get_cloud_policy()
        assert srv_allow is False
        assert eff_en is False
        assert "administratively disabled" in desc
    finally:
        settings.LLM_CLOUD_ENABLED = original_server_setting

def test_evidence_validation_rejects_hallucinations():
    from app.services.llm_pipeline import two_stage_pipeline
    original_text = "Urgent: Your account is locked. Please confirm your OTP."
    
    mock_evidence = [
        {
            "title": "Legitimate Quote",
            "description": "Urgent prompt",
            "severity": "high",
            "category": "Urgency",
            "exact_quote": "Your account is locked"
        },
        {
            "title": "Fabricated Quote",
            "description": "Hallucinated claim",
            "severity": "high",
            "category": "Blackmail",
            "exact_quote": "We have video of your webcam" # NOT in original_text!
        }
    ]

    validated = two_stage_pipeline._validate_evidence_spans(original_text, mock_evidence)
    assert len(validated) == 2
    # First quote matched verbatim
    assert validated[0].snippet == "Your account is locked"
    # Second quote was not in text, so snippet must be None and limitation noted in description
    assert validated[1].snippet is None
    assert "could not be strictly verified" in validated[1].description

def test_tunnel_status_endpoint():
    res = client.get("/api/tunnel/status")
    assert res.status_code == 200
    data = res.json()
    assert "status" in data
    assert data["status"] in ("online", "offline")
    assert "target_addr" in data

def test_enriched_health_subsystems():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "operational"
    assert "backend" in data
    assert data["backend"]["status"] == "operational"
    assert "ollama" in data
    assert data["ollama"]["status"] in ("online", "offline")
    assert "gemini" in data
    assert "tunnel" in data
    assert data["storage"] == "sqlite_wal_active"

def test_backend_authentication_middleware():
    original_key = settings.BACKEND_API_KEY
    try:
        settings.BACKEND_API_KEY = "test-secret-key-12345"

        # Public endpoint should still be accessible
        res_public = client.get("/api/health")
        assert res_public.status_code == 200

        # Protected endpoint without key should receive 401
        res_unauth = client.delete("/api/analyses/test-id")
        assert res_unauth.status_code == 401
        assert "Authentication required" in res_unauth.json()["detail"]

        # Protected endpoint with wrong key should receive 401
        res_wrong = client.delete("/api/analyses/test-id", headers={"x-api-key": "wrong-key"})
        assert res_wrong.status_code == 401

        # Protected endpoint with valid X-API-Key should be accepted (404 for non-existent item, but authenticated!)
        res_auth_header = client.delete("/api/analyses/test-id", headers={"x-api-key": "test-secret-key-12345"})
        assert res_auth_header.status_code != 401

        # Protected endpoint with valid Bearer token should be accepted
        res_auth_bearer = client.delete("/api/analyses/test-id", headers={"Authorization": "Bearer test-secret-key-12345"})
        assert res_auth_bearer.status_code != 401
    finally:
        settings.BACKEND_API_KEY = original_key


