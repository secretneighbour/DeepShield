import io
import time
import pytest
from starlette.testclient import TestClient
from PIL import Image

from app.main import app
from app.models.schemas import RiskLevel
from app.services.url_detector import url_detector, split_domain_components
from app.services.image_detector import image_detector
from app.services.threat_intel import threat_intel_service

client = TestClient(app)

# ============================================================================
# 1. URL DETECTION TESTS
# ============================================================================

def test_url_compound_tld_parsing():
    """Verify standards-compliant parsing for multi-part / compound TLDs."""
    sub, main, tld, reg = split_domain_components("login.paypal.co.uk")
    assert sub == "login"
    assert main == "paypal"
    assert tld == "co.uk"
    assert reg == "paypal.co.uk"

    sub2, main2, tld2, reg2 = split_domain_components("portal.service.gov.au")
    assert sub2 == "portal"
    assert main2 == "service"
    assert tld2 == "gov.au"
    assert reg2 == "service.gov.au"

@pytest.mark.asyncio
async def test_url_legitimate_structure():
    """Legitimate brand URLs should be classified as LOW_RISK with high confidence."""
    res = await url_detector.analyze("https://login.paypal.co.uk", check_threat_intel=False)
    assert res.risk_level == RiskLevel.LOW_RISK
    assert res.confidence >= 0.85
    assert res.structure["registered_domain"] == "paypal.co.uk"
    assert not any(e.title.startswith("Brand Lookalike") for e in res.evidence)

@pytest.mark.asyncio
async def test_url_lookalike_domain():
    """Brand lookalike domains must be flagged as HIGH_RISK."""
    res = await url_detector.analyze("http://chase-security-update.xyz/verify", check_threat_intel=False)
    assert res.risk_level == RiskLevel.HIGH_RISK
    assert any("Brand Lookalike" in e.title for e in res.evidence)
    assert any("High-Abuse Top-Level Domain" in e.title for e in res.evidence)

@pytest.mark.asyncio
async def test_url_deceptive_subdomain_impersonation():
    """Target brand in subdomain on unrelated registered domain must trigger HIGH_RISK."""
    res = await url_detector.analyze("https://chase.com.security-alert-login.net/auth", check_threat_intel=False)
    assert res.risk_level == RiskLevel.HIGH_RISK
    assert any("Deceptive Subdomain Impersonation" in e.title for e in res.evidence)
    assert res.structure["registered_domain"] == "security-alert-login.net"

@pytest.mark.asyncio
async def test_url_userinfo_delimiter_spoof():
    """Authority '@' delimiter spoofing must be flagged as high-severity."""
    res = await url_detector.analyze("https://paypal.com@malicious-lure.org/login", check_threat_intel=False)
    assert res.risk_level == RiskLevel.HIGH_RISK
    assert any("Deceptive Authority Userinfo" in e.title for e in res.evidence)

@pytest.mark.asyncio
async def test_url_homoglyph_and_punycode():
    """Punycode (xn--) and Unicode homoglyphs must be detected."""
    # Punycode
    res_puny = await url_detector.analyze("https://xn--apple-43a.com/support", check_threat_intel=False)
    assert res_puny.has_homoglyphs is True
    assert any("Punycode" in e.title for e in res_puny.evidence)

    # Cyrillic lookalike character
    res_homo = await url_detector.analyze("https://p\u0430ypal.com/signin", check_threat_intel=False)
    assert res_homo.has_homoglyphs is True
    assert any("Homoglyph" in e.title for e in res_homo.evidence)

@pytest.mark.asyncio
async def test_url_nested_redirect_parameters():
    """URLs with nested redirect/target parameters should be flagged."""
    res = await url_detector.analyze("https://legit-site.com/redirect?url=https://evil-phish.xyz/lure", check_threat_intel=False)
    assert any("Nested Redirect Parameter" in e.title for e in res.evidence)

@pytest.mark.asyncio
async def test_url_direct_ip_not_automatically_high_risk():
    """Public direct IP without malicious signals must not be forced to HIGH_RISK."""
    res = await url_detector.analyze("http://93.184.216.34/page.html", check_threat_intel=False)
    assert res.risk_level == RiskLevel.LOW_RISK
    assert res.is_ip_address is True

@pytest.mark.asyncio
async def test_url_invalid_and_empty_input():
    """Invalid, empty, or unparseable input must return INCONCLUSIVE safely."""
    res_empty = await url_detector.analyze("", check_threat_intel=False)
    assert res_empty.risk_level == RiskLevel.INCONCLUSIVE
    assert res_empty.confidence == 0.5

@pytest.mark.asyncio
async def test_threat_intel_unconfigured_honest_reporting():
    """When external feeds are unconfigured, report UNRATED without fabricating clean reputation."""
    res = await threat_intel_service.check_url_reputation("https://unknown-site-12345.com", "unknown-site-12345.com")
    assert not res["is_flagged"]
    if not threat_intel_service.safe_browsing_key and not threat_intel_service.virustotal_key:
        assert "UNRATED" in res["verdict"]

# ============================================================================
# 2. IMAGE DETECTION TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_image_benign_rgb():
    """A standard benign JPEG should pass local heuristics and produce an ELA heatmap."""
    img = Image.new("RGB", (100, 100), color=(120, 140, 160))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=90)
    raw = buf.getvalue()

    res = await image_detector.analyze(raw, "benign.jpg", "image/jpeg", cloud_enabled=False)
    assert res.analysis_status == "completed"
    assert res.risk_level == RiskLevel.LOW_RISK
    assert res.dimensions == [100, 100]
    assert res.annotated_heatmap_base64 is not None
    assert res.ocr_status == "unavailable_offline"

@pytest.mark.asyncio
async def test_image_invalid_file_signature_blocked():
    """Files disguised as images (e.g. bash script) must be rejected with HIGH_RISK."""
    fake_img = b"#!/bin/bash\necho 'disguised payload'\n"
    res = await image_detector.analyze(fake_img, "exploit.jpg", "image/jpeg", cloud_enabled=False)
    assert res.risk_level == RiskLevel.HIGH_RISK
    assert res.analysis_status == "failed"
    assert any("Invalid File Header Signature" in e.title for e in res.evidence)

@pytest.mark.asyncio
async def test_image_corrupted_stream_handled_safely():
    """Corrupted image bytes should yield INCONCLUSIVE without crashing."""
    corrupted_bytes = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00corrupted_garbage"
    res = await image_detector.analyze(corrupted_bytes, "bad.jpg", "image/jpeg", cloud_enabled=False)
    assert res.risk_level == RiskLevel.INCONCLUSIVE
    assert res.analysis_status == "failed"

@pytest.mark.asyncio
async def test_image_oversized_guard():
    """Oversized payloads exceeding threshold must be rejected safely."""
    detector = image_detector
    # Temporarily set max_size_bytes to small value to test guard safely
    orig_max = detector.max_size_bytes
    try:
        detector.max_size_bytes = 1024  # 1 KB limit
        res = await detector.analyze(b"A" * 2048, "large.jpg", "image/jpeg", cloud_enabled=False)
        assert res.risk_level == RiskLevel.INCONCLUSIVE
        assert res.analysis_status == "failed"
        assert any("Exceeds Upload Threshold" in e.title for e in res.evidence)
    finally:
        detector.max_size_bytes = orig_max

@pytest.mark.asyncio
async def test_image_scam_text_separate_from_synthetic_media():
    """
    Test deterministic separation:
    Scam message in screenshot evaluates scam_content_risk=HIGH_RISK
    while synthetic_media_risk=LOW_RISK.
    """
    scam_text = "URGENT: Your Chase checking account is suspended. Send $500 in gift cards or bitcoin immediately."
    risk, conf, evidence = image_detector._analyze_scam_text(scam_text)
    assert risk == RiskLevel.HIGH_RISK
    assert conf >= 0.85
    assert any("Financial" in e.title or "Urgency" in e.title for e in evidence)

# ============================================================================
# 3. API RELIABILITY TESTS
# ============================================================================

def test_api_text_bounded_response_time():
    """The /api/analyze/text endpoint must return in bounded time (< 15 seconds)."""
    start = time.time()
    payload = {
        "text": "Your account has been deactivated. Verify immediately at http://chase-update.xyz",
        "channel": "sms"
    }
    res = client.post("/api/analyze/text", json=payload)
    elapsed = time.time() - start

    assert res.status_code == 200
    assert elapsed < 15.0, f"Analysis took {elapsed:.2f}s, exceeding 15.0s limit"
    data = res.json()
    assert "risk_level" in data
    assert "overall_status" in data
    assert "limitations" in data

def test_api_image_endpoint():
    """Test image upload via API endpoint."""
    img = Image.new("RGB", (64, 64), color=(50, 100, 150))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    raw = buf.getvalue()

    res = client.post(
        "/api/analyze/image?cloud_enabled=false",
        files={"file": ("test.jpg", raw, "image/jpeg")}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["analysis_status"] == "completed"
    assert data["dimensions"] == [64, 64]
    assert "deepfake_detector_status" in data
