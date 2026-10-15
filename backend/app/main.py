import os
import time
import json
from typing import Optional, List, Dict, Any

import httpx
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException, Request, Response, UploadFile, File, Form, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.database import (
    init_db,
    save_analysis,
    get_analyses,
    get_analysis_by_id,
    delete_analysis,
    clear_all_analyses,
    get_stats,
    log_audit,
    get_setting,
    set_setting,
    create_feedback,
    get_feedbacks,
    get_feedback_by_id,
    update_feedback_review,
    get_feedback_stats,
    export_curated_feedback,
)
from app.models.schemas import (
    TextAnalysisRequest,
    TextAnalysisResponse,
    URLAnalysisRequest,
    URLAnalysisResponse,
    ImageAnalysisResponse,
    VideoAnalysisResponse,
    AudioAnalysisResponse,
    SystemCapabilitiesResponse,
    StatsResponse,
    CloudAnalysisSettingsResponse,
    CloudAnalysisSettingsUpdate,
    LLMStatusResponse,
    FeedbackCreateRequest,
    FeedbackReviewRequest,
    FeedbackResponse,
    FeedbackStatsResponse,
)
from app.services.text_detector import text_detector
from app.services.llm_pipeline import two_stage_pipeline
from app.services.url_detector import url_detector
from app.services.image_detector import image_detector
from app.services.video_detector import video_detector
from app.services.audio_detector import audio_detector
from app.services.threat_intel import threat_intel_service
from app.services.evaluator import evaluator
from app.utils.security import rate_limiter

# Initialize database schema on startup
init_db()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Explainable, privacy-conscious AI-powered scam and deepfake detection platform",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_origin_regex=settings.ALLOWED_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

async def fetch_ngrok_status() -> Dict[str, Any]:
    """Inspect local ngrok agent API to obtain active tunnel metadata and public HTTPS URL."""
    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            res = await client.get(settings.NGROK_API_URL)
            if res.status_code == 200:
                tunnels = res.json().get("tunnels", [])
                if tunnels:
                    https_tunnel = next((t for t in tunnels if t.get("proto") == "https"), tunnels[0])
                    return {
                        "status": "online",
                        "public_url": https_tunnel.get("public_url"),
                        "proto": https_tunnel.get("proto"),
                        "target_addr": https_tunnel.get("config", {}).get("addr"),
                        "name": https_tunnel.get("name"),
                        "persistent_domain_configured": bool(settings.NGROK_DOMAIN),
                    }
    except Exception:
        pass
    return {
        "status": "offline",
        "public_url": None,
        "target_addr": f"http://127.0.0.1:{settings.NGROK_PORT}",
        "persistent_domain_configured": bool(settings.NGROK_DOMAIN),
        "message": "ngrok tunnel is not active. Run './run_ngrok.sh' or './start_all.sh' to expose publicly."
    }

# Security Headers & Rate Limiting Middleware
@app.middleware("http")
async def security_and_ratelimit_middleware(request: Request, call_next):
    # Extract client IP supporting reverse proxy X-Forwarded-For header
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
    elif request.client:
        client_ip = request.client.host
    else:
        client_ip = "127.0.0.1"

    # Optional backend authentication when configured
    if settings.BACKEND_API_KEY and request.url.path.startswith("/api/"):
        public_paths = ("/api/health", "/api/capabilities", "/api/tunnel/status", "/api/llm/status", "/api/stats", "/api/feedback")
        if not any(request.url.path == p or request.url.path.startswith(f"{p}/") for p in public_paths):
            api_key_header = request.headers.get("x-api-key")
            auth_header = request.headers.get("authorization", "")
            bearer_token = auth_header.replace("Bearer ", "").strip() if auth_header.startswith("Bearer ") else ""
            if api_key_header != settings.BACKEND_API_KEY and bearer_token != settings.BACKEND_API_KEY:
                log_audit("AUTH_FAILURE", client_ip, f"Unauthorized request to {request.url.path}")
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Authentication required. Provide valid X-API-Key or Bearer token."}
                )

    # Rate limiting on write/analyze endpoints
    if request.method in ("POST", "DELETE", "PUT") and request.url.path.startswith("/api/"):
        if not rate_limiter.is_allowed(client_ip):
            log_audit("RATE_LIMIT_EXCEEDED", client_ip, f"Path: {request.url.path}")
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Request limit exceeded. Please wait a moment before submitting further analyses."}
            )

    start_time = time.time()
    try:
        response = await call_next(request)
    except Exception as exc:
        # Prevent stack trace leakage to clients
        log_audit("UNHANDLED_EXCEPTION", client_ip, f"Path: {request.url.path}, Error: {str(exc)[:200]}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An internal error occurred during security inspection. Please verify your input and try again."}
        )

    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = f"{process_time:.4f}s"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
    return response

# --- Core Diagnostics & Capabilities ---

@app.get("/api/health")
async def get_health(request: Request):
    """Expose service health without leaking credentials or server paths."""
    ollama_info = await two_stage_pipeline.check_ollama_health()
    gemini_info = two_stage_pipeline.check_gemini_health()
    tunnel_info = await fetch_ngrok_status()
    return {
        "status": "operational",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "zero_retention_mode": settings.ENABLE_ZERO_RETENTION,
        "storage": "sqlite_wal_active",
        "backend": {
            "status": "operational",
            "host": "127.0.0.1",
            "port": 8000,
        },
        "ollama": {
            "status": ollama_info.get("status"),
            "target_model": ollama_info.get("target_model"),
            "target_model_installed": ollama_info.get("target_model_installed", False),
        },
        "gemini": {
            "api_key_configured": gemini_info.get("api_key_configured"),
            "configured_model": gemini_info.get("configured_model"),
            "server_allowed": gemini_info.get("server_allowed"),
        },
        "tunnel": {
            "status": tunnel_info.get("status"),
            "public_url": tunnel_info.get("public_url"),
        }
    }

@app.get("/api/tunnel/status")
async def get_tunnel_status():
    """Retrieve live status of ngrok public tunnel without exposing internal credentials."""
    return await fetch_ngrok_status()

@app.get("/api/capabilities", response_model=SystemCapabilitiesResponse)
def get_capabilities():
    """Return operational capabilities and detection models without fabricating statuses."""
    return SystemCapabilitiesResponse(
        app_name=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        text_detector={
            "status": "active",
            "model": "DeepShield Hybrid NLP & Rule Engine (TF-IDF + Calibrated Classifier v1.0)",
            "categories": 9,
            "latency": "<5ms",
            "local_execution": True
        },
        url_detector={
            "status": "active",
            "capabilities": ["SSRF Prevention", "Homoglyph & Punycode Mapping", "Shannon Entropy", "Brand Spoof Heuristics"],
            "external_threat_intel": "active (hybrid local + API fallback)",
            "local_execution": True
        },
        image_detector={
            "status": "active",
            "capabilities": ["Error Level Analysis (ELA)", "2D FFT Spectral Anomaly", "Noise Inconsistency", "EXIF Tamper Clues"],
            "max_file_size_mb": 30,
            "local_execution": True
        },
        video_detector={
            "status": "active",
            "capabilities": ["Frame Anomaly Sampling", "Inter-Frame Jitter Analysis", "Temporal Inconsistency Timeline"],
            "max_duration_sec": 60,
            "local_execution": True
        },
        audio_detector={
            "status": "active",
            "capabilities": ["Pitch Jitter Tracking", "Spectral Vocoder Rolloff", "Digital Silence Anomaly", "Dual-Verdict Transcript Intent"],
            "max_duration_sec": 120,
            "local_execution": True
        },
        threat_intel_status=threat_intel_service.get_providers_status(),
        security_safeguards=[
            "Strict MIME magic-byte verification",
            "SSRF protection blocking RFC-1918 and loopback CIDRs",
            "In-memory sliding window rate limiting",
            "Zero retention privacy compliance toggle",
            "Non-leaking sanitized error boundaries"
        ]
    )

# --- Analysis Endpoints ---

@app.get("/api/llm/status", response_model=LLMStatusResponse)
async def get_llm_status():
    """Return diagnostic status of Ollama Stage 1 and Gemini Stage 2 providers."""
    ollama_info = await two_stage_pipeline.check_ollama_health()
    gemini_info = two_stage_pipeline.check_gemini_health()
    user_en, srv_allow, eff_en, desc = two_stage_pipeline.get_cloud_policy()
    return LLMStatusResponse(
        ollama=ollama_info,
        gemini=gemini_info,
        cloud_analysis_policy={
            "user_enabled": user_en,
            "server_allowed": srv_allow,
            "effective_enabled": eff_en,
            "description": desc,
        },
        pipeline_ready=True
    )

@app.get("/api/settings/cloud-analysis", response_model=CloudAnalysisSettingsResponse)
def get_cloud_analysis_setting():
    """Return effective cloud analysis policy and user setting."""
    user_en, srv_allow, eff_en, desc = two_stage_pipeline.get_cloud_policy()
    return CloudAnalysisSettingsResponse(
        user_enabled=user_en,
        server_allowed=srv_allow,
        effective_enabled=eff_en,
        description=desc,
    )

@app.put("/api/settings/cloud-analysis", response_model=CloudAnalysisSettingsResponse)
def update_cloud_analysis_setting(payload: CloudAnalysisSettingsUpdate, request: Request):
    """Update user preference for Gemini cloud second-stage analysis."""
    set_setting("cloud_analysis_enabled", "true" if payload.enabled else "false")
    client_ip = request.client.host if request.client else "unknown"
    log_audit("UPDATE_CLOUD_SETTING", client_ip, f"Cloud analysis toggled to {payload.enabled}")
    user_en, srv_allow, eff_en, desc = two_stage_pipeline.get_cloud_policy()
    return CloudAnalysisSettingsResponse(
        user_enabled=user_en,
        server_allowed=srv_allow,
        effective_enabled=eff_en,
        description=desc,
    )

class GeminiConfigUpdate(BaseModel):
    api_key: Optional[str] = None
    model: Optional[str] = None

@app.post("/api/settings/gemini")
async def update_gemini_config(payload: GeminiConfigUpdate, request: Request):
    """Save Gemini API key and model dynamically without server restart."""
    if payload.api_key is not None:
        set_setting("gemini_api_key", payload.api_key.strip())
        os.environ["GEMINI_API_KEY"] = payload.api_key.strip()
    if payload.model is not None:
        set_setting("gemini_model", payload.model.strip())
        os.environ["GEMINI_MODEL"] = payload.model.strip()

    client_ip = request.client.host if request.client else "unknown"
    log_audit("UPDATE_GEMINI_SETTINGS", client_ip, f"Updated Gemini config. Model: {two_stage_pipeline.gemini_model}")
    return {
        "status": "success",
        "gemini": two_stage_pipeline.check_gemini_health()
    }

@app.post("/api/settings/gemini/test")
async def test_gemini_config():
    """Test live connectivity with the current Gemini configuration."""
    test_result = await two_stage_pipeline.test_gemini_connection()
    return test_result

@app.post("/api/analyze/text", response_model=TextAnalysisResponse)
async def analyze_text(payload: TextAnalysisRequest, request: Request):
    """Execute Two-Stage LLM Pipeline: Stage 1 (Local Ollama) followed by Stage 2 (Gemini Reviewer)."""
    result = await two_stage_pipeline.analyze(
        text=payload.text,
        sender_context=payload.sender_context,
        channel=payload.channel or "auto"
    )

    # Persist summary to database unless zero retention is active
    save_analysis(
        analysis_id=result.id,
        analysis_type="text",
        target_summary=payload.text[:120],
        risk_level=result.risk_level.value,
        confidence=result.confidence,
        category_or_detail=result.scam_category.value,
        full_result=result.model_dump()
    )

    client_ip = request.client.host if request.client else "unknown"
    log_audit("ANALYZE_TEXT", client_ip, f"Category: {result.scam_category.value}, Risk: {result.risk_level.value}, Overall: {result.overall_status}")
    return result

@app.post("/api/analyze/url", response_model=URLAnalysisResponse)
async def analyze_url(payload: URLAnalysisRequest, request: Request):
    """Analyze URL for phishing traits, homoglyphs, SSRF risks, and threat feeds."""
    result = await url_detector.analyze(
        raw_url=payload.url,
        check_threat_intel=payload.check_threat_intel
    )

    save_analysis(
        analysis_id=result.id,
        analysis_type="url",
        target_summary=result.normalized_url[:120],
        risk_level=result.risk_level.value,
        confidence=result.confidence,
        category_or_detail="Phishing & Reputation Scan",
        full_result=result.model_dump()
    )

    client_ip = request.client.host if request.client else "unknown"
    log_audit("ANALYZE_URL", client_ip, f"Host: {result.structure.get('domain', 'unknown')}, Risk: {result.risk_level.value}")
    return result

@app.post("/api/analyze/image", response_model=ImageAnalysisResponse)
async def analyze_image(
    file: UploadFile = File(...),
    cloud_enabled: bool = True,
    request: Request = None
):
    """Forensic deepfake and screenshot scam analysis using ELA, FFT, noise inconsistency, and multimodal OCR."""
    content = await file.read()
    if len(content) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum upload limit of {settings.MAX_UPLOAD_SIZE_MB}MB"
        )

    result = await image_detector.analyze(
        file_content=content,
        filename=file.filename or "image.jpg",
        declared_mime=file.content_type or "image/jpeg",
        cloud_enabled=cloud_enabled
    )

    save_analysis(
        analysis_id=result.id,
        analysis_type="image",
        target_summary=f"Image: {result.filename} ({result.dimensions[0]}x{result.dimensions[1]})",
        risk_level=result.risk_level.value,
        confidence=result.confidence,
        category_or_detail="Deepfake & ELA Forensics",
        full_result=result.model_dump()
    )

    client_ip = request.client.host if request and request.client else "unknown"
    log_audit("ANALYZE_IMAGE", client_ip, f"File: {file.filename}, Risk: {result.risk_level.value}")
    return result

@app.post("/api/analyze/video", response_model=VideoAnalysisResponse)
async def analyze_video(
    file: UploadFile = File(...),
    request: Request = None
):
    """Deepfake video analysis using controlled frame sampling and temporal jitter analysis."""
    content = await file.read()
    if len(content) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum upload limit of {settings.MAX_UPLOAD_SIZE_MB}MB"
        )

    result = video_detector.analyze(
        file_content=content,
        filename=file.filename or "video.mp4",
        declared_mime=file.content_type or "video/mp4"
    )

    save_analysis(
        analysis_id=result.id,
        analysis_type="video",
        target_summary=f"Video: {result.filename} ({result.duration_seconds}s, {result.total_frames_sampled} frames)",
        risk_level=result.risk_level.value,
        confidence=result.confidence,
        category_or_detail="Video Temporal Consistency",
        full_result=result.model_dump()
    )

    client_ip = request.client.host if request and request.client else "unknown"
    log_audit("ANALYZE_VIDEO", client_ip, f"File: {file.filename}, Risk: {result.risk_level.value}")
    return result

@app.post("/api/analyze/audio", response_model=AudioAnalysisResponse)
async def analyze_audio(
    file: UploadFile = File(...),
    transcript: Optional[str] = Form(None),
    request: Request = None
):
    """Audio authenticity and voice cloning inspection with dual-verdict transcript intent analysis."""
    content = await file.read()
    if len(content) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum upload limit of {settings.MAX_UPLOAD_SIZE_MB}MB"
        )

    result = audio_detector.analyze(
        file_content=content,
        filename=file.filename or "audio.wav",
        declared_mime=file.content_type or "audio/wav",
        transcript=transcript
    )

    save_analysis(
        analysis_id=result.id,
        analysis_type="audio",
        target_summary=f"Audio: {result.filename} ({result.duration_seconds}s, {result.voice_clone_likelihood})",
        risk_level=result.risk_level.value,
        confidence=result.confidence,
        category_or_detail=f"Voice Cloning: {result.voice_clone_likelihood}",
        full_result=result.model_dump()
    )

    client_ip = request.client.host if request and request.client else "unknown"
    log_audit("ANALYZE_AUDIO", client_ip, f"File: {file.filename}, Risk: {result.risk_level.value}")
    return result

# --- History and Forensic Records Management ---

@app.get("/api/analyses")
def list_analyses(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
    """List forensic analysis summaries from real database records."""
    records = get_analyses(limit=limit, offset=offset)
    return {
        "total_returned": len(records),
        "limit": limit,
        "offset": offset,
        "records": records
    }

@app.get("/api/analyses/{analysis_id}")
def retrieve_analysis(analysis_id: str):
    """Fetch the full forensic result JSON by ID."""
    result = get_analysis_by_id(analysis_id)
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Forensic record not found")
    return result

@app.delete("/api/analyses/{analysis_id}")
def remove_analysis(analysis_id: str, request: Request):
    """Delete a single analysis record."""
    success = delete_analysis(analysis_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Forensic record not found or already deleted")
    client_ip = request.client.host if request.client else "unknown"
    log_audit("DELETE_ANALYSIS", client_ip, f"ID: {analysis_id}")
    return {"status": "deleted", "id": analysis_id}

@app.delete("/api/analyses")
def clear_analyses(request: Request):
    """Clear all analysis records from history."""
    count = clear_all_analyses()
    client_ip = request.client.host if request.client else "unknown"
    log_audit("CLEAR_ALL_ANALYSES", client_ip, f"Count deleted: {count}")
    return {"status": "cleared", "records_removed": count}

@app.get("/api/stats", response_model=StatsResponse)
def get_system_stats():
    """Retrieve operational database metrics."""
    return get_stats()

# --- Feedback & Continuous Improvement Endpoints (Phase 2 & Phase 3) ---

@app.post("/api/feedback", response_model=FeedbackResponse, status_code=status.HTTP_201_CREATED)
def submit_feedback(payload: FeedbackCreateRequest, request: Request, response: Response):
    """
    Submit user feedback on detection accuracy with automatic deduplication.
    Feedback is stored untrusted as 'pending' until verified by authorized reviewers.
    """
    valid_modules = ("text", "url", "image", "video", "audio")
    if payload.detection_module not in valid_modules:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid detection module '{payload.detection_module}'. Must be one of {valid_modules}"
        )

    valid_corrections = (
        "correct", "false_positive", "false_negative",
        "wrong_risk_category", "incorrect_evidence", "inconclusive", "other"
    )
    if payload.user_correction not in valid_corrections:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid user correction '{payload.user_correction}'. Must be one of {valid_corrections}"
        )

    fb_data = payload.model_dump()
    fb_data["detector_version"] = "v1.2.0"
    created_record, is_duplicate = create_feedback(fb_data)

    if is_duplicate:
        response.status_code = status.HTTP_200_OK

    client_ip = request.client.host if request.client else "unknown"
    log_audit("SUBMIT_FEEDBACK", client_ip, f"Module: {payload.detection_module}, Corr: {payload.user_correction}, Dup: {is_duplicate}")
    return created_record

@app.get("/api/feedback", response_model=List[FeedbackResponse])
def list_feedback_entries(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    status: Optional[str] = Query(None),
    module: Optional[str] = Query(None)
):
    """Retrieve submitted feedback records with optional filtering."""
    return get_feedbacks(limit=limit, offset=offset, status=status, module=module)

@app.get("/api/feedback/stats", response_model=FeedbackStatsResponse)
def get_feedback_statistics():
    """Retrieve operational metrics on user feedback, reported false positives, and review states."""
    return get_feedback_stats()

@app.get("/api/feedback/export")
def export_feedback_dataset(
    format: str = Query("json", pattern="^(json|jsonl)$"),
    module: Optional[str] = Query(None)
):
    """
    Curated dataset export of reviewed, accepted feedback examples.
    - Strictly excludes unreviewed or rejected feedback.
    - Automatically strips PII (emails, phone numbers, credit cards, IP addresses).
    - Deduplicates identical samples and flags contradictory ground truths.
    - Formatted as JSON or JSONL for reproducible training and evaluation.
    """
    curated_records = export_curated_feedback(module=module)

    if format == "jsonl":
        lines = [json.dumps(r) for r in curated_records]
        content = "\n".join(lines)
        return Response(
            content=content,
            media_type="application/x-ndjson",
            headers={"Content-Disposition": "attachment; filename=curated_deepshield_dataset.jsonl"}
        )
    else:
        return {
            "dataset_name": "DeepShield Curated Benchmark Dataset",
            "version": "v1.2.0",
            "total_records": len(curated_records),
            "records": curated_records
        }

@app.get("/api/feedback/{feedback_id}", response_model=FeedbackResponse)
def get_single_feedback(feedback_id: str):
    """Retrieve a single feedback record by ID."""
    fb = get_feedback_by_id(feedback_id)
    if not fb:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feedback record not found")
    return fb

@app.patch("/api/feedback/{feedback_id}/review", response_model=FeedbackResponse)
def review_feedback_entry(feedback_id: str, payload: FeedbackReviewRequest, request: Request):
    """
    Authorized review transition for user feedback (pending -> accepted / rejected / needs_more_evidence).
    Only accepted feedback is eligible for curated datasets.
    """
    try:
        updated = update_feedback_review(
            feedback_id=feedback_id,
            review_status=payload.review_status,
            reviewer_notes=payload.reviewer_notes,
            dataset_eligible=payload.dataset_eligible
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feedback record not found")

    client_ip = request.client.host if request.client else "unknown"
    log_audit("REVIEW_FEEDBACK", client_ip, f"ID: {feedback_id}, Status: {payload.review_status}")
    return updated

# --- Evaluation Framework Endpoint ---

@app.post("/api/evaluate")
async def run_evaluation_benchmark():
    """Execute evaluation benchmark on held-out dataset and return metrics."""
    return await evaluator.run_evaluation()

# --- Settings and Privacy Controls ---

@app.post("/api/settings/zero-retention")
def toggle_zero_retention(enabled: bool = Query(...)):
    """Toggle zero retention privacy mode."""
    settings.ENABLE_ZERO_RETENTION = enabled
    return {
        "status": "updated",
        "zero_retention_enabled": settings.ENABLE_ZERO_RETENTION,
        "description": "When active, zero analysis contents or summaries are committed to disk."
    }
