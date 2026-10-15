from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class RiskLevel(str, Enum):
    LOW_RISK = "LOW_RISK"
    MEDIUM_RISK = "MEDIUM_RISK"
    HIGH_RISK = "HIGH_RISK"
    INCONCLUSIVE = "INCONCLUSIVE"

class ScamCategory(str, Enum):
    FINANCIAL_INVESTMENT = "Financial / Investment Scam"
    PHISHING_CREDENTIAL = "Phishing / Credential Harvesting"
    IMPERSONATION_AUTHORITY = "Authority / Executive Impersonation"
    URGENCY_EXTORTION = "Urgency / Threat / Blackmail"
    LOTTERY_PRIZE_CRYPTO = "Lottery / Prize / Crypto Giveaway"
    JOB_EMPLOYMENT = "Job / Employment / Task Scam"
    OTP_MFA_THEFT = "OTP / MFA Authentication Theft"
    ADVANCE_FEE_ROMANCE = "Advance Fee / Romance Scam"
    BENIGN = "Legitimate / Benign Communication"
    UNKNOWN = "Uncertain / Unclassified"

class EvidenceItem(BaseModel):
    title: str
    description: str
    severity: str = Field(description="high, medium, low, info")
    category: str
    snippet: Optional[str] = None
    metric_value: Optional[float] = None

# --- Text Analysis Schemas ---
class TextAnalysisRequest(BaseModel):
    text: str = Field(..., min_length=3, max_length=10000, description="Message text or script to inspect")
    sender_context: Optional[str] = Field(None, max_length=200, description="Optional declared sender or handle")
    channel: Optional[str] = Field("auto", description="sms, email, social, chat, voice_transcript")

class TextAnalysisResponse(BaseModel):
    id: str
    timestamp: str
    risk_level: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    scam_category: ScamCategory
    primary_reason: str
    detailed_reasons: List[str] = Field(default_factory=list)
    detected_entities: List[str] = Field(default_factory=list)
    highlighted_tokens: List[str] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    model_attribution: str

    # Standardized Shared Result Contract Fields
    analysis_id: Optional[str] = None
    input_type: str = "text"
    overall_status: str = "Completed" # Completed, Local only, Partial, Failed
    summary: Optional[str] = None
    indicators: List[str] = Field(default_factory=list)
    supporting_evidence: List[EvidenceItem] = Field(default_factory=list)
    alternative_explanations: List[str] = Field(default_factory=list)
    uncertainties: List[str] = Field(default_factory=list)
    local_stage_status: str = "completed" # completed, failed, unavailable, timeout
    gemini_stage_status: str = "not_run_cloud_disabled" # completed, not_run_cloud_disabled, not_run_server_disabled, not_run_local_failed, failed, timeout
    created_at: Optional[str] = None
    local_model_name: Optional[str] = None
    gemini_model_name: Optional[str] = None


# --- URL Analysis Schemas ---
class URLAnalysisRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048, description="URL or domain to analyze")
    check_threat_intel: bool = True

class URLAnalysisResponse(BaseModel):
    id: str
    timestamp: str
    url: str
    normalized_url: str
    risk_level: RiskLevel
    confidence: float
    is_ip_address: bool
    has_homoglyphs: bool
    homoglyph_details: List[str]
    suspicious_tokens: List[str]
    domain_entropy: float
    structure: Dict[str, Any]
    threat_intel_result: Dict[str, Any]
    evidence: List[EvidenceItem]
    recommended_actions: List[str]
    limitations: List[str]

    # Standardized Shared Result Contract Fields
    analysis_id: Optional[str] = None
    input_type: str = "url"
    overall_status: str = "Completed"
    detector_attribution: str = "DeepShield URL Forensics Engine v1.2"


# --- Media Analysis Schemas ---
class ImageAnalysisResponse(BaseModel):
    id: str
    timestamp: str
    filename: str
    filesize: int
    format: str
    dimensions: List[int]
    risk_level: RiskLevel
    confidence: float
    ela_score: float
    noise_inconsistency: float
    fft_frequency_anomaly: float
    metadata_summary: Dict[str, Any]
    exif_tampering_clues: List[str]
    evidence: List[EvidenceItem]
    recommended_actions: List[str]
    limitations: List[str]
    annotated_heatmap_base64: Optional[str] = None

    # Modular and structured extension fields
    analysis_id: Optional[str] = None
    input_type: str = "image"
    overall_status: str = "completed"
    analysis_status: str = "completed"
    scam_content_risk: Optional[RiskLevel] = None
    synthetic_media_risk: Optional[RiskLevel] = None
    ocr_status: str = "unavailable"
    ocr_extracted_text: Optional[str] = None
    qr_codes_detected: List[str] = []
    detector_attribution: str = "DeepShield Multimodal & Forensic Pipeline v1.2"
    deepfake_detector_status: str = "Heuristic Forensics (ELA/FFT/Noise) - Neural Deepfake Model Unconfigured"


class VideoFrameMetric(BaseModel):
    frame_index: int
    timestamp_sec: float
    anomaly_score: float
    is_anomaly: bool
    notes: Optional[str] = None

class VideoAnalysisResponse(BaseModel):
    id: str
    timestamp: str
    filename: str
    duration_seconds: float
    total_frames_sampled: int
    risk_level: RiskLevel
    confidence: float
    temporal_inconsistency_score: float
    frame_timeline: List[VideoFrameMetric]
    evidence: List[EvidenceItem]
    recommended_actions: List[str]
    limitations: List[str]

    # Standardized Shared Result Contract Fields
    analysis_id: Optional[str] = None
    input_type: str = "video"
    overall_status: str = "Completed"
    media_authenticity_risk: Optional[RiskLevel] = None
    content_intent_risk: Optional[RiskLevel] = None
    deepfake_detector_status: str = "Heuristic Forensics (Laplacian Edge Variance & Temporal Jitter) - Specialized Neural Weights Unconfigured"
    detector_attribution: str = "DeepShield Video Forensic Engine v1.2"


class AudioAnalysisResponse(BaseModel):
    id: str
    timestamp: str
    filename: str
    duration_seconds: float
    sample_rate: int
    risk_level: RiskLevel
    confidence: float
    pitch_jitter: float
    spectral_rolloff_anomaly: float
    silence_ratio: float
    voice_clone_likelihood: str
    evidence: List[EvidenceItem]
    recommended_actions: List[str]
    limitations: List[str]

    # Standardized Shared Result Contract Fields
    analysis_id: Optional[str] = None
    input_type: str = "audio"
    overall_status: str = "Completed"
    media_authenticity_risk: Optional[RiskLevel] = None
    content_intent_risk: Optional[RiskLevel] = None
    deepfake_detector_status: str = "Heuristic Acoustic Forensics (Pitch Jitter & Spectral Rolloff) - Neural Deepfake Weights Unconfigured"
    detector_attribution: str = "DeepShield Audio Forensics Engine v1.2"


# --- Persistent Feedback Schemas ---
class FeedbackCreateRequest(BaseModel):
    analysis_id: Optional[str] = Field(None, max_length=64, description="ID of analyzed entity if applicable")
    detection_module: str = Field(..., description="text, url, image, video, audio")
    predicted_verdict: Optional[str] = Field(None, max_length=32, description="SCAM, BENIGN, INCONCLUSIVE")
    predicted_risk_level: Optional[RiskLevel] = None
    user_correction: str = Field(
        ...,
        description="correct, false_positive, false_negative, wrong_risk_category, incorrect_evidence, inconclusive, other"
    )
    corrected_risk_level: Optional[RiskLevel] = None
    explanation: Optional[str] = Field(None, max_length=1000, description="Optional user commentary")
    target_content: Optional[str] = Field(None, max_length=500, description="Sanitized excerpt or identifier")

class FeedbackReviewRequest(BaseModel):
    review_status: str = Field(..., description="pending, accepted, rejected, needs_more_evidence")
    reviewer_notes: Optional[str] = Field(None, max_length=1000)
    dataset_eligible: Optional[bool] = None

class FeedbackResponse(BaseModel):
    id: str
    analysis_id: Optional[str] = None
    detection_module: str
    predicted_verdict: Optional[str] = None
    predicted_risk_level: Optional[str] = None
    user_correction: str
    corrected_risk_level: Optional[str] = None
    explanation: Optional[str] = None
    feedback_source: str = "user_web"
    review_status: str = "pending" # pending, accepted, rejected, needs_more_evidence
    reviewer_notes: Optional[str] = None
    detector_version: str = "v1.2.0"
    dataset_eligible: bool = False
    created_at: str
    updated_at: str

class FeedbackStatsResponse(BaseModel):
    total_feedback: int
    by_module: Dict[str, int]
    by_status: Dict[str, int]
    by_correction: Dict[str, int]
    false_positives_count: int
    false_negatives_count: int
    dataset_eligible_count: int
    active_detector_version: str


# --- Management & Stats Schemas ---
class AnalysisRecordSummary(BaseModel):
    id: str
    timestamp: str
    analysis_type: str # text, url, image, video, audio
    target_summary: str
    risk_level: RiskLevel
    confidence: float
    category_or_detail: str

class SystemCapabilitiesResponse(BaseModel):
    app_name: str
    version: str
    environment: str
    text_detector: Dict[str, Any]
    url_detector: Dict[str, Any]
    image_detector: Dict[str, Any]
    video_detector: Dict[str, Any]
    audio_detector: Dict[str, Any]
    threat_intel_status: Dict[str, Any]
    security_safeguards: List[str]

class StatsResponse(BaseModel):
    total_analyses: int
    by_type: Dict[str, int]
    by_risk: Dict[str, int]
    high_risk_count: int
    last_analysis_timestamp: Optional[str] = None

class CloudAnalysisSettingsResponse(BaseModel):
    user_enabled: bool
    server_allowed: bool
    effective_enabled: bool
    description: str

class CloudAnalysisSettingsUpdate(BaseModel):
    enabled: bool

class LLMStatusResponse(BaseModel):
    ollama: Dict[str, Any]
    gemini: Dict[str, Any]
    cloud_analysis_policy: Dict[str, Any]
    pipeline_ready: bool
