export type RiskLevel = 'LOW_RISK' | 'MEDIUM_RISK' | 'HIGH_RISK' | 'INCONCLUSIVE';

export interface EvidenceItem {
  title: string;
  description: string;
  severity: 'high' | 'medium' | 'low' | 'info';
  category: string;
  snippet?: string;
  metric_value?: number;
}

export interface TextAnalysisResponse {
  id: string;
  timestamp: string;
  risk_level: RiskLevel;
  confidence: number;
  scam_category: string;
  primary_reason: string;
  detailed_reasons: string[];
  detected_entities: string[];
  highlighted_tokens: string[];
  evidence: EvidenceItem[];
  recommended_actions: string[];
  limitations: string[];
  model_attribution: string;

  // Section 8 Standardized Result Fields
  analysis_id?: string;
  input_type?: string;
  overall_status?: string;
  summary?: string;
  indicators?: string[];
  supporting_evidence?: EvidenceItem[];
  alternative_explanations?: string[];
  uncertainties?: string[];
  local_stage_status?: string;
  gemini_stage_status?: string;
  created_at?: string;
  local_model_name?: string | null;
  gemini_model_name?: string | null;
}

export interface CloudAnalysisSettingsResponse {
  user_enabled: boolean;
  server_allowed: boolean;
  effective_enabled: boolean;
  description: string;
}

export interface LLMStatusResponse {
  ollama: {
    status: string;
    base_url: string;
    target_model: string;
    target_model_installed?: boolean;
    available_models?: string[];
    error?: string;
    instruction?: string;
  };
  gemini: {
    api_key_configured: boolean;
    configured_model: string;
    timeout_seconds: number;
    max_output_tokens: number;
    server_allowed: boolean;
  };
  cloud_analysis_policy: {
    user_enabled: boolean;
    server_allowed: boolean;
    effective_enabled: boolean;
    description: string;
  };
  pipeline_ready: boolean;
}

export interface URLAnalysisResponse {
  id: string;
  timestamp: string;
  url: string;
  normalized_url: string;
  risk_level: RiskLevel;
  confidence: number;
  is_ip_address: boolean;
  has_homoglyphs: boolean;
  homoglyph_details: string[];
  suspicious_tokens: string[];
  domain_entropy: number;
  structure: {
    scheme: string;
    domain: string;
    subdomains: string[];
    tld: string;
    path: string;
    query_params_count: number;
    has_port: boolean;
    raw_ip: boolean;
  };
  threat_intel_result: {
    is_flagged: boolean;
    threat_type: string | null;
    sources_consulted: string[];
    verdict: string;
    provider_attribution: string;
  };
  evidence: EvidenceItem[];
  recommended_actions: string[];
  limitations: string[];
}

export interface ImageAnalysisResponse {
  id: string;
  timestamp: string;
  filename: string;
  filesize: number;
  format: string;
  dimensions: [number, number];
  risk_level: RiskLevel;
  confidence: number;
  ela_score: number;
  noise_inconsistency: number;
  fft_frequency_anomaly: number;
  metadata_summary: Record<string, any>;
  exif_tampering_clues: string[];
  evidence: EvidenceItem[];
  recommended_actions: string[];
  limitations: string[];
  annotated_heatmap_base64?: string;
  analysis_status?: string;
  scam_content_risk?: RiskLevel;
  synthetic_media_risk?: RiskLevel;
  ocr_status?: string;
  ocr_extracted_text?: string;
  qr_codes_detected?: string[];
  detector_attribution?: string;
  deepfake_detector_status?: string;
  analysis_id?: string;
}

export interface VideoFrameMetric {
  frame_index: number;
  timestamp_sec: number;
  anomaly_score: number;
  is_anomaly: boolean;
  notes?: string;
}

export interface VideoAnalysisResponse {
  id: string;
  analysis_id?: string;
  timestamp: string;
  filename: string;
  duration_seconds: number;
  total_frames_sampled: number;
  risk_level: RiskLevel;
  confidence: number;
  temporal_inconsistency_score: number;
  frame_timeline: VideoFrameMetric[];
  evidence: EvidenceItem[];
  recommended_actions: string[];
  limitations: string[];
}

export interface AudioAnalysisResponse {
  id: string;
  analysis_id?: string;
  timestamp: string;
  filename: string;
  duration_seconds: number;
  sample_rate: number;
  risk_level: RiskLevel;
  confidence: number;
  pitch_jitter: number;
  spectral_rolloff_anomaly: number;
  silence_ratio: number;
  voice_clone_likelihood: string;
  evidence: EvidenceItem[];
  recommended_actions: string[];
  limitations: string[];
}

export interface AnalysisRecordSummary {
  id: string;
  timestamp: string;
  analysis_type: 'text' | 'url' | 'image' | 'video' | 'audio';
  target_summary: string;
  risk_level: RiskLevel;
  confidence: number;
  category_or_detail: string;
}

export interface SystemCapabilitiesResponse {
  app_name: string;
  version: string;
  environment: string;
  text_detector: Record<string, any>;
  url_detector: Record<string, any>;
  image_detector: Record<string, any>;
  video_detector: Record<string, any>;
  audio_detector: Record<string, any>;
  threat_intel_status: Record<string, any>;
  security_safeguards: string[];
}

export interface StatsResponse {
  total_analyses: number;
  by_type: Record<string, number>;
  by_risk: Record<string, number>;
  high_risk_count: number;
  last_analysis_timestamp: string | null;
}

export interface BenchmarkItemResult {
  type: string;
  input_snippet: string;
  ground_truth: string;
  predicted: string;
  confidence: number;
  category: string;
  outcome: string;
}

export interface EvaluationResponse {
  dataset_info: {
    name: string;
    sample_count: number;
    data_leakage_safeguard: string;
  };
  confusion_matrix: {
    true_positives: number;
    false_positives: number;
    true_negatives: number;
    false_negatives: number;
  };
  metrics: {
    accuracy: number;
    precision: number;
    recall: number;
    false_positive_rate: number;
    f1_score: number;
  };
  eval_results: BenchmarkItemResult[];
  observations: string[];
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  environment: string;
  zero_retention_mode: boolean;
  storage: string;
  backend?: {
    status: string;
    host: string;
    port: number;
  };
  ollama?: {
    status: string;
    target_model: string;
    target_model_installed: boolean;
  };
  gemini?: {
    api_key_configured: boolean;
    configured_model: string;
    server_allowed: boolean;
  };
  tunnel?: {
    status: string;
    public_url: string | null;
  };
}

export interface TunnelStatusResponse {
  status: string;
  public_url: string | null;
  proto?: string;
  target_addr?: string;
  name?: string;
  persistent_domain_configured?: boolean;
  message?: string;
}

export interface FeedbackCreateRequest {
  analysis_id?: string;
  detection_module: 'text' | 'url' | 'image' | 'video' | 'audio';
  predicted_verdict?: string;
  predicted_risk_level?: RiskLevel;
  user_correction: 'correct' | 'false_positive' | 'false_negative' | 'wrong_risk_category' | 'incorrect_evidence' | 'inconclusive' | 'other';
  corrected_risk_level?: RiskLevel;
  explanation?: string;
  target_content?: string;
}

export interface FeedbackResponse {
  id: string;
  analysis_id?: string;
  detection_module: string;
  predicted_verdict?: string;
  predicted_risk_level?: string;
  user_correction: string;
  corrected_risk_level?: string;
  explanation?: string;
  feedback_source: string;
  review_status: 'pending' | 'accepted' | 'rejected' | 'needs_more_evidence';
  reviewer_notes?: string;
  detector_version: string;
  dataset_eligible: boolean;
  created_at: string;
  updated_at: string;
}

export interface FeedbackStatsResponse {
  total_feedback: number;
  by_module: Record<string, number>;
  by_status: Record<string, number>;
  by_correction: Record<string, number>;
  false_positives_count: number;
  false_negatives_count: number;
  dataset_eligible_count: number;
  active_detector_version: string;
}

