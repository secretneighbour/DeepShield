import type {
  TextAnalysisResponse,
  URLAnalysisResponse,
  ImageAnalysisResponse,
  VideoAnalysisResponse,
  AudioAnalysisResponse,
  AnalysisRecordSummary,
  SystemCapabilitiesResponse,
  StatsResponse,
  EvaluationResponse,
  HealthResponse,
  TunnelStatusResponse,
} from './types';

const API_BASE = '/api';

export async function fetchCapabilities(): Promise<SystemCapabilitiesResponse> {
  const res = await fetch(`${API_BASE}/capabilities`);
  if (!res.ok) throw new Error(`Capabilities error: ${res.statusText}`);
  return res.json();
}

export async function fetchStats(): Promise<StatsResponse> {
  const res = await fetch(`${API_BASE}/stats`);
  if (!res.ok) throw new Error(`Stats error: ${res.statusText}`);
  return res.json();
}

export async function analyzeText(
  text: string,
  senderContext?: string,
  channel: string = 'auto'
): Promise<TextAnalysisResponse> {
  const res = await fetch(`${API_BASE}/analyze/text`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      text,
      sender_context: senderContext || null,
      channel,
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Text analysis failed');
  }
  return res.json();
}

export async function analyzeUrl(
  url: string,
  checkThreatIntel: boolean = true
): Promise<URLAnalysisResponse> {
  const res = await fetch(`${API_BASE}/analyze/url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      url,
      check_threat_intel: checkThreatIntel,
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'URL analysis failed');
  }
  return res.json();
}

export async function analyzeImage(file: File): Promise<ImageAnalysisResponse> {
  const formData = new FormData();
  formData.append('file', file);
  const res = await fetch(`${API_BASE}/analyze/image`, {
    method: 'POST',
    body: formData,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Image analysis failed');
  }
  return res.json();
}

export async function analyzeVideo(file: File): Promise<VideoAnalysisResponse> {
  const formData = new FormData();
  formData.append('file', file);
  const res = await fetch(`${API_BASE}/analyze/video`, {
    method: 'POST',
    body: formData,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Video analysis failed');
  }
  return res.json();
}

export async function analyzeAudio(
  file: File,
  transcript?: string
): Promise<AudioAnalysisResponse> {
  const formData = new FormData();
  formData.append('file', file);
  if (transcript && transcript.trim()) {
    formData.append('transcript', transcript.trim());
  }
  const res = await fetch(`${API_BASE}/analyze/audio`, {
    method: 'POST',
    body: formData,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Audio analysis failed');
  }
  return res.json();
}

export async function fetchAnalyses(limit = 50, offset = 0): Promise<{ records: AnalysisRecordSummary[] }> {
  const res = await fetch(`${API_BASE}/analyses?limit=${limit}&offset=${offset}`);
  if (!res.ok) throw new Error(`Analyses list error: ${res.statusText}`);
  return res.json();
}

export async function fetchAnalysisDetail(id: string): Promise<any> {
  const res = await fetch(`${API_BASE}/analyses/${id}`);
  if (!res.ok) throw new Error(`Detail error: ${res.statusText}`);
  return res.json();
}

export async function deleteAnalysis(id: string): Promise<void> {
  const res = await fetch(`${API_BASE}/analyses/${id}`, { method: 'DELETE' });
  if (!res.ok) throw new Error(`Delete error: ${res.statusText}`);
}

export async function clearAllAnalyses(): Promise<void> {
  const res = await fetch(`${API_BASE}/analyses`, { method: 'DELETE' });
  if (!res.ok) throw new Error(`Clear error: ${res.statusText}`);
}

export async function runEvaluation(): Promise<EvaluationResponse> {
  const res = await fetch(`${API_BASE}/evaluate`, { method: 'POST' });
  if (!res.ok) throw new Error(`Evaluation failed: ${res.statusText}`);
  return res.json();
}

export async function toggleZeroRetention(enabled: boolean): Promise<any> {
  const res = await fetch(`${API_BASE}/settings/zero-retention?enabled=${enabled}`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error(`Settings update failed: ${res.statusText}`);
  return res.json();
}

export async function fetchLLMStatus(): Promise<any> {
  const res = await fetch(`${API_BASE}/llm/status`);
  if (!res.ok) throw new Error(`LLM status error: ${res.statusText}`);
  return res.json();
}

export async function fetchCloudAnalysisSetting(): Promise<any> {
  const res = await fetch(`${API_BASE}/settings/cloud-analysis`);
  if (!res.ok) throw new Error(`Cloud settings error: ${res.statusText}`);
  return res.json();
}

export async function updateCloudAnalysisSetting(enabled: boolean): Promise<any> {
  const res = await fetch(`${API_BASE}/settings/cloud-analysis`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ enabled }),
  });
  if (!res.ok) throw new Error(`Cloud settings update failed: ${res.statusText}`);
  return res.json();
}

export async function fetchHealth(): Promise<HealthResponse> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error(`Health check failed: ${res.statusText}`);
  return res.json();
}

export async function fetchTunnelStatus(): Promise<TunnelStatusResponse> {
  const res = await fetch(`${API_BASE}/tunnel/status`);
  if (!res.ok) throw new Error(`Tunnel status check failed: ${res.statusText}`);
  return res.json();
}

export async function submitFeedback(payload: import('./types').FeedbackCreateRequest): Promise<import('./types').FeedbackResponse> {
  const res = await fetch(`${API_BASE}/feedback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Feedback submission failed');
  }
  return res.json();
}

export async function fetchFeedbackStats(): Promise<import('./types').FeedbackStatsResponse> {
  const res = await fetch(`${API_BASE}/feedback/stats`);
  if (!res.ok) throw new Error(`Feedback stats error: ${res.statusText}`);
  return res.json();
}

export async function fetchFeedbacks(
  limit = 50,
  offset = 0,
  status?: string,
  module?: string
): Promise<import('./types').FeedbackResponse[]> {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (status) params.append('status', status);
  if (module) params.append('module', module);
  const res = await fetch(`${API_BASE}/feedback?${params.toString()}`);
  if (!res.ok) throw new Error(`Feedback list error: ${res.statusText}`);
  return res.json();
}

export async function reviewFeedback(
  feedbackId: string,
  reviewStatus: 'pending' | 'accepted' | 'rejected' | 'needs_more_evidence',
  reviewerNotes?: string,
  datasetEligible?: boolean
): Promise<import('./types').FeedbackResponse> {
  const res = await fetch(`${API_BASE}/feedback/${feedbackId}/review`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      review_status: reviewStatus,
      reviewer_notes: reviewerNotes || null,
      dataset_eligible: datasetEligible,
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Feedback review failed');
  }
  return res.json();
}


