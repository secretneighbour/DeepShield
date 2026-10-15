# DeepShield — Autonomous Threat Intelligence & Deepfake Forensics
### *See Beyond the Surface. Detect Deception.*
## Production-Grade Digital Safety, Two-Stage LLM Pipeline, Synthetic Media Forensics & ASUS-Inspired UI

**DeepShield** is an enterprise-grade digital safety and forensic analysis platform designed to detect social engineering scams, credential harvesting, phishing URLs, synthetic voice cloning, and manipulated deepfake media.

---

## 1. System Architecture Overview (Laptop-Hosted via ngrok)

```
                                  [ User Client / Browser ]
                                              │
                       ┌──────────────────────┴──────────────────────┐
                       ▼                                             ▼
          [ ASUS-Inspired Luxury Landing ]             [ Forensic Command Center ]
               Route: / (Cinematic)                       Route: /dashboard
                       │                                             │
                       └──────────────────────┬──────────────────────┘
                                              ▼
                             [ React + Vite + Tailwind CSS ]
                                              │ REST API
                                              ▼
                             [ FastAPI Security Core (8000) ]
                                              │
          ┌───────────────────┬───────────────┴───────────────┬───────────────────┐
          ▼                   ▼                               ▼                   ▼
    [ Media Forensics ] [ Phishing / SSRF ]         [ Database & Cache ]    [ Two-Stage LLM Pipeline ]
    • Image (ELA/FFT)   • Homoglyphs/Entropy        • SQLite WAL Engine     • Stage 1: Local Ollama
    • Video (Jitter)    • RFC-1918 Blocking         • Zero-Retention Memory   (Gemma 3 4B)
    • Audio (Jitter)    • Threat Intel Feeds        • Persistent Settings   • Stage 2: Google Gemini
                                                                              (Cloud Reviewer)
```

---

## 2. Key Implemented Capabilities

### 🧠 Mandatory Two-Stage LLM Pipeline (Text Forensics)
- **Strict Sequencing Enforcement:**
  1. **Stage 1 (Local LLM Candidate):** Executes Ollama locally (`gemma3:4b` at `http://127.0.0.1:11434`). Extracts urgency coercion, authority impersonation, financial/credential theft, and alternative interpretations. If Ollama is offline or uninstalled, gracefully falls back to the local calibrated heuristic classifier (`deepshield-local-baseline-v1`) without crashing or fabricating Ollama execution.
  2. **Stage 2 (Google Gemini Reviewer):** Only after the local model succeeds, the original text and structured local findings are dispatched to Google Gemini (`gemini-2.5-flash` via official `google-genai` SDK). Gemini critically audits the findings, identifies missed nuances, considers legitimate explanations, and produces actionable security advice.
- **Evidence Span Hallucination Protection:** The backend validates all model-generated snippets against verbatim substrings in the user-submitted text, stripping or flagging hallucinated quotes.
- **User-Controlled Cloud Privacy Gate:**
  - Persisted setting: *"Enable Gemini cloud analysis"*.
  - When disabled, Gemini review is completely skipped, payload is never sent off-device, and the stage status is recorded as `not_run_cloud_disabled` with overall status `Local only`.
  - Administrative server override (`LLM_CLOUD_ENABLED=false`) takes precedence over user preference.

### 🌐 Phishing & URL Inspector
- **Homoglyph & Punycode Detection:** Identifies IDN lookalike characters (e.g., Cyrillic `а` substituted for Latin `a`) used in brand impersonation attacks.
- **Lexical Structure & Shannon Entropy:** Computes domain entropy to detect randomly generated algorithmically registered domains (DGA).
- **SSRF Defense:** Strict socket and IP validation blocking access to RFC-1918 private subnets, loopback interfaces (`127.0.0.1`), and cloud metadata endpoints (`169.254.169.254`).
- **Threat Intelligence Integration:** Local zero-latency curated threat database with adapters for Google Safe Browsing and VirusTotal APIs.

### 🖼️ Image Deepfake & Manipulation Analyzer
- **Error Level Analysis (ELA):** Computes compression error matrices and generates visual heatmaps highlighting spliced or in-painted regions.
- **2D Fast Fourier Transform (FFT):** Detects high-frequency periodic grid artifacts characteristic of generative diffusion decoders and GAN upsampling.
- **Spatial Noise Inconsistency:** Evaluates high-pass Laplacian noise variance across image quadrants to detect composites.
- **EXIF Forensics:** Scans image metadata for generative AI signatures (Midjourney, Stable Diffusion, Photoshop) and camera hardware anomalies.

### 🎬 Video Deepfake & Temporal Consistency Analyzer
- **Controlled Frame Sampling:** Extracts and analyzes frames at safe intervals without unbounded memory overhead.
- **Temporal Jitter & Inter-Frame Inconsistency:** Computes temporal variance between adjacent frames to detect facial boundary flickering and warping.
- **Frame-by-Frame Timeline:** Generates an interactive chart displaying per-second anomaly metrics.
- **Transparent Reporting:** Explicitly documents how many frames were sampled vs. skipped.

### 🎙️ Audio Authenticity & Voice Cloning Analyzer
- **Dual-Verdict Engine:**
  1. *Acoustic Authenticity:* Measures vocal pitch jitter (human baseline: 0.5%–2.0%; synthetic TTS: <0.3% rigidity) and vocoder frequency truncation (>7.5kHz cutoff).
  2. *Spoken Intent Forensics:* Evaluates transcripts for emergency wire scams or OTP theft.
- **Digital Zero Detection:** Flags unnatural mathematical zero-amplitude blocks common in synthesized audio.

### 📊 Forensics Audit Trail, Feedback Loop & Curated Dataset Pipeline
- **Database Backed:** SQLite with WAL mode (`journal_mode=WAL`) for high concurrency and audit history persistence.
- **Persistent User Feedback:** Users can submit contextual feedback across all 5 analyzers (Text, URL, Image, Video, Audio) covering false positives, false negatives, risk category adjustments, or insufficient evidence.
- **Feedback Deduplication & Protection:** Automatic 300-second client and server deduplication per analysis prevents spam and duplicate submissions.
- **Automated PII Redaction:** Automated sanitizer (`redact_sensitive_pii`) redacts emails, telephone numbers, credit card sequences, and IPv4 addresses before storage and export.
- **Strict Human-in-the-Loop Review:** User feedback is never automatically trusted as ground truth. Only feedback with `review_status = "accepted"` and `dataset_eligible = 1` is included in curated training datasets.
- **Curated Dataset Export:** Formatted JSON and JSONL export endpoints for reproducible downstream training and offline model evaluation splits.
- **Zero-Retention Mode:** Configurable toggle to execute all analyses strictly in-memory without persisting audit records or feedback to disk.
- **Held-Out Evaluation Framework:** Measures precision, recall, F1-score, and false-positive rates on an isolated benchmark without data leakage.

---

## 3. Web Application & Visual Design

- **Landing Page (`/`):** ASUS-inspired luxury dark technology design.
  - Headline: *"Trust what you see. Verify what you receive."*
  - Supporting copy: *"Analyze suspicious messages, investigate potentially dangerous links, and examine media for signs of manipulation with AI-assisted security analysis."*
  - Abstract animated radar security shield with dynamic layered rings and pulsing threat scan lines.
  - 3-Step Verification Protocol & 4-Quadrant Capability Grid.
  - Final CTA: *"Look closer. Question more. Verify better."*
- **Forensic Command Center (`/dashboard`):** Real-time threat telemetry, scan statistics, interactive feedback improvement telemetry card, direct JSONL dataset export buttons, and quick analysis launchers.
- **Dedicated Route Architecture:**
  - `/` — Public Introduction Page
  - `/dashboard` — Main Operations Command Center & Feedback Dataset Hub
  - `/analyze/text` — Two-Stage LLM Text Forensics & Contextual Feedback
  - `/analyze/url` — Phishing & URL Inspector with Feedback
  - `/analyze/image` — Spectral & ELA Image Forensics with Feedback
  - `/analyze/video` — Temporal Jitter Video Analysis with Feedback
  - `/analyze/audio` — Acoustic & Intent Voice Forensics with Feedback
  - `/history` — Forensic Audit Log
  - `/settings` — Cloud Privacy & LLM Diagnostic Center

---

## 4. Persistent Feedback System & Dataset Curation

### Database Schema (`feedbacks` Table)
The backend maintains a relational `feedbacks` table in SQLite (`scamshield.db`) with strict schema typing:

| Column | Type | Constraints / Default | Description |
|---|---|---|---|
| `id` | `TEXT` | `PRIMARY KEY` | Unique UUID v4 feedback identifier |
| `analysis_id` | `TEXT` | `NOT NULL` | Associated analysis record UUID |
| `detection_module` | `TEXT` | `NOT NULL` | Module name (`text`, `url`, `image`, `video`, `audio`) |
| `predicted_verdict` | `TEXT` | `NOT NULL` | Original system verdict (`scam`, `phishing`, `manipulated`, `safe`) |
| `predicted_risk_level` | `TEXT` | `NOT NULL` | Original risk category (`Low`, `Moderate`, `High`, `Critical`) |
| `user_correction` | `TEXT` | `NOT NULL` | User claim (`correct`, `false_positive`, `false_negative`, etc.) |
| `corrected_risk_level` | `TEXT` | `NULLABLE` | Optional user-suggested risk level |
| `explanation` | `TEXT` | `NULLABLE` | User commentary or rationale |
| `target_content` | `TEXT` | `NULLABLE` | PII-redacted analysis snippet or target URL/subject |
| `feedback_source` | `TEXT` | `DEFAULT 'user_web_ui'` | Source identifier |
| `review_status` | `TEXT` | `DEFAULT 'pending'` | Lifecycle state: `pending`, `accepted`, `rejected`, `needs_more_evidence` |
| `reviewer_notes` | `TEXT` | `NULLABLE` | Authorized reviewer audit remarks |
| `detector_version` | `TEXT` | `DEFAULT 'v1.2.0'` | Detector/pipeline version active during analysis |
| `dataset_eligible` | `INTEGER` | `DEFAULT 0` | Boolean flag (1=eligible for training/eval export, 0=ineligible) |
| `created_at` | `TIMESTAMP` | `DEFAULT CURRENT_TIMESTAMP` | Submission timestamp |
| `updated_at` | `TIMESTAMP` | `DEFAULT CURRENT_TIMESTAMP` | Last review update timestamp |

### Implemented Feedback REST Endpoints

1. **Submit Feedback:**
   `POST /api/feedback`
   - Payload: `FeedbackCreateRequest` (analysis ID, module, original verdict, user correction, explanation, optional target content).
   - Deduplication: Automatically detects repeated submissions within 300 seconds for the same analysis and returns the existing record.
   - PII Sanitization: Pre-filters submitted text for credit cards, emails, phone numbers, and IP addresses.

2. **Retrieve Feedback Telemetry:**
   `GET /api/feedback/stats`
   - Returns real-time aggregates: total feedbacks, distribution by module (`text`, `url`, `image`, etc.), user corrections (`false_positive`, `false_negative`, etc.), review lifecycle status counts (`pending`, `accepted`, `rejected`), and active detector version (`v1.2.0`).

3. **Query Feedback Records:**
   `GET /api/feedback?status={status}&module={module}&limit=50&offset=0`
   - Paginated endpoint allowing security reviewers to audit submitted claims.

4. **Reviewer State Transitions:**
   `PATCH /api/feedback/{feedback_id}/review`
   - Payload: `review_status` (`accepted`, `rejected`, `needs_more_evidence`), `reviewer_notes`, `dataset_eligible` (bool).
   - Enforces human-in-the-loop review before any submission is promoted to training eligibility.

5. **Curated Dataset Export:**
   `GET /api/feedback/export?format=jsonl` or `?format=json`
   - Streams strictly approved (`review_status='accepted'` and `dataset_eligible=1`) examples.
   - Automatically re-sanitizes PII, applies structural formatting, and outputs training-ready evaluation pairs.

---

## 5. Detector Versioning, Regression Testing & Local Learning Roadmap

### Active Version: `v1.2.0`
The detection pipeline enforces strict semantic versioning (`v1.2.0`) across all modules:
- **Context-Aware Text Forensics:** Replaced naïve keyword matching with context-paired rules (e.g. authority impersonation combined with coercive threat; executive authority paired with gift card purchase).
- **Negation Defense:** Preceding token analysis specifically differentiates defensive security warnings (*"Do NOT share this one-time code with anyone"*) from genuine credential theft, preventing false positives.
- **Authenticity vs. Intent Separation:** Decoupled media manipulation detection from spoken/textual intent in audio and video modules.

### Local Model Fine-Tuning Feasibility Assessment
- **Hardware Audit:**
  - Host Processor: Intel Core i5-7200U (2 physical cores / 4 threads @ 2.50GHz)
  - Memory: 15 GB DDR4 (~6.7 GB available)
  - GPU Acceleration: None (Integrated Intel HD Graphics 620, no CUDA support)
- **Feasibility Finding:**
  Fine-tuning 4B+ parameter models (such as `gemma3:4b`) directly on a dual-core mobile CPU is technically infeasible. Attempting LoRA backpropagation on CPU would cause severe thrashing, thread exhaustion, and system-level OOM crashes.
- **Production Improvement Strategy:**
  1. **Immediate Improvement via Feedback-Derived Rules:** Approved false-positive and false-negative submissions are immediately codified into deterministic regression test fixtures (`test_feedback.py`).
  2. **Prompt & Context Calibration:** Identified edge cases are integrated into few-shot system context templates for Ollama and Gemini review without modifying model weights.
  3. **Export for Dedicated GPU Fine-Tuning:** The `GET /api/feedback/export?format=jsonl` endpoint prepares curated, PII-sanitized instruction-tuning datasets ready for LoRA fine-tuning on external GPU infrastructure (NVIDIA A10G / H100) using frameworks like Unsloth or Axolotl.
  4. **Strict Rollback Guarantee:** Configuration and heuristic versions are tracked (`v1.2.0`), allowing instant rollback to earlier baseline rule engines if performance degrades.

---

## 6. Linux Setup, Installation & Startup Guide

### Prerequisites
- Linux OS (Ubuntu, Debian, Fedora, Arch Linux, etc.)
- Python 3.11+
- Node.js 18+ & npm
- [Ollama](https://ollama.com/)
- [ngrok](https://ngrok.com/download)

### 1. Initial Setup & Environment Configuration
```bash
# 1. Copy environment template to .env
cp .env.example .env

# 2. (Optional) Edit .env with your preferences:
# - GEMINI_API_KEY: for Stage 2 cloud review (stored server-side only)
# - NGROK_DOMAIN: if you have a persistent reserved domain (e.g. your-subdomain.ngrok-free.app)
# - BACKEND_API_KEY: if you require API authentication
```

### 2. Single-Command Launch (All Services)
Launch all components (FastAPI backend, Vite frontend & reverse proxy, Ollama daemon with Gemma 3 4B, and ngrok public tunnel) using the master startup script:

```bash
# Launch in foreground (press Ctrl+C to stop all services)
./start_all.sh

# OR launch in daemon mode to keep running in background:
./start_all.sh --daemon
```

When started, `start_all.sh` automatically:
1. Validates local tools and virtual environment.
2. Checks that the Ollama daemon is running on `127.0.0.1:11434` and verifies `gemma3:4b` is present.
3. Launches the FastAPI Security Core on `127.0.0.1:8000`.
4. Launches the React/Vite frontend on `0.0.0.0:5173` with reverse proxying for `/api/*`.
5. Starts the ngrok HTTPS tunnel targeting port `5173`.
6. Discovers the public HTTPS URL from ngrok's local inspection API and prints the complete telemetry banner.

### 3. Individual Service Scripts
If you prefer running components in dedicated terminal tabs:
```bash
# Tab 1: Local Ollama & Gemma 3 4B (127.0.0.1:11434)
./run_ollama.sh

# Tab 2: FastAPI Backend Core (127.0.0.1:8000)
./run_backend.sh

# Tab 3: Vite Frontend & Local Reverse Proxy (0.0.0.0:5173)
./run_frontend.sh

# Tab 4: ngrok Public Tunnel
./run_ngrok.sh
```

### 4. How to Obtain the Public URL
The public HTTPS URL can be obtained at any time via:
- The startup output banner of `./start_all.sh` or `./run_ngrok.sh`
- Querying the local backend tunnel endpoint:
  ```bash
  curl -s http://127.0.0.1:8000/api/tunnel/status | jq .
  ```
- Directly querying the local ngrok inspection API:
  ```bash
  curl -s http://127.0.0.1:4040/api/tunnels | jq -r '.tunnels[0].public_url'
  ```
- Directly in the web interface top navigation header and Settings page.

### 5. How to Safely Stop All Services
To cleanly terminate the backend, frontend, and ngrok tunnel without leaving orphaned port listeners:
```bash
./stop_all.sh
```

---

## 7. Automated Test Suite

Run the full automated test suite:
```bash
PYTHONPATH=backend ./venv/bin/pytest backend/tests/ -v
```

All **49 automated test suites** pass cleanly:
- **Core Pipeline & Endpoints (`test_all.py` — 19 tests):**
  - `test_health_endpoint`: Operational status and SQLite engine check.
  - `test_capabilities_endpoint`: Text, URL, Image, Video, Audio capabilities report.
  - `test_text_scam_detector_phishing`: High-risk phishing detection and scoring via local LLM.
  - `test_text_scam_detector_benign`: Benign communication non-flagging.
  - `test_url_ssrf_protection`: Blocks loopback (`127.0.0.1`), AWS metadata (`169.254.169.254`), and private subnets.
  - `test_url_detector_homoglyph_and_brand_spoof`: Flags Cyrillic homoglyphs and typosquatting.
  - `test_url_detector_benign`: Legitimate domain verification.
  - `test_file_signature_validation_rejection`: Rejects disguised file extensions without matching magic bytes.
  - `test_image_detector_synthetic_and_tampering`: ELA heatmap, Laplacian noise, and FFT frequency tests.
  - `test_audio_detector_valid_and_transcription`: Acoustic pitch jitter, zero-run detection, and spoken intent.
  - `test_evaluation_framework_endpoint`: Held-out dataset benchmark calculations.
  - `test_database_crud_and_zero_retention`: SQLite persistence and zero-retention ephemeral mode.
  - `test_cloud_settings_persistence_and_status`: Settings table persistence and `/api/settings/cloud-analysis` endpoints.
  - `test_two_stage_pipeline_sequencing_and_cloud_disabled`: Local model runs first, Gemini called second, Gemini skipped when cloud disabled (`gemini_stage_status = not_run_cloud_disabled`).
  - `test_two_stage_pipeline_admin_override`: Server administrative flag (`LLM_CLOUD_ENABLED=false`) overrides user toggle.
  - `test_evidence_validation_rejects_hallucinations`: Strips and flags hallucinated quotes not present in submitted text.
  - `test_tunnel_status_endpoint`: Live ngrok tunnel inspection without exposing secrets.
  - `test_enriched_health_subsystems`: Subsystem health reporting for backend, Ollama, Gemini, and tunnel.
  - `test_backend_authentication_middleware`: Rate limiting, X-API-Key and Bearer authorization verification.
- **Feedback Loop & Dataset Curation (`test_feedback.py` — 13 tests):**
  - Context scam regressions: legitimate police notices, congratulations, executive announcements, and defensive OTP warnings.
  - Adversarial context scams: CEO gift card solicitations, arrest warrant extortion.
  - Feedback lifecycle: submission validation, 300s deduplication, invalid module rejection, and review state transitions.
  - PII redaction: regex sanitization of phone numbers, emails, credit cards, and IPs.
  - Curated export: strict filtering for accepted, dataset-eligible records in JSON and JSONL formats.
  - Feedback stats telemetry endpoint verification.
- **Detection Refinements & Edge Cases (`test_refinements.py` — 17 tests):**
  - URL compound TLD parsing, lookalike domains, deceptive subdomains, userinfo delimiter spoofing, homoglyph punycode, and nested redirects.
  - Safe handling of raw IPs and unconfigured threat intelligence feeds.
  - Image binary signature guards, oversized memory limits, corrupted stream recovery, and separation of screenshot OCR text from synthetic media authenticity.
  - Bounded API response times preventing hanging connections.

---

## 8. Security Guarantees & Safeguards

1. **Ollama Isolation:** Ollama runs strictly on local loopback `127.0.0.1:11434`. Its port is never exposed to ngrok or the internet.
2. **Reverse Proxy Architecture:** Ngrok terminates HTTPS and forwards to the local reverse proxy on port 5173. The proxy serves the frontend SPA and routes same-origin `/api/*` calls to FastAPI on port 8000.
3. **Strict File Magic-Byte Validation:** Every upload is validated against genuine binary signatures (`\xff\xd8\xff` for JPEG, `\x89PNG` for PNG, `RIFF...WAVE` for WAV, `ftyp` for MP4). Disguised extensions are rejected.
4. **Comprehensive SSRF Defense:** All analyzed URLs are parsed and resolved via DNS; requests to RFC-1918 private subnets, loopback, or cloud link-local addresses are rejected.
5. **Rate Limiting with X-Forwarded-For:** The backend inspects reverse proxy forwarded headers to track and enforce per-IP sliding-window rate limits.
6. **Zero-Retention Mode:** One-click ephemeral mode guarantees zero content, audit logs, or feedback records are retained on disk.
7. **No Key Leakage:** API credentials remain strictly server-side on your laptop and are never exposed in frontend bundles or API responses.
8. **Hardened HTTP Headers:** `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Content-Security-Policy`.

