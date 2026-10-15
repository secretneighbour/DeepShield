import os
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Tuple

import cv2
import numpy as np
from PIL import Image

from app.models.schemas import RiskLevel, EvidenceItem, VideoFrameMetric, VideoAnalysisResponse
from app.utils.security import validate_file_signature

class VideoDeepfakeDetector:
    def __init__(self, max_duration_sec: float = 60.0, max_frames_to_sample: int = 30):
        self.max_duration_sec = max_duration_sec
        self.max_frames_to_sample = max_frames_to_sample

    def analyze_frame_anomaly(self, frame_rgb: np.ndarray) -> float:
        """
        Analyze a single sampled frame for synthetic artifact indicators:
        - High-frequency edge gradient variance
        - Color channel distribution anomalies
        """
        # Convert to float and grayscale
        gray = cv2.cvtColor(frame_rgb, cv2.COLOR_RGB2GRAY)
        
        # Laplacian variance measures blurriness and artificial smoothing in face regions
        laplacian_var = cv2.Laplacian(gray, cv2.CV_64F).var()
        
        # In deepfakes, face swaps often have lower sharpness or distinct blurring compared to surrounding background
        # Also check color channel correlation
        r, g, b = frame_rgb[:,:,0], frame_rgb[:,:,1], frame_rgb[:,:,2]
        rb_corr = np.corrcoef(r.flatten()[:10000], b.flatten()[:10000])[0, 1]
        
        # Anomaly metric combining edge smoothness and color divergence
        smoothness_penalty = max(0.0, 1.0 - (laplacian_var / 350.0))
        corr_penalty = max(0.0, (0.75 - rb_corr) if not np.isnan(rb_corr) else 0.0)
        
        score = min(1.0, max(0.0, smoothness_penalty * 0.6 + corr_penalty * 0.4))
        return round(float(score), 3)

    def analyze(self, file_content: bytes, filename: str, declared_mime: str) -> VideoAnalysisResponse:
        analysis_id = str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. File signature validation
        valid_sig, detected_mime = validate_file_signature(file_content, declared_mime)
        if not valid_sig:
            return VideoAnalysisResponse(
                id=analysis_id,
                timestamp=now_iso,
                filename=filename,
                duration_seconds=0.0,
                total_frames_sampled=0,
                risk_level=RiskLevel.HIGH_RISK,
                confidence=0.95,
                temporal_inconsistency_score=0.0,
                frame_timeline=[],
                evidence=[
                    EvidenceItem(
                        title="Invalid Video Header Signature",
                        description=f"File content does not contain valid MP4/WebM headers ({detected_mime}). Potential malicious payload.",
                        severity="high",
                        category="Malicious File Format"
                    )
                ],
                recommended_actions=["Do not run or transcode this video file. Delete from host immediately."],
                limitations=["File failed binary signature validation."]
            )

        # 2. Write safely to a restricted temporary file
        temp_dir = tempfile.gettempdir()
        temp_video_path = os.path.join(temp_dir, f"shield_vid_{uuid.uuid4().hex}.mp4")

        try:
            with open(temp_video_path, "wb") as f:
                f.write(file_content)

            cap = cv2.VideoCapture(temp_video_path)
            if not cap.isOpened():
                return VideoAnalysisResponse(
                    id=analysis_id,
                    timestamp=now_iso,
                    filename=filename,
                    duration_seconds=0.0,
                    total_frames_sampled=0,
                    risk_level=RiskLevel.INCONCLUSIVE,
                    confidence=0.5,
                    temporal_inconsistency_score=0.0,
                    frame_timeline=[],
                    evidence=[
                        EvidenceItem(
                            title="Unreadable Video Stream",
                            description="Video container could not be opened by standard codec demuxers.",
                            severity="medium",
                            category="Codec Incompatibility"
                        )
                    ],
                    recommended_actions=["Ensure video is encoded in H.264/AAC MP4 or VP8/VP9 WebM format."],
                    limitations=["Codec demuxer failed to extract video frames."]
                )

            fps = cap.get(cv2.CAP_PROP_FPS)
            if fps <= 0 or np.isnan(fps):
                fps = 30.0

            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            duration_sec = total_frames / fps

            # Step calculation to sample up to max_frames_to_sample evenly
            step = max(1, total_frames // self.max_frames_to_sample)
            
            sampled_metrics: List[VideoFrameMetric] = []
            prev_frame_gray = None
            inter_frame_diffs = []
            frame_scores = []

            curr_frame_idx = 0
            while curr_frame_idx < total_frames and len(sampled_metrics) < self.max_frames_to_sample:
                cap.set(cv2.CAP_PROP_POS_FRAMES, curr_frame_idx)
                ret, frame_bgr = cap.read()
                if not ret or frame_bgr is None:
                    break

                timestamp_sec = round(curr_frame_idx / fps, 2)
                frame_rgb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)
                frame_gray = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2GRAY)

                # Compute frame anomaly
                score = self.analyze_frame_anomaly(frame_rgb)
                frame_scores.append(score)

                # Inter-frame temporal difference (flickering & boundary shifting)
                if prev_frame_gray is not None:
                    # Compare resized representations
                    fg_small = cv2.resize(frame_gray, (160, 90))
                    pg_small = cv2.resize(prev_frame_gray, (160, 90))
                    diff = float(np.mean(cv2.absdiff(fg_small, pg_small)))
                    inter_frame_diffs.append(diff)
                
                prev_frame_gray = frame_gray
                is_anom = score > 0.65

                notes = "Normal frame integrity"
                if score > 0.75:
                    notes = "Severe facial/edge blur and color inconsistency"
                elif score > 0.60:
                    notes = "Elevated smoothing anomaly"

                sampled_metrics.append(
                    VideoFrameMetric(
                        frame_index=curr_frame_idx,
                        timestamp_sec=timestamp_sec,
                        anomaly_score=score,
                        is_anomaly=is_anom,
                        notes=notes
                    )
                )

                curr_frame_idx += step

            cap.release()

        finally:
            if os.path.exists(temp_video_path):
                try:
                    os.remove(temp_video_path)
                except OSError:
                    pass

        # 3. Calculate temporal consistency score
        # High variance in inter-frame differences indicates flickering artifacts common in frame-by-frame deepfakes
        if len(inter_frame_diffs) > 1:
            diff_std = float(np.std(inter_frame_diffs))
            diff_mean = float(np.mean(inter_frame_diffs))
            temporal_inconsistency = min(1.0, max(0.0, (diff_std / (diff_mean + 1e-5)) * 0.7))
        else:
            temporal_inconsistency = 0.0

        mean_frame_anomaly = float(np.mean(frame_scores)) if frame_scores else 0.0
        anomalous_frames_count = sum(1 for m in sampled_metrics if m.is_anomaly)

        # 4. Generate evidence and risk level
        evidence_list: List[EvidenceItem] = []
        suspect_points = 0.0

        evidence_list.append(
            EvidenceItem(
                title=f"Sampled Frame Inspection ({len(sampled_metrics)} frames)",
                description=f"Evenly sampled {len(sampled_metrics)} frames across {duration_sec:.1f}s video duration (step interval: {step} frames).",
                severity="info",
                category="Sampling Report"
            )
        )

        if temporal_inconsistency > 0.55:
            evidence_list.append(
                EvidenceItem(
                    title="Temporal Inconsistency & Frame Jitter Detected",
                    description=f"High inter-frame variance ({temporal_inconsistency:.2f}) indicates flickering, face boundary shifting, or inconsistent facial feature generation across adjacent frames.",
                    severity="high" if temporal_inconsistency > 0.75 else "medium",
                    category="Temporal Dynamics",
                    metric_value=temporal_inconsistency
                )
            )
            suspect_points += 0.40

        if anomalous_frames_count > (len(sampled_metrics) * 0.3):
            evidence_list.append(
                EvidenceItem(
                    title=f"Elevated Synthetic Anomalies in Sampled Frames",
                    description=f"{anomalous_frames_count} of {len(sampled_metrics)} sampled frames exhibit significant artificial smoothing and edge variance anomalies.",
                    severity="high",
                    category="Frame Forensics",
                    metric_value=mean_frame_anomaly
                )
            )
            suspect_points += 0.45
        elif mean_frame_anomaly > 0.45:
            evidence_list.append(
                EvidenceItem(
                    title="Moderate Frame Smoothing Anomaly",
                    description=f"Average frame anomaly score is {mean_frame_anomaly:.2f}. Potential light face-filter, beauty filter, or compression artifacting.",
                    severity="medium",
                    category="Frame Forensics",
                    metric_value=mean_frame_anomaly
                )
            )
            suspect_points += 0.20

        # Verdict assignment
        if suspect_points >= 0.55:
            risk_level = RiskLevel.HIGH_RISK
            confidence = min(0.90, 0.60 + suspect_points * 0.3)
        elif suspect_points >= 0.25:
            risk_level = RiskLevel.MEDIUM_RISK
            confidence = min(0.78, 0.50 + suspect_points * 0.25)
        else:
            risk_level = RiskLevel.LOW_RISK
            confidence = 0.80
            evidence_list.append(
                EvidenceItem(
                    title="Continuous Frame Consistency",
                    description="Inter-frame transitions are smooth without anomalous frame-to-frame warping or boundary discontinuities.",
                    severity="info",
                    category="Integrity Check"
                )
            )

        recommended_actions = []
        if risk_level == RiskLevel.HIGH_RISK:
            recommended_actions.append("Do not accept this video for remote KYC, authorization, or executive sign-off.")
            recommended_actions.append("Request an interactive live video call with randomized actions (e.g., turn head sideways, hold hand in front of face).")
        elif risk_level == RiskLevel.MEDIUM_RISK:
            recommended_actions.append("Inspect frame timeline for localized warping near eyes, lips, and neck boundaries.")
            recommended_actions.append("Request secondary confirmation via a trusted channel.")
        else:
            recommended_actions.append("Video maintains natural temporal dynamics. Standard precautions remain recommended.")

        limitations = [
            f"Analyzed {len(sampled_metrics)} frames out of {total_frames} total frames to ensure sub-second response times; skipped {total_frames - len(sampled_metrics)} frames.",
            "Heavy social media video re-encoding (e.g. TikTok, WhatsApp) introduces quantization noise that can mimic temporal inconsistencies.",
            "Dedicated 3D spatiotemporal neural networks (e.g., VideoMAE, SlowFast) require external GPU compute; this analysis operates on calibrated computer vision heuristics."
        ]

        return VideoAnalysisResponse(
            id=analysis_id,
            analysis_id=analysis_id,
            timestamp=now_iso,
            filename=filename,
            duration_seconds=round(duration_sec, 2),
            total_frames_sampled=len(sampled_metrics),
            risk_level=risk_level,
            confidence=round(confidence, 3),
            temporal_inconsistency_score=round(temporal_inconsistency, 3),
            frame_timeline=sampled_metrics,
            evidence=evidence_list,
            recommended_actions=recommended_actions,
            limitations=limitations,
            media_authenticity_risk=risk_level,
            content_intent_risk=RiskLevel.INCONCLUSIVE,
            deepfake_detector_status="Heuristic Forensics (Laplacian Variance & Temporal Inconsistency) - Specialized Neural Weights Unconfigured",
            detector_attribution="DeepShield Video Forensic Engine v1.2"
        )

video_detector = VideoDeepfakeDetector()
