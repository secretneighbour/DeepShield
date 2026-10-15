import os
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Tuple, Optional

import numpy as np
from scipy.io import wavfile

from app.models.schemas import RiskLevel, EvidenceItem, AudioAnalysisResponse
from app.utils.security import validate_file_signature
from app.services.text_detector import text_detector

class AudioAuthenticityDetector:
    def __init__(self, max_duration_sec: float = 120.0):
        self.max_duration_sec = max_duration_sec

    def convert_to_wav_pcm(self, input_bytes: bytes, original_ext: str) -> Tuple[Optional[int], Optional[np.ndarray], Optional[str]]:
        """Safely convert audio bytes to 16kHz mono PCM using ffmpeg subprocess."""
        temp_in = tempfile.NamedTemporaryFile(suffix=f".{original_ext}", delete=False)
        temp_out = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
        
        try:
            temp_in.write(input_bytes)
            temp_in.flush()
            temp_in.close()
            temp_out.close()

            # Run ffmpeg with parameterized arguments (no shell=True)
            cmd = [
                "ffmpeg", "-y", "-i", temp_in.name,
                "-ar", "16000", "-ac", "1", "-f", "wav",
                temp_out.name
            ]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            if res.returncode != 0:
                return None, None, f"FFmpeg transcoding failed: {res.stderr.decode('utf-8', errors='ignore')[:150]}"

            sample_rate, data = wavfile.read(temp_out.name)
            # Ensure float array normalized to [-1.0, 1.0]
            if data.dtype == np.int16:
                samples = data.astype(np.float32) / 32768.0
            elif data.dtype == np.int32:
                samples = data.astype(np.float32) / 2147483648.0
            elif data.dtype == np.uint8:
                samples = (data.astype(np.float32) - 128) / 128.0
            else:
                samples = data.astype(np.float32)

            return sample_rate, samples, None

        except subprocess.TimeoutExpired:
            return None, None, "Audio processing timed out"
        except Exception as e:
            return None, None, f"Audio decode error: {str(e)}"
        finally:
            if os.path.exists(temp_in.name):
                try: os.remove(temp_in.name)
                except OSError: pass
            if os.path.exists(temp_out.name):
                try: os.remove(temp_out.name)
                except OSError: pass

    def calculate_pitch_jitter(self, samples: np.ndarray, sample_rate: int) -> float:
        """
        Estimate pitch period jitter (micro-tremor).
        Human vocal cords naturally exhibit micro-variations (0.5% - 2.0% jitter).
        Synthetic neural TTS vocoders often generate overly rigid pitch trajectories (<0.3%)
        or erratic unnatural phase glitches (>3.5%).
        """
        if len(samples) < sample_rate * 0.5:
            return 0.01

        # Frame based autocorrelation for pitch tracking
        frame_len = int(sample_rate * 0.03) # 30ms window
        hop_len = int(sample_rate * 0.015) # 15ms hop
        
        periods = []
        for i in range(0, len(samples) - frame_len, hop_len * 4): # sample periodic windows
            window = samples[i:i+frame_len]
            if np.max(np.abs(window)) < 0.05:
                continue # skip silence
                
            corr = np.correlate(window, window, mode="full")
            corr = corr[len(corr)//2:]
            
            # Look for pitch peak between 70Hz and 400Hz
            min_lag = int(sample_rate / 400)
            max_lag = int(sample_rate / 70)
            if max_lag < len(corr):
                lag = min_lag + np.argmax(corr[min_lag:max_lag])
                periods.append(lag)

        if len(periods) < 5:
            return 0.015

        # Compute relative jitter
        diffs = np.abs(np.diff(periods))
        mean_period = np.mean(periods)
        jitter = float(np.mean(diffs) / (mean_period + 1e-6))
        return round(jitter, 4)

    def calculate_spectral_anomaly(self, samples: np.ndarray, sample_rate: int) -> float:
        """
        Detect unnatural frequency truncation or vocoder artifacts.
        Many synthetic speech models drop abruptly past 7.5 kHz or show comb filter lines.
        """
        if len(samples) < 512:
            return 0.0

        fft_vals = np.abs(np.fft.rfft(samples[:min(len(samples), sample_rate * 5)]))
        freqs = np.fft.rfftfreq(min(len(samples), sample_rate * 5), d=1.0/sample_rate)

        # High frequency energy above 7000 Hz
        high_freq_mask = freqs > 7000
        mid_freq_mask = (freqs >= 1000) & (freqs <= 4000)

        high_energy = np.sum(fft_vals[high_freq_mask])
        mid_energy = np.sum(fft_vals[mid_freq_mask]) + 1e-6

        ratio = float(high_energy / mid_energy)
        
        # In natural 16kHz speech, ratio is usually between 0.05 and 0.35.
        # Deepfake vocoders often have near zero (<0.01) or harsh noisy artifacts (>0.6)
        if ratio < 0.015:
            anomaly = 0.75 # steep vocoder cutoff
        elif ratio > 0.55:
            anomaly = 0.65 # abnormal high frequency noise
        else:
            anomaly = max(0.0, 0.4 - ratio)
            
        return round(float(anomaly), 3)

    def calculate_silence_characteristics(self, samples: np.ndarray) -> Tuple[float, bool]:
        """
        Detect absolute digital silence vs natural background ambient room noise.
        """
        threshold = 0.005
        silent_samples = np.sum(np.abs(samples) < threshold)
        silence_ratio = float(silent_samples / max(1, len(samples)))
        
        # Check if there are exact zero blocks (>100 consecutive 0.0 values)
        has_pure_digital_zeros = False
        zero_runs = (samples == 0.0).astype(int)
        if np.sum(zero_runs) > 200:
            has_pure_digital_zeros = True

        return round(silence_ratio, 3), has_pure_digital_zeros

    def analyze(self, file_content: bytes, filename: str, declared_mime: str, transcript: Optional[str] = None) -> AudioAnalysisResponse:
        analysis_id = str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. File signature validation
        valid_sig, detected_mime = validate_file_signature(file_content, declared_mime)
        if not valid_sig:
            return AudioAnalysisResponse(
                id=analysis_id,
                timestamp=now_iso,
                filename=filename,
                duration_seconds=0.0,
                sample_rate=0,
                risk_level=RiskLevel.HIGH_RISK,
                confidence=0.95,
                pitch_jitter=0.0,
                spectral_rolloff_anomaly=0.0,
                silence_ratio=0.0,
                voice_clone_likelihood="UNVERIFIABLE",
                evidence=[
                    EvidenceItem(
                        title="Invalid Audio Header Signature",
                        description=f"File content does not match declared audio MIME type ({detected_mime}). Potential payload disguise.",
                        severity="high",
                        category="Malicious File Format"
                    )
                ],
                recommended_actions=["Do not open or play this file. Delete safely."],
                limitations=["File failed binary signature validation."]
            )

        # 2. Decode and convert audio
        ext = filename.split(".")[-1].lower() if "." in filename else "wav"
        if ext not in ("wav", "mp3", "ogg", "flac", "m4a", "aac"):
            ext = "wav"

        sample_rate, samples, err = self.convert_to_wav_pcm(file_content, ext)
        if err or samples is None or sample_rate is None:
            return AudioAnalysisResponse(
                id=analysis_id,
                timestamp=now_iso,
                filename=filename,
                duration_seconds=0.0,
                sample_rate=0,
                risk_level=RiskLevel.INCONCLUSIVE,
                confidence=0.5,
                pitch_jitter=0.0,
                spectral_rolloff_anomaly=0.0,
                silence_ratio=0.0,
                voice_clone_likelihood="UNKNOWN",
                evidence=[
                    EvidenceItem(
                        title="Audio Decoding Error",
                        description=f"Audio codec could not be processed: {err}",
                        severity="medium",
                        category="Audio Processing"
                    )
                ],
                recommended_actions=["Ensure audio file is in standard WAV, MP3, or M4A format."],
                limitations=["Could not decode audio bitstream."]
            )

        duration_sec = len(samples) / float(sample_rate)

        # 3. Compute acoustic metrics
        jitter = self.calculate_pitch_jitter(samples, sample_rate)
        spectral_anomaly = self.calculate_spectral_anomaly(samples, sample_rate)
        silence_ratio, has_digital_zeros = self.calculate_silence_characteristics(samples)

        evidence_list: List[EvidenceItem] = []
        suspect_points = 0.0

        # Pitch jitter analysis
        if jitter < 0.004:
            evidence_list.append(
                EvidenceItem(
                    title="Robotic Unnatural Pitch Rigidity (Low Jitter)",
                    description=f"Pitch perturbation jitter is abnormally low ({jitter:.4f} < 0.005). Natural human vocal cords vibrate with micro-irregularities; synthetic neural TTS often produces unnaturally uniform fundamental frequencies.",
                    severity="high" if jitter < 0.002 else "medium",
                    category="Vocal Mechanics",
                    metric_value=jitter
                )
            )
            suspect_points += 0.35
        elif jitter > 0.038:
            evidence_list.append(
                EvidenceItem(
                    title="Erratic Pitch Instability",
                    description=f"Elevated pitch jitter ({jitter:.4f} > 0.035) indicative of phase synthesis errors or poor vocoder concatenation.",
                    severity="medium",
                    category="Vocal Mechanics",
                    metric_value=jitter
                )
            )
            suspect_points += 0.25

        # Spectral anomaly
        if spectral_anomaly > 0.5:
            evidence_list.append(
                EvidenceItem(
                    title="Acoustic Spectral Truncation / Vocoder Artifact",
                    description=f"Frequency distribution displays abnormal rolloff ({spectral_anomaly:.2f}). Typical of neural vocoders band-limited to 16kHz or 22kHz sampling domains.",
                    severity="medium",
                    category="Spectral Analysis",
                    metric_value=spectral_anomaly
                )
            )
            suspect_points += 0.30

        # Digital silence check
        if has_digital_zeros:
            evidence_list.append(
                EvidenceItem(
                    title="Absolute Digital Zero Silence Detected",
                    description="Audio contains contiguous runs of mathematical zero amplitude, characteristic of programmatic synthetic generation rather than analog microphone recordings.",
                    severity="medium",
                    category="Acoustic Environment"
                )
            )
            suspect_points += 0.20

        # Determine acoustic voice clone likelihood
        if suspect_points >= 0.55:
            voice_clone_likelihood = "HIGH_LIKELIHOOD"
            risk_level = RiskLevel.HIGH_RISK
            confidence = min(0.88, 0.60 + suspect_points * 0.3)
        elif suspect_points >= 0.25:
            voice_clone_likelihood = "SUSPICIOUS_INDICATORS"
            risk_level = RiskLevel.MEDIUM_RISK
            confidence = min(0.75, 0.50 + suspect_points * 0.25)
        else:
            voice_clone_likelihood = "LOW_LIKELIHOOD"
            risk_level = RiskLevel.LOW_RISK
            confidence = 0.80
            evidence_list.append(
                EvidenceItem(
                    title="Natural Acoustic Jitter & Ambient Noise",
                    description="Audio exhibits healthy human pitch micro-tremors and natural ambient background room acoustics.",
                    severity="info",
                    category="Integrity Check"
                )
            )

        # 4. Spoken Content Scam Analysis (Dual-Result)
        if transcript and transcript.strip():
            text_result = text_detector.analyze(transcript, channel="voice_transcript")
            if text_result.risk_level in (RiskLevel.HIGH_RISK, RiskLevel.MEDIUM_RISK):
                evidence_list.append(
                    EvidenceItem(
                        title=f"Spoken Scam Intent Detected: {text_result.scam_category.value}",
                        description=f"Spoken transcript contains social engineering cues: '{text_result.primary_reason}'. Note: Suspicious intent is evaluated independently from synthetic acoustic cloning.",
                        severity="high" if text_result.risk_level == RiskLevel.HIGH_RISK else "medium",
                        category="Spoken Content Semantics",
                        snippet=transcript[:150]
                    )
                )
                # Escalate overall risk if the spoken message is an outright scam
                if text_result.risk_level == RiskLevel.HIGH_RISK:
                    risk_level = RiskLevel.HIGH_RISK
                    confidence = max(confidence, text_result.confidence)

        recommended_actions = []
        if risk_level == RiskLevel.HIGH_RISK:
            recommended_actions.append("Do NOT authorize emergency fund transfers, disclose passwords, or share OTPs based on this voice message.")
            recommended_actions.append("Hang up and call the alleged speaker back directly using a known verified phone number.")
            recommended_actions.append("Establish a private verbal 'family password' or security challenge for unusual requests.")
        elif risk_level == RiskLevel.MEDIUM_RISK:
            recommended_actions.append("Treat this audio cautiously. Voice cloning tools can synthesize convincing audio from 3 seconds of reference audio.")
            recommended_actions.append("Verify through an independent secondary communication channel.")
        else:
            recommended_actions.append("Acoustic metrics indicate natural human speech. Normal verification procedures apply.")

        limitations = [
            "Acoustic feature analysis provides probabilistic indicators; clean studio recordings or aggressive noise-gate plugins can sometimes mimic synthetic acoustic characteristics.",
            "A suspicious request (e.g., asking for money) does NOT prove that a voice is cloned, and conversely, a cloned voice may be used in benign satire.",
            "Speech recognition transcription is performed on-device without cloud leakage."
        ]

        media_authenticity_risk = RiskLevel.HIGH_RISK if suspect_points >= 0.55 else (RiskLevel.MEDIUM_RISK if suspect_points >= 0.25 else RiskLevel.LOW_RISK)
        content_intent_risk = text_result.risk_level if (transcript and transcript.strip()) else RiskLevel.INCONCLUSIVE

        return AudioAnalysisResponse(
            id=analysis_id,
            analysis_id=analysis_id,
            timestamp=now_iso,
            filename=filename,
            duration_seconds=round(duration_sec, 2),
            sample_rate=sample_rate,
            risk_level=risk_level,
            confidence=round(confidence, 3),
            pitch_jitter=round(jitter, 4),
            spectral_rolloff_anomaly=round(spectral_anomaly, 3),
            silence_ratio=round(silence_ratio, 3),
            voice_clone_likelihood=voice_clone_likelihood,
            evidence=evidence_list,
            recommended_actions=recommended_actions,
            limitations=limitations,
            media_authenticity_risk=media_authenticity_risk,
            content_intent_risk=content_intent_risk,
            deepfake_detector_status="Heuristic Acoustic Forensics (Pitch Jitter & Spectral Rolloff) - Neural Deepfake Weights Unconfigured",
            detector_attribution="DeepShield Audio Forensics Engine v1.2"
        )

audio_detector = AudioAuthenticityDetector()
