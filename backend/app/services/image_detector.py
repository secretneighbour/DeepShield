import asyncio
import base64
import io
import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple

import cv2
import numpy as np
from PIL import Image, ImageChops, ImageEnhance, ImageOps, UnidentifiedImageError
from PIL.ExifTags import TAGS

from app.config import settings
from app.models.schemas import RiskLevel, EvidenceItem, ImageAnalysisResponse
from app.utils.security import validate_file_signature
from app.services.url_detector import url_detector

logger = logging.getLogger("scamshield.image_detector")

# Suspect software signatures explicitly embedded in AI-generated images
EXPLICIT_AI_SOFTWARE_SIGNATURES = [
    "stable diffusion", "midjourney", "dall-e", "novelai",
    "automatic1111", "comfyui", "flux", "sdxl", "civitai"
]

# Scam indicators commonly present in screenshot lures
SCAM_CONTENT_PATTERNS = [
    (r"(?i)\b(wire transfer|gift card|bitcoin|btc|eth|crypto|cashapp|zelle|venmo)\b", "Suspicious Financial / Cryptographic Payment Lure", "high"),
    (r"(?i)\b(account (has been )?suspended|card (has been )?deactivated|immediately verify|within 24 hours|action required)\b", "Artificial Urgency & Coercive Pressure", "high"),
    (r"(?i)\b(enter your pin|verify password|social security|ssn|seed phrase|private key)\b", "Credential / Identity Harvesting Attempt", "high"),
    (r"(?i)\b(lottery winner|claim your prize|congratulations you won|\$1,?000,?000|free gift card)\b", "Deceptive Prize / Advance-Fee Scam", "high"),
    (r"(?i)\b(geek squad|norton|mcafee|microsoft support|apple support|irs notice|fbi alert)\b", "Authority / Tech Support Impersonation", "medium"),
    (r"(?i)\b(urgent|critical alert|unauthorized transaction|fraud alert)\b", "Security Panic Inoculation", "medium"),
]

# Modular interface for deepfake / synthetic media detection
class BaseSyntheticMediaDetector:
    """Modular contract for image forensics and deepfake models."""
    def analyze_authenticity(self, image: Image.Image) -> Dict[str, Any]:
        raise NotImplementedError

class HeuristicForensicsDetector(BaseSyntheticMediaDetector):
    """
    Classical image forensics engine implementing:
    - Error Level Analysis (ELA) for recompression quantization anomalies
    - Fast Fourier Transform (FFT) 2D spectral inspection for periodic lattice artifacts
    - Spatial noise inconsistency across quadrants (Laplacian variance)
    - Non-destructive EXIF inspection for explicit generative AI software tags
    """
    def compute_ela(self, image: Image.Image, quality: int = 90) -> Tuple[float, Image.Image]:
        orig_rgb = image.convert("RGB")
        buffer = io.BytesIO()
        orig_rgb.save(buffer, format="JPEG", quality=quality)
        buffer.seek(0)
        recompressed = Image.open(buffer)

        diff = ImageChops.difference(orig_rgb, recompressed)
        extrema = diff.getextrema()
        max_diff = max([ex[1] for ex in extrema]) if extrema else 1
        scale = 255.0 / max(1, max_diff)

        enhanced = ImageEnhance.Brightness(diff).enhance(scale)
        diff_arr = np.array(diff, dtype=np.float32)
        mean_err = float(np.mean(diff_arr))
        return mean_err, enhanced

    def compute_fft_anomaly(self, image: Image.Image) -> float:
        gray = image.convert("L").resize((256, 256), Image.Resampling.BILINEAR)
        arr = np.array(gray, dtype=np.float32) / 255.0

        f = np.fft.fft2(arr)
        fshift = np.fft.fftshift(f)
        magnitude_spectrum = 20 * np.log(np.abs(fshift) + 1e-9)

        h, w = magnitude_spectrum.shape
        cy, cx = h // 2, w // 2
        r_inner = 25
        r_outer = 90

        y, x = np.ogrid[:h, :w]
        dist_from_center = np.sqrt((x - cx)**2 + (y - cy)**2)

        center_mask = dist_from_center <= r_inner
        outer_mask = (dist_from_center > r_inner) & (dist_from_center <= r_outer)

        outer_energy = float(np.mean(magnitude_spectrum[outer_mask]))
        std_outer = float(np.std(magnitude_spectrum[outer_mask]))
        peak_anomaly = float(np.max(magnitude_spectrum[outer_mask]) - outer_energy)

        anomaly_metric = min(1.0, max(0.0, (peak_anomaly / 35.0) * 0.5 + (std_outer / 20.0) * 0.5))
        return round(anomaly_metric, 4)

    def compute_noise_inconsistency(self, image: Image.Image) -> float:
        gray = image.convert("L").resize((512, 512), Image.Resampling.BILINEAR)
        arr = np.array(gray, dtype=np.float32)

        laplacian = (
            np.roll(arr, 1, axis=0) + np.roll(arr, -1, axis=0) +
            np.roll(arr, 1, axis=1) + np.roll(arr, -1, axis=1) -
            4 * arr
        )[2:-2, 2:-2]

        blocks = []
        bs = laplacian.shape[0] // 4
        for r in range(4):
            for c in range(4):
                block = laplacian[r*bs:(r+1)*bs, c*bs:(c+1)*bs]
                blocks.append(float(np.std(block)))

        if not blocks:
            return 0.0

        mean_std = np.mean(blocks)
        if mean_std == 0:
            return 0.0

        coef_of_variation = float(np.std(blocks) / (mean_std + 1e-6))
        score = min(1.0, max(0.0, coef_of_variation / 1.5))
        return round(score, 4)

    def extract_metadata(self, image: Image.Image) -> Tuple[Dict[str, Any], List[str]]:
        """
        Extract EXIF metadata safely.
        NOTE: Per standards, lack of camera metadata or ordinary recompression is NOT
        treated as proof of AI generation or tampering.
        """
        summary: Dict[str, Any] = {}
        ai_clues: List[str] = []

        try:
            raw_exif = image.getexif()
        except Exception:
            raw_exif = None

        if not raw_exif:
            summary["exif_status"] = "No EXIF metadata present (standard for web screenshots and stripped uploads)"
            return summary, ai_clues

        for tag_id, value in raw_exif.items():
            tag_name = TAGS.get(tag_id, str(tag_id))
            val_str = str(value).strip()[:200]
            if tag_name in ("Make", "Model", "Software", "DateTime", "Artist", "Copyright", "UserComment"):
                summary[tag_name] = val_str

        # Scan specifically for explicit generative AI software tags
        sw = summary.get("Software", "").lower()
        comment = summary.get("UserComment", "").lower()
        combined_meta = f"{sw} {comment}"

        for sig in EXPLICIT_AI_SOFTWARE_SIGNATURES:
            if sig in combined_meta:
                ai_clues.append(f"Metadata references generative AI creation tool: '{sig.title()}'")

        return summary, ai_clues

    def analyze_authenticity(self, image: Image.Image) -> Dict[str, Any]:
        meta_summary, ai_clues = self.extract_metadata(image)
        ela_mean, ela_img = self.compute_ela(image)
        fft_anomaly = self.compute_fft_anomaly(image)
        noise_inconsistency = self.compute_noise_inconsistency(image)
        ela_norm = min(1.0, max(0.0, ela_mean / 15.0))

        # Forensic scoring: distinguish authentic, altered, and synthetic signatures
        evidence: List[EvidenceItem] = []
        if ai_clues:
            for clue in ai_clues:
                evidence.append(EvidenceItem(
                    title="Generative AI Software Header",
                    description=clue,
                    severity="high",
                    category="EXIF Forensics"
                ))

        if fft_anomaly > 0.80:
            evidence.append(EvidenceItem(
                title="Spectral Periodic Grid Anomaly",
                description=f"FFT magnitude spectrum exhibits high-frequency periodic lattice spikes ({fft_anomaly:.2f}), characteristic of GAN or diffusion upsampling.",
                severity="medium",
                category="Spectral Forensics",
                metric_value=fft_anomaly
            ))
        elif fft_anomaly > 0.50:
            evidence.append(EvidenceItem(
                title="Mild Spectral Deviation",
                description=f"Minor high-frequency variation ({fft_anomaly:.2f}), which may indicate synthetic generation, resampling, or aggressive sharpening.",
                severity="low",
                category="Spectral Forensics",
                metric_value=fft_anomaly
            ))

        if noise_inconsistency > 0.70:
            evidence.append(EvidenceItem(
                title="Spatial Noise Inconsistency",
                description=f"High variance in residual sensor noise across spatial quadrants ({noise_inconsistency:.2f}). Suggests selective splicing, compositing, or localized in-painting.",
                severity="medium",
                category="Noise Distribution",
                metric_value=noise_inconsistency
            ))

        if ela_norm > 0.60:
            evidence.append(EvidenceItem(
                title="Compression Error Discrepancy",
                description=f"Elevated compression error gradient ({ela_norm:.2f}). Differing JPEG quantization levels observed across image regions.",
                severity="low",
                category="Compression Analysis",
                metric_value=ela_norm
            ))

        # Determine synthetic media risk
        if ai_clues:
            synth_risk = RiskLevel.HIGH_RISK
            synth_confidence = 0.92
        elif fft_anomaly > 0.82 and noise_inconsistency > 0.75:
            synth_risk = RiskLevel.MEDIUM_RISK
            synth_confidence = 0.75
        elif fft_anomaly > 0.60 or noise_inconsistency > 0.60:
            synth_risk = RiskLevel.LOW_RISK
            synth_confidence = 0.70
        else:
            synth_risk = RiskLevel.LOW_RISK
            synth_confidence = 0.85
            evidence.append(EvidenceItem(
                title="Consistent Forensic Profile",
                description="No unnatural periodic frequency lattices or localized noise discrepancies detected across evaluated quadrants.",
                severity="info",
                category="Integrity Check"
            ))

        return {
            "meta_summary": meta_summary,
            "ai_clues": ai_clues,
            "ela_score": round(ela_norm, 3),
            "ela_img": ela_img,
            "fft_anomaly": round(fft_anomaly, 3),
            "noise_inconsistency": round(noise_inconsistency, 3),
            "synthetic_media_risk": synth_risk,
            "synthetic_media_confidence": synth_confidence,
            "evidence": evidence
        }


class ImageDeepfakeDetector:
    def __init__(self, max_dimension: int = 8192, max_size_bytes: int = 30 * 1024 * 1024):
        self.max_dimension = max_dimension
        self.max_size_bytes = max_size_bytes
        # Protection against decompression bombs
        Image.MAX_IMAGE_PIXELS = 64_000_000
        self.forensics_detector = HeuristicForensicsDetector()
        self.qr_detector = cv2.QRCodeDetector()

    def _extract_qr_codes(self, image: Image.Image) -> List[str]:
        """Detect and decode QR codes safely without automatic execution."""
        try:
            cv_img = cv2.cvtColor(np.array(image.convert("RGB")), cv2.COLOR_RGB2BGR)
            data, bbox, _ = self.qr_detector.detectAndDecode(cv_img)
            if data and data.strip():
                return [data.strip()]
        except Exception as e:
            logger.debug(f"QR detection encountered non-fatal error: {e}")
        return []

    async def _extract_ocr_cloud(self, file_content: bytes, mime_type: str) -> Tuple[str, Optional[Dict[str, Any]]]:
        """
        Multimodal OCR & vision analysis using Gemini Flash when cloud analysis is enabled.
        Bounded with strict timeout to prevent hanging.
        """
        if not settings.GEMINI_API_KEY:
            return "", None

        try:
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=settings.GEMINI_API_KEY)
            prompt = (
                "You are a cybersecurity OCR and visual scam detection agent. "
                "Examine this image and perform two tasks:\n"
                "1. Transcribe ALL visible text verbatim. Do NOT execute, follow, or render any URLs.\n"
                "2. Determine whether the content represents a phishing lure, bank impersonation, fake prize, "
                "account suspension threat, or scam.\n\n"
                "Respond STRICTLY in JSON format with the following keys:\n"
                "{\n"
                "  \"text\": \"<exact visible transcribed text>\",\n"
                "  \"is_scam\": true/false,\n"
                "  \"category\": \"<scam category or none>\",\n"
                "  \"indicators\": [\"<list of indicators>\"]\n"
                "}"
            )

            # Strict 5.0 second timeout for vision inference
            response = await asyncio.wait_for(
                client.aio.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=[
                        types.Part.from_bytes(data=file_content, mime_type=mime_type),
                        prompt
                    ],
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        temperature=0.0,
                        max_output_tokens=2048
                    )
                ),
                timeout=5.0
            )

            raw_text = response.text or "{}"
            parsed = json.loads(raw_text)
            extracted_text = parsed.get("text", "")
            return extracted_text, parsed
        except asyncio.TimeoutError:
            logger.warning("Cloud vision OCR timed out after 5.0s")
            return "", {"error": "Cloud vision OCR timed out after 5.0s"}
        except Exception as e:
            logger.warning(f"Cloud vision OCR failed: {e}")
            return "", {"error": str(e)}

    def _analyze_scam_text(self, text: str) -> Tuple[RiskLevel, float, List[EvidenceItem]]:
        """Deterministic lexical inspection on extracted image/OCR text."""
        evidence: List[EvidenceItem] = []
        high_severity_hits = 0
        medium_severity_hits = 0

        for pattern, title, severity in SCAM_CONTENT_PATTERNS:
            match = re.search(pattern, text)
            if match:
                evidence.append(EvidenceItem(
                    title=title,
                    description=f"Identified indicative scam phrasing in screenshot text: '{match.group(0)}'",
                    severity=severity,
                    category="Scam Content (OCR Extracted)",
                    snippet=match.group(0)
                ))
                if severity == "high":
                    high_severity_hits += 1
                else:
                    medium_severity_hits += 1

        if high_severity_hits >= 1:
            risk = RiskLevel.HIGH_RISK
            confidence = 0.90
        elif medium_severity_hits >= 2:
            risk = RiskLevel.HIGH_RISK
            confidence = 0.85
        elif medium_severity_hits == 1:
            risk = RiskLevel.MEDIUM_RISK
            confidence = 0.70
        else:
            risk = RiskLevel.LOW_RISK
            confidence = 0.80

        return risk, confidence, evidence

    async def analyze(
        self,
        file_content: bytes,
        filename: str,
        declared_mime: str,
        cloud_enabled: bool = True
    ) -> ImageAnalysisResponse:
        """
        Comprehensive image analysis pipeline:
        1. Input validation & security guards (size, magic bytes, decompression protection).
        2. Orientation normalization and dimension safety.
        3. QR code / embedded link detection (without automatic execution).
        4. OCR text extraction & scam content assessment (Gemini Vision with timeout).
        5. Classical image forensics (ELA, FFT spectrum, noise variance, metadata).
        6. Structured synthesis with clear separation of scam content vs synthetic media authenticity.
        """
        analysis_id = str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).isoformat()
        filesize = len(file_content)

        # 1. Size Validation Guard
        if filesize > self.max_size_bytes:
            return ImageAnalysisResponse(
                id=analysis_id,
                timestamp=now_iso,
                filename=filename,
                filesize=filesize,
                format="OVERSIZED",
                dimensions=[0, 0],
                risk_level=RiskLevel.INCONCLUSIVE,
                confidence=0.5,
                ela_score=0.0,
                noise_inconsistency=0.0,
                fft_frequency_anomaly=0.0,
                metadata_summary={},
                exif_tampering_clues=[],
                evidence=[EvidenceItem(
                    title="File Exceeds Upload Threshold",
                    description=f"Image size ({filesize / (1024*1024):.1f}MB) exceeds limit of {self.max_size_bytes / (1024*1024):.0f}MB.",
                    severity="medium",
                    category="Input Validation"
                )],
                recommended_actions=["Compress or resize the image before submitting."],
                limitations=["Oversized images are rejected to protect server memory."],
                analysis_status="failed",
                deepfake_detector_status="Analysis skipped due to file size"
            )

        # 2. File Signature (Magic Bytes) Validation
        valid_sig, detected_mime = validate_file_signature(file_content, declared_mime)
        if not valid_sig:
            return ImageAnalysisResponse(
                id=analysis_id,
                timestamp=now_iso,
                filename=filename,
                filesize=filesize,
                format="UNKNOWN",
                dimensions=[0, 0],
                risk_level=RiskLevel.HIGH_RISK,
                confidence=0.95,
                ela_score=0.0,
                noise_inconsistency=0.0,
                fft_frequency_anomaly=0.0,
                metadata_summary={"error": "File signature validation failed"},
                exif_tampering_clues=["Magic bytes do not match declared image format (potential disguised executable/exploit)"],
                evidence=[EvidenceItem(
                    title="Invalid File Header Signature",
                    description=f"Declared type '{declared_mime}' does not match detected byte header ({detected_mime}).",
                    severity="high",
                    category="Malicious File Format",
                    snippet=f"Detected: {detected_mime}"
                )],
                recommended_actions=[
                    "Do not execute or open this file with default desktop handlers.",
                    "Verify file origin before opening."
                ],
                limitations=["Disguised or invalid payloads are blocked from pixel decoding."],
                analysis_status="failed",
                deepfake_detector_status="Analysis aborted due to invalid file signature"
            )

        # 3. Safe Image Decoding & Decompression Bomb Guard
        try:
            image = Image.open(io.BytesIO(file_content))
            # Normalize EXIF orientation to prevent geometric distortion in forensics
            image = ImageOps.exif_transpose(image) or image
            width, height = image.size
        except UnidentifiedImageError as e:
            return ImageAnalysisResponse(
                id=analysis_id,
                timestamp=now_iso,
                filename=filename,
                filesize=filesize,
                format="CORRUPTED",
                dimensions=[0, 0],
                risk_level=RiskLevel.INCONCLUSIVE,
                confidence=0.5,
                ela_score=0.0,
                noise_inconsistency=0.0,
                fft_frequency_anomaly=0.0,
                metadata_summary={},
                exif_tampering_clues=[],
                evidence=[EvidenceItem(
                    title="Corrupted or Unreadable Image Stream",
                    description=f"Image parser failed to decode pixel matrix: {str(e)}",
                    severity="medium",
                    category="Image Decoding"
                )],
                recommended_actions=["Ensure image was completely downloaded and not truncated."],
                limitations=["Image could not be rendered."],
                analysis_status="failed",
                deepfake_detector_status="Image decoder failed"
            )
        except Exception as e:
            return ImageAnalysisResponse(
                id=analysis_id,
                timestamp=now_iso,
                filename=filename,
                filesize=filesize,
                format="CORRUPTED",
                dimensions=[0, 0],
                risk_level=RiskLevel.INCONCLUSIVE,
                confidence=0.5,
                ela_score=0.0,
                noise_inconsistency=0.0,
                fft_frequency_anomaly=0.0,
                metadata_summary={},
                exif_tampering_clues=[],
                evidence=[EvidenceItem(
                    title="Image Stream Decoding Error",
                    description=f"Decryption or decompression error: {str(e)}",
                    severity="medium",
                    category="Image Decoding"
                )],
                recommended_actions=["Ensure image is a supported format (JPEG, PNG, WebP)."],
                limitations=["Decoder failure."],
                analysis_status="failed"
            )

        # Dimension Safety Guard
        if width > self.max_dimension or height > self.max_dimension:
            return ImageAnalysisResponse(
                id=analysis_id,
                timestamp=now_iso,
                filename=filename,
                filesize=filesize,
                format=image.format or "UNKNOWN",
                dimensions=[width, height],
                risk_level=RiskLevel.INCONCLUSIVE,
                confidence=0.5,
                ela_score=0.0,
                noise_inconsistency=0.0,
                fft_frequency_anomaly=0.0,
                metadata_summary={},
                exif_tampering_clues=["Image exceeds safety dimension thresholds."],
                evidence=[],
                recommended_actions=["Resize the image under 8192x8192 before scanning."],
                limitations=["Exceeded safe pixel dimensions."],
                analysis_status="failed"
            )

        evidence_list: List[EvidenceItem] = []
        limitations: List[str] = [
            "Forensic ELA and FFT analyses are heuristic signal-processing tools; absence of camera metadata is common in web downloads and does NOT prove synthetic origin.",
            "Specialized neural deepfake weights are not loaded; assessment is based on classical frequency/noise analysis.",
            "Images stripped by social platforms (WhatsApp, X) lose original quantization tables."
        ]

        # 4. QR Code & Barcode Analysis (Quishing Vector)
        qr_codes = self._extract_qr_codes(image)
        for qr_data in qr_codes:
            evidence_list.append(EvidenceItem(
                title="Embedded QR Code Detected",
                description=f"Image contains a machine-readable QR code pointing to: '{qr_data[:80]}'",
                severity="medium",
                category="Embedded QR / Quishing",
                snippet=qr_data[:60]
            ))
            # Safely analyze extracted URL without following or visiting
            if qr_data.startswith(("http://", "https://")):
                url_res = await url_detector.analyze(qr_data, check_threat_intel=False)
                if url_res.risk_level == RiskLevel.HIGH_RISK:
                    evidence_list.append(EvidenceItem(
                        title="Suspicious QR Destination Hostname",
                        description=f"Decoded QR code leads to suspicious destination: {url_res.url}",
                        severity="high",
                        category="Phishing / Quishing",
                        snippet=url_res.url
                    ))

        # 5. OCR & Visible Scam Text Extraction
        ocr_status = "unavailable"
        extracted_text = ""
        scam_content_risk: Optional[RiskLevel] = None

        if cloud_enabled and settings.GEMINI_API_KEY:
            extracted_text, cloud_meta = await self._extract_ocr_cloud(file_content, detected_mime)
            if extracted_text:
                ocr_status = "completed"
                scam_content_risk, scam_conf, scam_evidence = self._analyze_scam_text(extracted_text)
                evidence_list.extend(scam_evidence)
            elif cloud_meta and "error" in cloud_meta:
                ocr_status = "failed"
                limitations.append(f"Cloud vision OCR stage: {cloud_meta['error']}")
            else:
                ocr_status = "no_text_found"
        else:
            ocr_status = "unavailable_offline"
            limitations.append("Cloud analysis disabled or unconfigured; screenshot OCR requires active Gemini cloud configuration.")

        # 6. Heuristic Image Manipulation & Synthetic Media Forensics
        forensics = self.forensics_detector.analyze_authenticity(image)
        synthetic_media_risk = forensics["synthetic_media_risk"]
        evidence_list.extend(forensics["evidence"])

        # Create thumbnail for ELA heatmap visualization
        buf = io.BytesIO()
        forensics["ela_img"].resize(
            (min(400, width), int(min(400, width) * (height / width))),
            Image.Resampling.BILINEAR
        ).save(buf, format="PNG")
        ela_base64 = base64.b64encode(buf.getvalue()).decode("utf-8")

        # 7. Synthesize Overall Risk Level (Distinguishing Scam Content from Deepfake Manipulation)
        if scam_content_risk == RiskLevel.HIGH_RISK or synthetic_media_risk == RiskLevel.HIGH_RISK:
            overall_risk = RiskLevel.HIGH_RISK
            confidence = 0.90
        elif scam_content_risk == RiskLevel.MEDIUM_RISK or synthetic_media_risk == RiskLevel.MEDIUM_RISK:
            overall_risk = RiskLevel.MEDIUM_RISK
            confidence = 0.75
        elif scam_content_risk == RiskLevel.LOW_RISK and synthetic_media_risk == RiskLevel.LOW_RISK:
            overall_risk = RiskLevel.LOW_RISK
            confidence = 0.85
        else:
            overall_risk = synthetic_media_risk
            confidence = forensics["synthetic_media_confidence"]

        # Recommendations
        recommended_actions = []
        if overall_risk == RiskLevel.HIGH_RISK:
            if scam_content_risk == RiskLevel.HIGH_RISK:
                recommended_actions.append("DO NOT call phone numbers, visit URLs, or transfer funds mentioned in this image.")
                recommended_actions.append("Directly contact the legitimate organization through verified official channels.")
            if synthetic_media_risk == RiskLevel.HIGH_RISK:
                recommended_actions.append("Do not rely on this image for evidentiary or biometric identity verification.")
        elif overall_risk == RiskLevel.MEDIUM_RISK:
            recommended_actions.append("Scrutinize screenshot claims independently before proceeding with any financial actions.")
            recommended_actions.append("Verify through independent channels before making identity or security decisions.")
        else:
            recommended_actions.append("No obvious scam lures or forensic anomalies detected. Standard visual prudence advised.")

        return ImageAnalysisResponse(
            id=analysis_id,
            timestamp=now_iso,
            filename=filename,
            filesize=filesize,
            format=image.format or "JPEG",
            dimensions=[width, height],
            risk_level=overall_risk,
            confidence=round(confidence, 3),
            ela_score=forensics["ela_score"],
            noise_inconsistency=forensics["noise_inconsistency"],
            fft_frequency_anomaly=forensics["fft_anomaly"],
            metadata_summary=forensics["meta_summary"],
            exif_tampering_clues=forensics["ai_clues"],
            evidence=evidence_list,
            recommended_actions=recommended_actions,
            limitations=limitations,
            annotated_heatmap_base64=f"data:image/png;base64,{ela_base64}",
            analysis_status="completed",
            scam_content_risk=scam_content_risk,
            synthetic_media_risk=synthetic_media_risk,
            ocr_status=ocr_status,
            ocr_extracted_text=extracted_text[:500] if extracted_text else None,
            qr_codes_detected=qr_codes,
            detector_attribution="DeepShield Multimodal & Heuristic Forensics Pipeline",
            deepfake_detector_status="Heuristic Forensics (ELA/FFT/Noise) - Neural Deepfake Model Weights Not Configured"
        )

image_detector = ImageDeepfakeDetector()
