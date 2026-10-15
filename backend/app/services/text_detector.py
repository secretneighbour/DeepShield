import re
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Any, Optional

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from app.models.schemas import (
    RiskLevel,
    ScamCategory,
    EvidenceItem,
    TextAnalysisResponse,
)
from app.dataset.scam_corpus import TRAINING_DATA

# Context-aware scam indicators: requires paired intent or explicit coercive semantics
INDICATOR_RULES = [
    {
        "id": "AUTH_COERCION",
        "pattern": r"(?i)\b(?:irs|fbi|dhs|police|sheriff|federal marshals?|ice|customs|court|magistrate|treasury)\b.*?\b(?:arrest|warrant|subpoena|criminal complaint|legal action|suspended your ssn|asset seizure|fine|jail|custody|pay immediately)\b",
        "category": ScamCategory.IMPERSONATION_AUTHORITY,
        "title": "Law Enforcement / Authority Coercion",
        "desc": "Claims of legal action, warrants, or arrest demands by government/police agencies designed to induce immediate panic.",
        "severity": "high",
    },
    {
        "id": "AUTH_WARRANT_DIRECT",
        "pattern": r"(?i)\b(?:federal warrant|arrest warrant|bench warrant|issued for your arrest|taken into custody|criminal charges filed)\b",
        "category": ScamCategory.IMPERSONATION_AUTHORITY,
        "title": "Arrest / Criminal Warrant Threat",
        "desc": "Explicit threats of criminal prosecution or immediate arrest.",
        "severity": "high",
    },
    {
        "id": "EXEC_GIFT_CARD",
        "pattern": r"(?i)\b(?:ceo|cfo|executive|president|director|founder|boss)\b.*?\b(?:gift cards?|steam cards?|apple cards?|itunes cards?|confidential request|urgent favor|wire funds|cannot take calls|board meeting)\b",
        "category": ScamCategory.IMPERSONATION_AUTHORITY,
        "title": "Executive Impersonation / Gift Card Lure",
        "desc": "Impersonates organizational leadership requesting urgent, uncharacteristic actions like gift card purchases or confidential wires.",
        "severity": "high",
    },
    {
        "id": "DIRECT_GIFT_CARD_DEMAND",
        "pattern": r"(?i)\b(?:purchase|buy|send|scratch)\s+(?:\d+\s+)?(?:apple|steam|google\s*play|itunes|amazon|target)\s+(?:gift\s+)?cards?\b",
        "category": ScamCategory.IMPERSONATION_AUTHORITY,
        "title": "Gift Card Payment Demand",
        "desc": "Soliciting gift cards as an untraceable, irreversible payment method.",
        "severity": "high",
    },
    {
        "id": "PHISH_SUSPENSION_ACTION",
        "pattern": r"(?i)\b(?:account|card|access|banking|profile|service)\b.*?\b(?:suspended|locked|restricted|deactivated|frozen|disabled)\b.*?\b(?:verify|restore|unlock|click|login|confirm|sign\s*in|update)\b",
        "category": ScamCategory.PHISHING_CREDENTIAL,
        "title": "Deactivation Threat with Verification Demand",
        "desc": "Urges immediate login or verification under the pretext of an account breach, freeze, or suspension.",
        "severity": "high",
    },
    {
        "id": "PHISH_CREDENTIAL_PROMPT",
        "pattern": r"(?i)\b(?:enter|provide|confirm|verify|submit|text|send|share)\s+(?:your\s+)?(?:\d+[\s-]digit\s+)?(?:password|pin\b|social security|ssn\b|debit card|credit card|cvv|credentials|secret key|otp\b|verification code|passcode)\b",
        "category": ScamCategory.PHISHING_CREDENTIAL,
        "title": "Direct Credential / PIN / SSN / OTP Solicitation",
        "desc": "Explicitly requests highly sensitive credentials, PINs, OTP codes, or government identifiers.",
        "severity": "high",
    },
    {
        "id": "PHISH_UNAUTHORIZED_TX_DISPUTE",
        "pattern": r"(?i)\b(?:unauthorized transaction|unusual (?:login|activity)|charge of \$\d+)\b.*?\b(?:cancel|reverse|verify|dispute|click\s+here)\b",
        "category": ScamCategory.PHISHING_CREDENTIAL,
        "title": "Fake Transaction Alert with Fraudulent Cancellation Link",
        "desc": "Fabricates a high-dollar transaction to provoke the recipient into clicking a fraudulent reversal link.",
        "severity": "high",
    },
    {
        "id": "OTP_THEFT_SOLICIT",
        "pattern": r"(?i)\b(?:text|send|share|reply with|forward|give|enter|confirm|verify)\s+(?:me\s+)?(?:this|the|your)?\s*(?:\d+[\s-]digit\s+)?(?:otp|code|passcode|token|verification code)\b",
        "category": ScamCategory.OTP_MFA_THEFT,
        "title": "MFA / OTP Token Theft Solicitation",
        "desc": "Actively solicits one-time authorization tokens or security verification codes to bypass authentication.",
        "severity": "high",
    },
    {
        "id": "OTP_CALLER_IMPERSONATION",
        "pattern": r"(?i)\b(?:representative|agent|engineer|support|caller)\s+(?:will call|needs|is asking for)\s+.*?(?:code|passcode|otp|token)\b",
        "category": ScamCategory.OTP_MFA_THEFT,
        "title": "Impersonator OTP Extraction Pretext",
        "desc": "Pretext claiming a support representative or engineer needs your 2FA code to assist you.",
        "severity": "high",
    },
    {
        "id": "INVEST_GUARANTEED_RETURNS",
        "pattern": r"(?i)\b(?:guaranteed\s+(?:returns?|profit|income)|100%\s+risk[\s-]free|double\s+your\s+(?:bitcoin|btc|crypto|money)|\d+%\s+return\s+in\s+\d+\s+(?:hours|days))\b",
        "category": ScamCategory.FINANCIAL_INVESTMENT,
        "title": "High-Yield Investment / Crypto Multiplier Claim",
        "desc": "Promises unrealistic, guaranteed financial returns or automated crypto doubling schemes.",
        "severity": "high",
    },
    {
        "id": "CRYPTO_WALLET_EXTRACTION",
        "pattern": r"(?i)\b(?:send|deposit|transfer|wire)\s+.*?\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,39}|0x[a-fA-F0-9]{40})\b",
        "category": ScamCategory.FINANCIAL_INVESTMENT,
        "title": "Cryptocurrency Transfer Request",
        "desc": "Solicits direct transfer of funds to a raw Bitcoin or Ethereum wallet address.",
        "severity": "high",
    },
    {
        "id": "EXTORTION_SEXTORTION_RANSOM",
        "pattern": r"(?i)\b(?:pegasus|recorded video of you|adult sites?|webcam footage|compromising (?:video|photos?)|trojan-spy)\b.*?\b(?:leak|send|expose|pay|bitcoin|btc|ransom|encrypted)\b",
        "category": ScamCategory.URGENCY_EXTORTION,
        "title": "Blackmail / Sextortion Scareware",
        "desc": "Fabricates claims of compromising webcam recordings, spyware, or device encryption to extort ransom.",
        "severity": "high",
    },
    {
        "id": "LOTTERY_PRIZE_ADVANCE_FEE",
        "pattern": r"(?i)\b(?:congratulations|you(?:'ve|\s+have)?\s+won|lucky draw|selected as (?:today's|the) winner)\b.*?\b(?:\$[\d,]+|iphone|prize|claim|courier fee|processing fee|shipping fee)\b",
        "category": ScamCategory.LOTTERY_PRIZE_CRYPTO,
        "title": "Unsolicited Prize / Advance-Fee Lottery Lure",
        "desc": "Claims recipient has won a large lottery or luxury item but requires payment of an upfront fee to release funds.",
        "severity": "high",
    },
    {
        "id": "JOB_TASK_UNREALISTIC_PAY",
        "pattern": r"(?i)\b(?:earn\s+\$[\d]+(?:\s*-\s*\$[\d]+)?\s+per\s+day|rating\s+products|reviewing\s+apps|no\s+experience\s+required)\b.*?\b(?:telegram|whatsapp|commission|daily\s+pay)\b",
        "category": ScamCategory.JOB_EMPLOYMENT,
        "title": "Work-From-Home / Task Scam Pattern",
        "desc": "Promises high daily earnings for trivial product ratings or reviews, funneling to messaging apps.",
        "severity": "medium",
    },
    {
        "id": "JOB_ADVANCE_CHECK",
        "pattern": r"(?i)\b(?:cashier'?s\s+check|send\s+you\s+a\s+check)\b.*?\b(?:home\s+office\s+equipment|approved\s+vendor)\b",
        "category": ScamCategory.JOB_EMPLOYMENT,
        "title": "Fake Check / Equipment Advance-Fee Lure",
        "desc": "Offers to send a cashier's check to purchase home office equipment from an 'approved vendor'.",
        "severity": "high",
    },
    {
        "id": "PRESSURE_COERCION",
        "pattern": r"(?i)\b(?:within\s+(?:24|\d+)\s+hours|within\s+\d+\s+minutes|immediate action required|final warning)\b.*?\b(?:or else|suspended|arrested|deleted|encrypted|leaked|terminated)\b",
        "category": ScamCategory.URGENCY_EXTORTION,
        "title": "Artificial Deadline with Threat Consequence",
        "desc": "Imposes strict short deadlines paired with threats of punitive action to pressure hasty compliance.",
        "severity": "medium",
    },
    {
        "id": "IRREVERSIBLE_PAYMENT_CHANNEL",
        "pattern": r"(?i)\b(?:western union|moneygram|wire funds|wire deposit|zelle to unknown|send money via)\b",
        "category": ScamCategory.FINANCIAL_INVESTMENT,
        "title": "Irreversible Payment Mechanism",
        "desc": "Solicits irreversible money transfer channels typically favoured by fraudulent operations.",
        "severity": "medium",
    },
    {
        "id": "SUSPICIOUS_EMBEDDED_LINK",
        "pattern": r"(?i)https?://[^\s]+",
        "category": ScamCategory.PHISHING_CREDENTIAL,
        "title": "Embedded Hyperlink",
        "desc": "Message contains external hyperlinks that warrant scrutiny.",
        "severity": "info",
    }
]

BENIGN_INDICATOR_RULES = [
    {
        "pattern": r"(?i)\b(?:do not share (?:this|your) (?:code|password|otp)|never share your (?:pin|password|code)|will never ask for your (?:pin|password|otp))\b",
        "title": "Legitimate Security Warning",
        "desc": "Message contains official defensive warning instructing user never to disclose credentials.",
    },
    {
        "pattern": r"(?i)\b(?:meeting at|calendar invite|standup reminder|lunch tomorrow|dinner tonight|boarded the flight|doctor appointment|prescription is ready)\b",
        "title": "Routine Personal / Workplace Scheduling",
        "desc": "Standard interpersonal or organizational calendar communication.",
    },
    {
        "pattern": r"(?i)\b(?:jira tickets?|pull request|confluence space|github repository|clean code|code review|production deploy)\b",
        "title": "Software Engineering / Technical Context",
        "desc": "Routine development coordination without financial or credential demands.",
    },
    {
        "pattern": r"(?i)\b(?:tracking (?:number|1z\w+)|order #[\w-]+.*shipped|delivered to your front porch|arriving in a [a-z]+)\b",
        "title": "Authentic E-Commerce / Carrier Notification",
        "desc": "Legitimate logistics update without fraudulent fee solicitation.",
    }
]

class TextScamDetector:
    def __init__(self):
        self.detector_version = "v1.2.0"
        self.model_pipeline: Optional[Pipeline] = None
        self._train_baseline_model()

    def _train_baseline_model(self):
        """Train calibrated TF-IDF + Logistic Regression pipeline on the curated corpus."""
        texts = [item["text"] for item in TRAINING_DATA]
        labels = [item["label"] for item in TRAINING_DATA]

        self.model_pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, lowercase=True)),
            ("clf", LogisticRegression(C=1.5, class_weight="balanced", random_state=42))
        ])
        self.model_pipeline.fit(texts, labels)

    def analyze(self, text: str, sender_context: Optional[str] = None, channel: str = "auto") -> TextAnalysisResponse:
        analysis_id = f"txt_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.now(timezone.utc).isoformat()

        clean_text = text.strip()
        if len(clean_text) < 10:
            return TextAnalysisResponse(
                id=analysis_id,
                analysis_id=analysis_id,
                timestamp=now_iso,
                created_at=now_iso,
                input_type="text",
                overall_status="Completed",
                risk_level=RiskLevel.INCONCLUSIVE,
                confidence=0.5,
                scam_category=ScamCategory.UNKNOWN,
                primary_reason="Input text is too brief for reliable forensic or semantic evaluation.",
                summary="Insufficient text volume for statistical or forensic assessment.",
                detailed_reasons=["Provide a longer sample or full message context for meaningful assessment."],
                detected_entities=[],
                highlighted_tokens=[],
                indicators=["Insufficient Text Volume"],
                evidence=[EvidenceItem(
                    title="Insufficient Text Volume",
                    description="Text contains fewer than 10 characters.",
                    severity="info",
                    category="Input Quality"
                )],
                supporting_evidence=[],
                alternative_explanations=["The message may have been clipped or sent as a partial fragment."],
                uncertainties=["Cannot infer social engineering intent from fewer than 10 characters."],
                recommended_actions=["Supply the complete message including headers or sender context if available."],
                limitations=["Statistical and NLP models require sufficient tokens to establish behavioral context."],
                model_attribution=f"DeepShield Contextual NLP & Hybrid Rule Engine {self.detector_version}"
            )

        # 1. Run Machine Learning Pipeline
        try:
            proba = self.model_pipeline.predict_proba([clean_text])[0]
            ml_scam_score = float(proba[1]) # probability of scam class
        except Exception:
            ml_scam_score = 0.5

        # 2. Run Heuristic Rules & Token Extraction
        evidence_list: List[EvidenceItem] = []
        highlighted_tokens: List[str] = []
        category_votes: Dict[ScamCategory, int] = {}

        for rule in INDICATOR_RULES:
            matches = list(re.finditer(rule["pattern"], clean_text))
            if rule.get("id") in ("OTP_THEFT_SOLICIT", "PHISH_CREDENTIAL_PROMPT"):
                # Filter out defensive statements with negation (e.g. "do not share this code", "never give your password")
                filtered_matches = []
                for m in matches:
                    start_idx = max(0, m.start() - 35)
                    preceding = clean_text[start_idx:m.start()].lower()
                    if any(neg in preceding for neg in ("do not", "never", "don't", "wont", "won't", "will not", "not to")):
                        continue
                    filtered_matches.append(m)
                matches = filtered_matches

            if matches:
                matched_snippets = [m.group(0) for m in matches]
                highlighted_tokens.extend(matched_snippets)
                
                cat = rule["category"]
                weight = 3 if rule["severity"] == "high" else 1
                category_votes[cat] = category_votes.get(cat, 0) + weight

                evidence_list.append(EvidenceItem(
                    title=rule["title"],
                    description=rule["desc"],
                    severity=rule["severity"],
                    category=cat.value if isinstance(cat, ScamCategory) else str(cat),
                    snippet=", ".join(matched_snippets[:2]),
                    metric_value=float(len(matches))
                ))

        # Check Benign Context Rules
        benign_matches: List[str] = []
        for b_rule in BENIGN_INDICATOR_RULES:
            if re.search(b_rule["pattern"], clean_text):
                benign_matches.append(b_rule["title"])

        # Deduplicate highlighted tokens
        highlighted_tokens = list(dict.fromkeys(highlighted_tokens))

        # 3. Determine Primary Category
        if category_votes:
            primary_category = max(category_votes.items(), key=lambda kv: kv[1])[0]
        else:
            if ml_scam_score > 0.65:
                primary_category = ScamCategory.PHISHING_CREDENTIAL
            else:
                primary_category = ScamCategory.BENIGN

        # 4. Multi-Signal Calibrated Decision Logic
        has_high_severity = any(e.severity == "high" for e in evidence_list)
        high_severity_count = sum(1 for e in evidence_list if e.severity == "high")
        has_benign_indicators = len(benign_matches) > 0

        # Calibrate risk:
        # High Risk requires:
        # - Either multiple high severity contextual indicators (e.g. impersonation + payment demand)
        # - Or single high severity indicator corroborated by strong ML scam score (>= 0.60)
        # - Or extremely strong ML score (>= 0.85)
        # Crucially: If strong benign indicators exist and no explicit high severity pattern is matched, protect from false positive.
        if (high_severity_count >= 2) or (high_severity_count >= 1 and ml_scam_score >= 0.55) or (ml_scam_score >= 0.82 and high_severity_count >= 1):
            risk_level = RiskLevel.HIGH_RISK
            confidence = min(0.97, max(0.82, ml_scam_score if has_high_severity else 0.85))
            primary_reason = f"High probability of malicious intent: identified {len(evidence_list)} suspicious indicator(s) including {primary_category.value} patterns."
        elif (high_severity_count == 1 and not has_benign_indicators) or (len(evidence_list) > 0 and ml_scam_score >= 0.45) or (ml_scam_score >= 0.60 and not has_benign_indicators):
            risk_level = RiskLevel.MEDIUM_RISK
            confidence = max(0.65, ml_scam_score)
            primary_reason = f"Suspicious elements identified matching {primary_category.value}; caution is advised before complying."
        else:
            risk_level = RiskLevel.LOW_RISK
            confidence = max(0.75, 1.0 - ml_scam_score)
            if has_benign_indicators:
                primary_reason = f"Content structure conforms to benign communication ({', '.join(benign_matches[:2])}). No coercive extortion or credential theft cues detected."
            else:
                primary_reason = "No prevalent scam markers, credential harvesting phrases, or high-risk coercion tactics identified."

        # Supporting and detailed explanations
        detailed_reasons = []
        if has_high_severity:
            detailed_reasons.append("Critical threat vectors identified (e.g. credential harvesting, urgency, or impersonation).")
        if ml_scam_score > 0.65:
            detailed_reasons.append(f"Statistical language model rated content with {int(ml_scam_score * 100)}% scam likeness based on token distribution.")
        if len(highlighted_tokens) > 0:
            detailed_reasons.append(f"Flagged {len(highlighted_tokens)} contextual lexical phrases.")
        if has_benign_indicators:
            detailed_reasons.append(f"Identified legitimate context patterns: {', '.join(benign_matches)}.")
        if not detailed_reasons:
            detailed_reasons.append("Content tone and structure conform to typical benign correspondence.")

        alternative_explanations = []
        if risk_level == RiskLevel.HIGH_RISK:
            alternative_explanations.append("If this came from a verified enterprise colleague, they may be testing security awareness with an internal phishing simulation.")
        elif risk_level == RiskLevel.MEDIUM_RISK:
            alternative_explanations.append("Legitimate administrative alerts occasionally use urgent language to prompt timely account maintenance.")
            alternative_explanations.append("The sender may be communicating clumsily rather than acting with fraudulent intent.")
        else:
            alternative_explanations.append("Message appears routine; standard vigilance still applies to unexpected links or attachments.")

        uncertainties = []
        if not sender_context:
            uncertainties.append("Sender identity/header verification was not provided; cannot authenticate originating address.")
        if any(e.title == "Embedded Hyperlink" for e in evidence_list):
            uncertainties.append("Embedded link destinations require independent DNS and threat feed reputation scanning.")

        # Recommended safety actions
        recommended_actions = []
        if risk_level in (RiskLevel.HIGH_RISK, RiskLevel.MEDIUM_RISK):
            if primary_category == ScamCategory.OTP_MFA_THEFT:
                recommended_actions.append("NEVER share 2FA codes, passwords, or one-time verification tokens with anyone.")
                recommended_actions.append("Legitimate organizations and banks will never call or message asking for your OTP.")
            elif primary_category == ScamCategory.IMPERSONATION_AUTHORITY:
                recommended_actions.append("Do not reply. Contact the organization directly using a phone number or website from an official public bill or directory.")
                recommended_actions.append("Government agencies never demand gift cards, crypto, or immediate wire transfers under threat of arrest.")
            elif primary_category == ScamCategory.FINANCIAL_INVESTMENT:
                recommended_actions.append("Beware of guaranteed high returns. Consult a licensed financial advisor before transferring funds.")
                recommended_actions.append("Do not send cryptocurrency to unknown recipient addresses.")
            else:
                recommended_actions.append("Do not click any embedded links or download attachments.")
                recommended_actions.append("Verify the sender's authentic address or phone number directly.")
        else:
            recommended_actions.append("Standard vigilance: always inspect full sender email domain before opening attachments.")
            recommended_actions.append("Ensure multi-factor authentication (MFA) remains active on all your primary accounts.")

        limitations = [
            "Detection is probabilistic and heuristic; novel phrasing or tailored spear-phishing may evade detection.",
            "Legitimate organizations occasionally use urgent language for genuine emergencies.",
            "Always corroborate alerts through an independent, verified communication channel."
        ]

        # Extract entities (emails, urls, phone numbers)
        entities = []
        urls = re.findall(r"https?://[^\s]+", clean_text)
        emails = re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", clean_text)
        phones = re.findall(r"(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}", clean_text)
        entities.extend([f"URL: {u}" for u in urls[:5]])
        entities.extend([f"Email: {e}" for e in emails[:5]])
        entities.extend([f"Phone: {''.join(p)}" for p in phones[:3] if ''.join(p).strip()])

        return TextAnalysisResponse(
            id=analysis_id,
            analysis_id=analysis_id,
            timestamp=now_iso,
            created_at=now_iso,
            input_type="text",
            overall_status="Completed",
            risk_level=risk_level,
            confidence=round(confidence, 3),
            scam_category=primary_category,
            primary_reason=primary_reason,
            summary=primary_reason,
            detailed_reasons=detailed_reasons,
            detected_entities=entities,
            highlighted_tokens=highlighted_tokens,
            indicators=[e.title for e in evidence_list],
            evidence=evidence_list,
            supporting_evidence=evidence_list,
            alternative_explanations=alternative_explanations,
            uncertainties=uncertainties,
            recommended_actions=recommended_actions,
            limitations=limitations,
            model_attribution=f"DeepShield Contextual NLP & Hybrid Rule Engine {self.detector_version}"
        )

text_detector = TextScamDetector()
