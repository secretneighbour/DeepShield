import math
import re
import uuid
import idna
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, List, Any, Tuple, Optional

from app.models.schemas import RiskLevel, EvidenceItem, URLAnalysisResponse
from app.utils.security import is_ssrf_safe_url
from app.services.threat_intel import threat_intel_service

# Suspicious TLDs with elevated abuse rates in phishing intelligence feeds
SUSPICIOUS_TLDS = {
    "top", "xyz", "club", "buzz", "click", "fit", "work", "rest", "icu",
    "tk", "ml", "ga", "cf", "gq", "loan", "men", "country", "stream"
}

# Common multi-part / compound public suffixes
COMPOUND_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "ltd.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "nic.in", "gov.in", "ac.in", "edu.in", "res.in",
    "com.br", "net.br", "org.br", "gov.br",
    "com.mx", "org.mx", "edu.mx", "gob.mx",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp", "ed.jp", "ad.jp",
    "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg",
    "co.za", "org.za", "web.za", "net.za", "gov.za",
    "com.tr", "edu.tr", "gov.tr", "org.tr",
    "com.cn", "net.cn", "org.cn", "gov.cn"
}

# Major targeted brand keywords
TARGETED_BRANDS = [
    "paypal", "apple", "google", "microsoft", "chase", "wellsfargo",
    "bankofamerica", "amazon", "netflix", "fedex", "usps", "binance",
    "coinbase", "metamask", "whatsapp", "telegram", "facebook", "instagram"
]

# Legitimate official domain mapping for targeted brands
OFFICIAL_BRAND_DOMAINS = {
    "paypal": ["paypal.com", "paypal.me"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com", "google.co.uk", "google.co.in"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com"],
    "chase": ["chase.com", "jpmorganchase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "aws.amazon.com"],
    "netflix": ["netflix.com"],
    "fedex": ["fedex.com"],
    "usps": ["usps.com"],
    "binance": ["binance.com", "binance.us"],
    "coinbase": ["coinbase.com"],
    "metamask": ["metamask.io"],
    "whatsapp": ["whatsapp.com"],
    "telegram": ["telegram.org", "t.me"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"]
}

# Phishing deceptive tokens commonly used in malicious paths/subdomains
PHISHING_KEYWORDS = [
    "login", "verify", "verification", "secure", "security", "update", "recovery",
    "dispute", "resolution", "account", "suspended", "wallet", "signin", "auth",
    "validate", "portal", "confirm", "passcode", "support", "billing", "re-activate"
]

# Common query parameters used in open redirects
REDIRECT_PARAM_NAMES = {
    "url", "redirect", "redirect_url", "redirect_uri", "dest", "destination",
    "target", "link", "next", "return_to", "return", "forward", "to", "go", "out"
}

# Homoglyph character mapping (Cyrillic, Greek lookalikes to Latin)
HOMOGLYPH_MAP = {
    '\u0430': 'a', # Cyrillic small letter a
    '\u0435': 'e', # Cyrillic small letter ie
    '\u043e': 'o', # Cyrillic small letter o
    '\u0440': 'p', # Cyrillic small letter er
    '\u0441': 'c', # Cyrillic small letter es
    '\u0443': 'y', # Cyrillic small letter u
    '\u0445': 'x', # Cyrillic small letter ha
    '\u0456': 'i', # Cyrillic small letter byelorussian-ukrainian i
    '\u0458': 'j', # Cyrillic small letter je
    '\u03bf': 'o', # Greek small letter omicron
    '\u03bd': 'v', # Greek small letter nu
    '\u0455': 's', # Cyrillic small letter dze
    '\u045d': 'i', # Cyrillic small letter i with grave
}

def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def split_domain_components(hostname: str) -> Tuple[str, str, str, str]:
    """
    Standards-compliant breakdown of hostname into (subdomain, main_domain, tld, registered_domain).
    Handles single TLDs (e.g. .com) and compound public suffixes (e.g. .co.uk, .com.au).
    """
    if not hostname:
        return "", "", "", ""
    
    parts = hostname.split(".")
    if len(parts) == 1:
        return "", parts[0], "", parts[0]
    
    # Check for compound public suffix
    if len(parts) >= 3:
        potential_compound = f"{parts[-2]}.{parts[-1]}"
        if potential_compound in COMPOUND_TLDS:
            tld = potential_compound
            main_domain = parts[-3]
            registered_domain = f"{main_domain}.{tld}"
            subdomain = ".".join(parts[:-3])
            return subdomain, main_domain, tld, registered_domain

    tld = parts[-1]
    main_domain = parts[-2]
    registered_domain = f"{main_domain}.{tld}"
    subdomain = ".".join(parts[:-2])
    return subdomain, main_domain, tld, registered_domain

class URLDetector:
    async def analyze(self, raw_url: str, check_threat_intel: bool = True) -> URLAnalysisResponse:
        analysis_id = f"url_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.now(timezone.utc).isoformat()

        if not raw_url or not raw_url.strip():
            return URLAnalysisResponse(
                id=analysis_id,
                timestamp=now_iso,
                url=raw_url or "",
                normalized_url="",
                risk_level=RiskLevel.INCONCLUSIVE,
                confidence=0.5,
                is_ip_address=False,
                has_homoglyphs=False,
                homoglyph_details=[],
                suspicious_tokens=[],
                domain_entropy=0.0,
                structure={"error": "Empty URL input provided"},
                threat_intel_result={"verdict": "SKIPPED", "reason": "Empty URL"},
                evidence=[EvidenceItem(
                    title="Empty Input",
                    description="No URL was provided to analyze.",
                    severity="info",
                    category="Input Validation"
                )],
                recommended_actions=["Provide a valid web URL or hostname to analyze."],
                limitations=["Cannot evaluate empty input."]
            )

        url = raw_url.strip()
        has_explicit_scheme = url.startswith(("http://", "https://"))
        if not has_explicit_scheme:
            url = f"https://{url}"

        # 1. SSRF Safety Check
        is_safe, ssrf_msg = is_ssrf_safe_url(url)
        if not is_safe:
            return URLAnalysisResponse(
                id=analysis_id,
                timestamp=now_iso,
                url=raw_url,
                normalized_url=url,
                risk_level=RiskLevel.HIGH_RISK,
                confidence=0.99,
                is_ip_address=True,
                has_homoglyphs=False,
                homoglyph_details=[],
                suspicious_tokens=["SSRF_BLOCKED_TARGET"],
                domain_entropy=0.0,
                structure={"error": ssrf_msg},
                threat_intel_result={"verdict": "BLOCKED", "reason": ssrf_msg},
                evidence=[EvidenceItem(
                    title="SSRF Violation Blocked",
                    description=f"Destination targets a restricted private network, loopback, or metadata address: {ssrf_msg}",
                    severity="high",
                    category="Network Security",
                    snippet=url
                )],
                recommended_actions=["Immediately discontinue connection. Do not target internal networks or private IP spaces."],
                limitations=["Requests to private addresses are blocked to prevent internal network scanning."]
            )

        try:
            parsed = urlparse(url)
            netloc = parsed.netloc or ""
            hostname = (parsed.hostname or "").lower()
            path = parsed.path or ""
            query = parsed.query or ""
        except Exception as e:
            return URLAnalysisResponse(
                id=analysis_id,
                timestamp=now_iso,
                url=raw_url,
                normalized_url=url,
                risk_level=RiskLevel.INCONCLUSIVE,
                confidence=0.5,
                is_ip_address=False,
                has_homoglyphs=False,
                homoglyph_details=[],
                suspicious_tokens=[],
                domain_entropy=0.0,
                structure={"error": f"Failed to parse URL: {str(e)}"},
                threat_intel_result={"verdict": "SKIPPED", "reason": "Malformed URL"},
                evidence=[EvidenceItem(
                    title="Malformed URL Structure",
                    description=f"Standard URL parser failed to decode destination: {str(e)}",
                    severity="medium",
                    category="Structural Anomaly"
                )],
                recommended_actions=["Check the URL for syntax errors or invalid percent-encodings."],
                limitations=["Malformed URL cannot be reliably mapped to DNS infrastructure."]
            )

        if not hostname:
            return URLAnalysisResponse(
                id=analysis_id,
                timestamp=now_iso,
                url=raw_url,
                normalized_url=url,
                risk_level=RiskLevel.INCONCLUSIVE,
                confidence=0.5,
                is_ip_address=False,
                has_homoglyphs=False,
                homoglyph_details=[],
                suspicious_tokens=[],
                domain_entropy=0.0,
                structure={"error": "No valid hostname extracted"},
                threat_intel_result={"verdict": "SKIPPED", "reason": "Missing hostname"},
                evidence=[EvidenceItem(
                    title="Missing Hostname",
                    description="Could not identify a valid domain name or IP address in the provided input.",
                    severity="medium",
                    category="Structural Anomaly"
                )],
                recommended_actions=["Ensure the URL includes a valid host (e.g., example.com)."],
                limitations=["No hostname to assess."]
            )

        # 2. Decompose Domain Components (Supporting compound TLDs like .co.uk)
        subdomain, main_domain, tld, registered_domain = split_domain_components(hostname)

        structure = {
            "scheme": parsed.scheme,
            "hostname": hostname,
            "subdomain": subdomain,
            "main_domain": main_domain,
            "tld": tld,
            "registered_domain": registered_domain,
            "path": path,
            "query": query,
            "port": parsed.port
        }

        evidence_list: List[EvidenceItem] = []
        suspicious_tokens: List[str] = []
        risk_points = 0.0

        # 3. Check for Deceptive URL Delimiters and Userinfo Spoofing (e.g., https://paypal.com@evil.com)
        if "@" in netloc:
            userinfo = netloc.split("@")[0]
            evidence_list.append(EvidenceItem(
                title="Deceptive Authority Userinfo (@ Delimiter)",
                description=f"URL uses userinfo authority delimiter '@' ({userinfo}@...). Browsers navigate to '{hostname}', while the preceding string is used to mislead victims into seeing a trusted entity.",
                severity="high",
                category="Deceptive Identity",
                snippet=netloc
            ))
            suspicious_tokens.append(f"userinfo_spoof:{userinfo}")
            risk_points += 40.0

        if "\\" in netloc or "%5c" in raw_url.lower():
            evidence_list.append(EvidenceItem(
                title="Ambiguous Backslash in Authority",
                description="URL contains backslashes ('\\') in the authority segment, an evasion technique used to bypass poorly implemented URL filters.",
                severity="high",
                category="Evasion Technique",
                snippet=raw_url
            ))
            risk_points += 25.0

        # 4. Check for Direct IP Hostname
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname))
        if is_ip:
            # Note: Direct IP is an anomaly signal, but per instructions, do not flag as HIGH_RISK on its own
            evidence_list.append(EvidenceItem(
                title="Direct IP Address Hostname",
                description="Destination uses a naked IP address instead of a registered domain name. While common in internal/embedded testing, public services standardly use domain names.",
                severity="low",
                category="Structural Anomaly",
                snippet=hostname
            ))
            suspicious_tokens.append(hostname)
            risk_points += 10.0

        # 5. Homoglyph / Punycode / Unicode Evasion Detection
        has_homoglyphs = False
        homoglyph_details = []

        if hostname.startswith("xn--") or ".xn--" in hostname:
            has_homoglyphs = True
            try:
                decoded_idn = idna.decode(hostname)
                detail_str = f"Punycode '{hostname}' decodes to Unicode: '{decoded_idn}'"
            except Exception:
                detail_str = f"Punycode internationalized domain name: {hostname}"
            homoglyph_details.append(detail_str)
            evidence_list.append(EvidenceItem(
                title="Punycode / IDN Domain Detected",
                description="Domain utilizes Punycode encoding (xn-- prefix), a frequent vehicle for visual lookalike spoofing attacks.",
                severity="high",
                category="Deceptive Identity",
                snippet=detail_str
            ))
            risk_points += 35.0

        for char in raw_url:
            if char in HOMOGLYPH_MAP:
                has_homoglyphs = True
                detail = f"Lookalike glyph '{char}' (U+{ord(char):04X}) mimicking Latin '{HOMOGLYPH_MAP[char]}'"
                if detail not in homoglyph_details:
                    homoglyph_details.append(detail)

        # Check for invisible / directional control characters
        invisible_chars = {'\u200b': "Zero-width space", '\u200c': "Zero-width non-joiner", '\u202e': "Right-to-left override"}
        for ch, name in invisible_chars.items():
            if ch in raw_url:
                has_homoglyphs = True
                homoglyph_details.append(f"Hidden Unicode character: {name} (U+{ord(ch):04X})")

        if has_homoglyphs and not any(e.title.startswith("Punycode") for e in evidence_list):
            evidence_list.append(EvidenceItem(
                title="Homoglyph Spoofing Detected",
                description=f"Identified {len(homoglyph_details)} non-Latin or control glyphs masquerading as familiar characters.",
                severity="high",
                category="Deceptive Identity",
                snippet=", ".join(homoglyph_details[:3])
            ))
            risk_points += 35.0

        # 6. Misleading Subdomains & Brand Lookalike Analysis
        for brand in TARGETED_BRANDS:
            brand_official_domains = OFFICIAL_BRAND_DOMAINS.get(brand, [f"{brand}.com"])
            # Exact brand match on registered domain (e.g. paypal.com, paypal.co.uk)
            is_legit_brand_domain = (main_domain == brand) or any(
                registered_domain == off or registered_domain.endswith(f".{off}")
                for off in brand_official_domains
            )

            # Scenario A: Brand in Subdomain on an unrelated root domain
            # e.g. chase.com.security-verify.net or paypal.billing-update.xyz
            if brand in subdomain and not is_legit_brand_domain:
                evidence_list.append(EvidenceItem(
                    title=f"Deceptive Subdomain Impersonation ({brand.upper()})",
                    description=f"Subdomain contains recognized brand keyword '{brand}', but the actual registered destination is '{registered_domain}'. This pattern is intentionally designed to deceive victims.",
                    severity="high",
                    category="Impersonation",
                    snippet=f"{subdomain} -> {registered_domain}"
                ))
                suspicious_tokens.append(f"subdomain_spoof:{brand}")
                risk_points += 40.0

            # Scenario B: Lookalike / Hyphenated main domain
            # e.g. chase-security-update.com or paypa1-auth.net (main_domain contains brand but is not brand)
            elif brand in main_domain and main_domain != brand and not is_legit_brand_domain:
                evidence_list.append(EvidenceItem(
                    title=f"Brand Lookalike Domain ({brand.upper()})",
                    description=f"Registered domain '{registered_domain}' incorporates brand name '{brand}' in an unauthorized permutation.",
                    severity="high",
                    category="Impersonation",
                    snippet=registered_domain
                ))
                suspicious_tokens.append(f"brand_lookalike:{brand}")
                risk_points += 35.0

        # 7. Lexical Phishing Tokens
        found_keywords = set()
        for kw in PHISHING_KEYWORDS:
            if kw in hostname or kw in path.lower():
                found_keywords.add(kw)

        if len(found_keywords) >= 2:
            unique_tokens = sorted(list(found_keywords))
            evidence_list.append(EvidenceItem(
                title="Clustered Phishing Keywords",
                description=f"Identified clustered high-risk tokens typically employed to engineer urgency or lure credentials: {', '.join(unique_tokens[:5])}",
                severity="medium",
                category="Lexical Heuristics",
                snippet=", ".join(unique_tokens[:4])
            ))
            suspicious_tokens.extend(list(found_keywords))
            risk_points += 15.0
        elif len(found_keywords) == 1:
            suspicious_tokens.extend(list(found_keywords))
            risk_points += 5.0

        # 8. Nested Open Redirect Parameters
        if query:
            try:
                parsed_params = parse_qs(query)
                for param, values in parsed_params.items():
                    if param.lower() in REDIRECT_PARAM_NAMES:
                        for val in values:
                            decoded_val = unquote(val).strip()
                            if decoded_val.startswith(("http://", "https://", "//")):
                                evidence_list.append(EvidenceItem(
                                    title=f"Nested Redirect Parameter ('{param}')",
                                    description=f"URL contains a forward/redirect query parameter '{param}' pointing to external destination '{decoded_val[:60]}...'. Often exploited in open-redirect phishing lures.",
                                    severity="medium",
                                    category="Open Redirect Risk",
                                    snippet=f"{param}={decoded_val[:50]}"
                                ))
                                risk_points += 15.0
                                break
            except Exception:
                pass

        # 9. Suspicious TLD Check
        if tld in SUSPICIOUS_TLDS:
            evidence_list.append(EvidenceItem(
                title=f"High-Abuse Top-Level Domain (.{tld})",
                description=f"Top-level domain '.{tld}' exhibits elevated historical abuse rates in phishing campaigns.",
                severity="medium",
                category="Domain Reputation",
                snippet=f".{tld}"
            ))
            risk_points += 15.0

        # 10. Shannon Entropy Analysis
        entropy = calculate_shannon_entropy(main_domain)
        if entropy > 3.9 and len(main_domain) > 10 and not is_ip:
            evidence_list.append(EvidenceItem(
                title="High Domain Name Entropy",
                description=f"Shannon entropy of '{main_domain}' is {entropy:.2f}, indicating algorithmic randomness typical of Domain Generation Algorithms (DGA) or disposable throwaway domains.",
                severity="low",
                category="Domain Obfuscation",
                metric_value=entropy
            ))
            risk_points += 10.0

        # 11. Cleartext HTTP Transport Notice
        if parsed.scheme == "http" and not is_ip:
            evidence_list.append(EvidenceItem(
                title="Cleartext HTTP Transport",
                description="URL specifies unencrypted HTTP transport. While some benign sites still serve HTTP, credentials entered here can be intercepted.",
                severity="low",
                category="Transport Security",
                snippet="http://"
            ))
            risk_points += 5.0

        # 12. Threat Intelligence Check (Optional & Configurable)
        threat_intel_result = {"verdict": "SKIPPED", "is_flagged": False}
        if check_threat_intel:
            threat_intel_result = await threat_intel_service.check_url_reputation(url, hostname)
            if threat_intel_result.get("is_flagged"):
                evidence_list.append(EvidenceItem(
                    title="Threat Intelligence Blacklist Match",
                    description=f"Flagged by threat intelligence: {threat_intel_result.get('details', 'Active malicious indicator')}",
                    severity="high",
                    category="Threat Intelligence",
                    snippet=threat_intel_result.get("provider_attribution")
                ))
                risk_points += 60.0

        # 13. Decouple Risk Severity from Confidence
        # Risk Severity reflects evaluated threat potential based on weighted evidence
        if threat_intel_result.get("is_flagged") or risk_points >= 45.0:
            risk_level = RiskLevel.HIGH_RISK
        elif risk_points >= 20.0:
            risk_level = RiskLevel.MEDIUM_RISK
        else:
            risk_level = RiskLevel.LOW_RISK

        # Confidence reflects how unambiguous and corroborated the evidence is
        if threat_intel_result.get("is_flagged"):
            confidence = 0.98
        elif risk_points >= 55.0:
            confidence = 0.94
        elif risk_points >= 40.0:
            confidence = 0.88
        elif risk_points >= 20.0:
            # Medium risk has more ambiguity; confidence reflects heuristic nature
            confidence = 0.72
        else:
            # Clean domain without any suspicious markers
            confidence = 0.90

        # Clean check evidence item if no suspicious indicators found
        if not evidence_list:
            evidence_list.append(EvidenceItem(
                title="Standard URL Structure",
                description="Hostname, path, and authority structure conform to normal conventions with no observed brand spoofing or homoglyph anomalies.",
                severity="info",
                category="Integrity Check"
            ))

        # Contextual Recommendations
        recommended_actions = []
        if risk_level == RiskLevel.HIGH_RISK:
            recommended_actions.append("DO NOT visit this URL or submit credentials/passwords.")
            recommended_actions.append("Block the domain or host on organizational firewalls and secure DNS resolvers.")
            recommended_actions.append("If credentials were submitted, immediately reset your password on the authentic service.")
        elif risk_level == RiskLevel.MEDIUM_RISK:
            recommended_actions.append("Proceed with caution. Independently verify the destination domain via bookmarks or search.")
            recommended_actions.append("Inspect the SSL/TLS certificate details before interacting with login forms.")
        else:
            recommended_actions.append("No obvious phishing indicators found. Standard browsing vigilance applies.")

        limitations = [
            "Newly registered zero-day phishing domains may not yet be catalogued on external reputation lists.",
            "HTTPS encrypts communication in transit but does NOT guarantee domain authenticity or safe content.",
            "Lexical inspection does not substitute for real-time sandbox detonation or certificate transparency logs.",
            "Threat intelligence coverage depends on configured external provider API keys."
        ]

        return URLAnalysisResponse(
            id=analysis_id,
            analysis_id=analysis_id,
            timestamp=now_iso,
            url=raw_url,
            normalized_url=url,
            risk_level=risk_level,
            confidence=round(confidence, 3),
            is_ip_address=is_ip,
            has_homoglyphs=has_homoglyphs,
            homoglyph_details=homoglyph_details,
            suspicious_tokens=list(set(suspicious_tokens)),
            domain_entropy=entropy,
            structure=structure,
            threat_intel_result=threat_intel_result,
            evidence=evidence_list,
            recommended_actions=recommended_actions,
            limitations=limitations
        )

url_detector = URLDetector()
