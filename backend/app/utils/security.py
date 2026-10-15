import ipaddress
import socket
import time
from urllib.parse import urlparse
from typing import Dict, Tuple, Optional

# Magic byte signatures for supported media formats
MAGIC_NUMBERS: Dict[str, list[bytes]] = {
    "image/jpeg": [b"\xff\xd8\xff"],
    "image/png": [b"\x89PNG\r\n\x1a\n"],
    "image/webp": [b"RIFF"], # followed by WEBP
    "video/mp4": [b"\x00\x00\x00\x18ftyp", b"\x00\x00\x00\x1cftyp", b"\x00\x00\x00\x20ftyp"],
    "video/webm": [b"\x1a\x45\xdf\xa3"], # EBML header
    "audio/wav": [b"RIFF"], # followed by WAVE
    "audio/mpeg": [b"\xff\xfb", b"\xff\xf3", b"\xff\xf2", b"ID3"],
}

# Blocked IP networks for SSRF prevention
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
]

def validate_file_signature(content: bytes, declared_mime: str) -> Tuple[bool, str]:
    """Validate that the file header matches its declared MIME type using magic bytes."""
    if len(content) < 4:
        return False, "File is too small to contain valid media headers"

    # Specific checks
    if declared_mime.startswith("image/jpeg") or declared_mime == "image/jpg":
        if content[:3] == b"\xff\xd8\xff":
            return True, "image/jpeg"
    elif declared_mime == "image/png":
        if content[:8] == b"\x89PNG\r\n\x1a\n":
            return True, "image/png"
    elif declared_mime == "image/webp":
        if content[:4] == b"RIFF" and len(content) >= 12 and content[8:12] == b"WEBP":
            return True, "image/webp"
    elif declared_mime in ("video/mp4", "video/quicktime"):
        if b"ftyp" in content[:32]:
            return True, "video/mp4"
    elif declared_mime in ("video/webm", "video/x-matroska"):
        if content[:4] == b"\x1a\x45\xdf\xa3":
            return True, "video/webm"
    elif declared_mime in ("audio/wav", "audio/x-wav"):
        if content[:4] == b"RIFF" and len(content) >= 12 and content[8:12] == b"WAVE":
            return True, "audio/wav"
    elif declared_mime in ("audio/mpeg", "audio/mp3"):
        if content[:3] == b"ID3" or (len(content) >= 2 and content[0] == 0xff and (content[1] & 0xe0) == 0xe0):
            return True, "audio/mpeg"

    # Fallback inspection across all signatures
    if content[:3] == b"\xff\xd8\xff":
        return True, "image/jpeg"
    if content[:8] == b"\x89PNG\r\n\x1a\n":
        return True, "image/png"
    if content[:4] == b"RIFF" and len(content) >= 12:
        if content[8:12] == b"WEBP":
            return True, "image/webp"
        if content[8:12] == b"WAVE":
            return True, "audio/wav"
    if b"ftyp" in content[:32]:
        return True, "video/mp4"

    return False, f"Invalid or mismatched file header for MIME type {declared_mime}"

def is_ssrf_safe_url(url: str) -> Tuple[bool, str]:
    """Ensure URL does not target loopback, private networks, or metadata endpoints."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False, f"Unsupported scheme '{parsed.scheme}'. Only http and https are allowed."
        
        hostname = parsed.hostname
        if not hostname:
            return False, "Invalid or missing hostname in URL"
        
        # Check if hostname directly represents an IP
        try:
            ip = ipaddress.ip_address(hostname)
            for net in BLOCKED_NETWORKS:
                if ip in net:
                    return False, f"Access to IP {ip} is blocked (private or internal network)"
            return True, "Safe"
        except ValueError:
            # Hostname is a domain name, resolve DNS
            pass

        # Resolve domain to IP addresses
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            for item in addr_info:
                sockaddr = item[4]
                ip_str = sockaddr[0]
                ip = ipaddress.ip_address(ip_str)
                for net in BLOCKED_NETWORKS:
                    if ip in net:
                        return False, f"Domain {hostname} resolves to blocked internal IP {ip_str}"
        except socket.gaierror:
            # Could not resolve; allow URL analysis to proceed offline/lexically
            return True, "Domain could not be resolved, proceeding with offline lexical analysis"

        return True, "Safe"
    except Exception as e:
        return False, f"URL validation error: {str(e)}"

class SimpleRateLimiter:
    """Sliding window in-memory rate limiter per client IP."""
    def __init__(self, limit: int = 60, window: int = 60):
        self.limit = limit
        self.window = window
        self.requests: Dict[str, list[float]] = {}

    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        timestamps = self.requests.get(client_ip, [])
        # Prune old timestamps
        timestamps = [ts for ts in timestamps if now - ts < self.window]
        if len(timestamps) >= self.limit:
            self.requests[client_ip] = timestamps
            return False
        timestamps.append(now)
        self.requests[client_ip] = timestamps
        return True

rate_limiter = SimpleRateLimiter(limit=120, window=60)
