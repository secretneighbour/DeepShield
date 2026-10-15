import os
from pathlib import Path
from pydantic import BaseModel

# Automatically load .env if present
env_file = Path(__file__).resolve().parents[2] / ".env"
if env_file.exists():
    try:
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k:
                        os.environ[k] = v
    except Exception:
        pass

class Settings(BaseModel):
    APP_NAME: str = "DeepShield"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    API_PREFIX: str = "/api"
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./scamshield.db")
    DB_PATH: str = os.getenv("DB_PATH", "scamshield.db")
    MAX_UPLOAD_SIZE_MB: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "50"))
    MAX_TEXT_LENGTH: int = int(os.getenv("MAX_TEXT_LENGTH", "10000"))
    ENABLE_ZERO_RETENTION: bool = os.getenv("ENABLE_ZERO_RETENTION", "false").lower() == "true"
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))
    ALLOWED_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]
    ALLOWED_ORIGIN_REGEX: str = os.getenv(
        "ALLOWED_ORIGIN_REGEX",
        r"^https?://([a-zA-Z0-9-]+\.)*(ngrok-free\.app|ngrok\.app|ngrok\.io|localhost)(:\d+)?$"
    )
    # Threat Intel API keys (optional)
    SAFE_BROWSING_API_KEY: str = os.getenv("SAFE_BROWSING_API_KEY", "")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")

    # Stage 1: Local LLM Configuration (Ollama)
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "gemma3:4b")
    OLLAMA_TIMEOUT_SECONDS: int = int(os.getenv("OLLAMA_TIMEOUT_SECONDS", "4"))

    # Stage 2: Cloud LLM Reviewer Configuration (Gemini)
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    GEMINI_TIMEOUT_SECONDS: int = int(os.getenv("GEMINI_TIMEOUT_SECONDS", "4"))
    GEMINI_MAX_OUTPUT_TOKENS: int = int(os.getenv("GEMINI_MAX_OUTPUT_TOKENS", "8192"))

    # Administrative server policy control
    LLM_CLOUD_ENABLED: bool = os.getenv("LLM_CLOUD_ENABLED", "true").lower() == "true"

    # Ngrok and Laptop reverse proxy settings
    NGROK_DOMAIN: str = os.getenv("NGROK_DOMAIN", "")
    NGROK_PORT: int = int(os.getenv("NGROK_PORT", "5173"))
    NGROK_API_URL: str = os.getenv("NGROK_API_URL", "http://127.0.0.1:4040/api/tunnels")

    # Optional backend authentication key (if set, protected routes require X-API-Key or Bearer token)
    BACKEND_API_KEY: str = os.getenv("BACKEND_API_KEY", "")

settings = Settings()
if settings.NGROK_DOMAIN:
    domain_url = f"https://{settings.NGROK_DOMAIN.lstrip('https://').lstrip('http://')}"
    if domain_url not in settings.ALLOWED_ORIGINS:
        settings.ALLOWED_ORIGINS.append(domain_url)

