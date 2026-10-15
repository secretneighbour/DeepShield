import sqlite3
import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any, Tuple
from app.config import settings

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(settings.DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for high concurrency
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analyses (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        analysis_type TEXT NOT NULL,
        target_summary TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        confidence REAL NOT NULL,
        category_or_detail TEXT NOT NULL,
        full_result_json TEXT NOT NULL
    );
    """)
    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_analyses_type ON analyses(analysis_type);
    """)
    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_analyses_timestamp ON analyses(timestamp);
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        ip_hash TEXT NOT NULL,
        details TEXT NOT NULL
    );
    """)
    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS app_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """)
    # Default cloud analysis to true if not already set
    cursor.execute("""
    INSERT OR IGNORE INTO app_settings (key, value, updated_at)
    VALUES ('cloud_analysis_enabled', 'true', datetime('now'))
    """)

    # Phase 2: Persistent User Feedback table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS feedbacks (
        id TEXT PRIMARY KEY,
        analysis_id TEXT,
        detection_module TEXT NOT NULL,
        predicted_verdict TEXT,
        predicted_risk_level TEXT,
        user_correction TEXT NOT NULL,
        corrected_risk_level TEXT,
        explanation TEXT,
        target_content TEXT,
        feedback_source TEXT NOT NULL DEFAULT 'user_web',
        review_status TEXT NOT NULL DEFAULT 'pending',
        reviewer_notes TEXT,
        detector_version TEXT NOT NULL DEFAULT 'v1.2.0',
        dataset_eligible INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """)
    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_feedbacks_module ON feedbacks(detection_module);
    """)
    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_feedbacks_status ON feedbacks(review_status);
    """)
    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_feedbacks_analysis_id ON feedbacks(analysis_id);
    """)
    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_feedbacks_created_at ON feedbacks(created_at);
    """)

    conn.commit()
    conn.close()

def get_setting(key: str, default: str = "") -> str:
    conn = get_db_connection()
    try:
        cursor = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row["value"] if row else default
    finally:
        conn.close()

def set_setting(key: str, value: str) -> None:
    conn = get_db_connection()
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT INTO app_settings (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, str(value), now_iso)
        )
        conn.commit()
    finally:
        conn.close()

def save_analysis(
    analysis_id: str,
    analysis_type: str,
    target_summary: str,
    risk_level: str,
    confidence: float,
    category_or_detail: str,
    full_result: Dict[str, Any]
) -> bool:
    if settings.ENABLE_ZERO_RETENTION:
        # Zero retention mode is active: do not persist to database
        return True
    
    conn = get_db_connection()
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT INTO analyses (id, timestamp, analysis_type, target_summary, risk_level, confidence, category_or_detail, full_result_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                analysis_id,
                now_iso,
                analysis_type,
                target_summary[:250],
                risk_level,
                float(confidence),
                category_or_detail[:150],
                json.dumps(full_result)
            )
        )
        conn.commit()
        return True
    finally:
        conn.close()

def get_analyses(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            """
            SELECT id, timestamp, analysis_type, target_summary, risk_level, confidence, category_or_detail
            FROM analyses
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset)
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

def get_analysis_by_id(analysis_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "SELECT full_result_json FROM analyses WHERE id = ?",
            (analysis_id,)
        )
        row = cursor.fetchone()
        if row:
            return json.loads(row["full_result_json"])
        return None
    finally:
        conn.close()

def delete_analysis(analysis_id: str) -> bool:
    conn = get_db_connection()
    try:
        cursor = conn.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()

def clear_all_analyses() -> int:
    conn = get_db_connection()
    try:
        cursor = conn.execute("DELETE FROM analyses")
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()

def get_stats() -> Dict[str, Any]:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM analyses")
        total = cursor.fetchone()["count"]

        cursor.execute("SELECT analysis_type, COUNT(*) as count FROM analyses GROUP BY analysis_type")
        by_type = {row["analysis_type"]: row["count"] for row in cursor.fetchall()}

        cursor.execute("SELECT risk_level, COUNT(*) as count FROM analyses GROUP BY risk_level")
        by_risk = {row["risk_level"]: row["count"] for row in cursor.fetchall()}

        cursor.execute("SELECT timestamp FROM analyses ORDER BY timestamp DESC LIMIT 1")
        last_row = cursor.fetchone()
        last_ts = last_row["timestamp"] if last_row else None

        return {
            "total_analyses": total,
            "by_type": by_type,
            "by_risk": by_risk,
            "high_risk_count": by_risk.get("HIGH_RISK", 0),
            "last_analysis_timestamp": last_ts
        }
    finally:
        conn.close()

# --- Feedback Subsystem Operations ---

def create_feedback(feedback_data: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    """
    Persist user feedback with duplicate protection.
    Returns (record_dict, is_duplicate).
    """
    conn = get_db_connection()
    try:
        analysis_id = feedback_data.get("analysis_id")
        user_corr = feedback_data.get("user_correction", "")
        detection_module = feedback_data.get("detection_module", "text")
        
        # Check duplicate submission: same analysis_id and correction within last 300 seconds
        if analysis_id:
            cur = conn.execute(
                """
                SELECT id, analysis_id, detection_module, predicted_verdict, predicted_risk_level,
                       user_correction, corrected_risk_level, explanation, feedback_source,
                       review_status, reviewer_notes, detector_version, dataset_eligible,
                       created_at, updated_at
                FROM feedbacks
                WHERE analysis_id = ? AND user_correction = ?
                ORDER BY created_at DESC LIMIT 1
                """,
                (analysis_id, user_corr)
            )
            existing = cur.fetchone()
            if existing:
                res = dict(existing)
                res["dataset_eligible"] = bool(res["dataset_eligible"])
                return res, True

        feedback_id = f"fb_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.now(timezone.utc).isoformat()
        
        target_content = feedback_data.get("target_content", "")
        if not target_content and analysis_id:
            # Look up target summary from analyses table
            row = conn.execute("SELECT target_summary FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
            if row:
                target_content = row["target_summary"]

        conn.execute(
            """
            INSERT INTO feedbacks (
                id, analysis_id, detection_module, predicted_verdict, predicted_risk_level,
                user_correction, corrected_risk_level, explanation, target_content,
                feedback_source, review_status, reviewer_notes, detector_version,
                dataset_eligible, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                feedback_id,
                analysis_id,
                detection_module,
                feedback_data.get("predicted_verdict"),
                feedback_data.get("predicted_risk_level"),
                user_corr,
                feedback_data.get("corrected_risk_level"),
                feedback_data.get("explanation"),
                target_content[:500] if target_content else None,
                feedback_data.get("feedback_source", "user_web"),
                "pending", # Untrusted until reviewed
                None,
                feedback_data.get("detector_version", "v1.2.0"),
                0, # Never eligible for dataset until reviewed & accepted
                now_iso,
                now_iso
            )
        )
        conn.commit()

        created = {
            "id": feedback_id,
            "analysis_id": analysis_id,
            "detection_module": detection_module,
            "predicted_verdict": feedback_data.get("predicted_verdict"),
            "predicted_risk_level": feedback_data.get("predicted_risk_level"),
            "user_correction": user_corr,
            "corrected_risk_level": feedback_data.get("corrected_risk_level"),
            "explanation": feedback_data.get("explanation"),
            "feedback_source": feedback_data.get("feedback_source", "user_web"),
            "review_status": "pending",
            "reviewer_notes": None,
            "detector_version": feedback_data.get("detector_version", "v1.2.0"),
            "dataset_eligible": False,
            "created_at": now_iso,
            "updated_at": now_iso
        }
        return created, False
    finally:
        conn.close()

def get_feedbacks(
    limit: int = 50,
    offset: int = 0,
    status: Optional[str] = None,
    module: Optional[str] = None
) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        query = """
            SELECT id, analysis_id, detection_module, predicted_verdict, predicted_risk_level,
                   user_correction, corrected_risk_level, explanation, feedback_source,
                   review_status, reviewer_notes, detector_version, dataset_eligible,
                   created_at, updated_at
            FROM feedbacks
            WHERE 1=1
        """
        params: List[Any] = []
        if status:
            query += " AND review_status = ?"
            params.append(status)
        if module:
            query += " AND detection_module = ?"
            params.append(module)

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = conn.execute(query, tuple(params)).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["dataset_eligible"] = bool(d["dataset_eligible"])
            result.append(d)
        return result
    finally:
        conn.close()

def get_feedback_by_id(feedback_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        cur = conn.execute(
            """
            SELECT id, analysis_id, detection_module, predicted_verdict, predicted_risk_level,
                   user_correction, corrected_risk_level, explanation, target_content, feedback_source,
                   review_status, reviewer_notes, detector_version, dataset_eligible,
                   created_at, updated_at
            FROM feedbacks
            WHERE id = ?
            """,
            (feedback_id,)
        )
        row = cur.fetchone()
        if row:
            d = dict(row)
            d["dataset_eligible"] = bool(d["dataset_eligible"])
            return d
        return None
    finally:
        conn.close()

def update_feedback_review(
    feedback_id: str,
    review_status: str,
    reviewer_notes: Optional[str] = None,
    dataset_eligible: Optional[bool] = None
) -> Optional[Dict[str, Any]]:
    valid_statuses = ("pending", "accepted", "rejected", "needs_more_evidence")
    if review_status not in valid_statuses:
        raise ValueError(f"Invalid review status: '{review_status}'. Must be one of {valid_statuses}")

    # Default dataset eligibility: 1 if accepted, 0 if rejected/pending/needs_more_evidence
    if dataset_eligible is None:
        eligible_val = 1 if review_status == "accepted" else 0
    else:
        eligible_val = 1 if (dataset_eligible and review_status == "accepted") else 0

    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        cur = conn.execute(
            """
            UPDATE feedbacks
            SET review_status = ?, reviewer_notes = ?, dataset_eligible = ?, updated_at = ?
            WHERE id = ?
            """,
            (review_status, reviewer_notes, eligible_val, now_iso, feedback_id)
        )
        conn.commit()
        if cur.rowcount == 0:
            return None
        return get_feedback_by_id(feedback_id)
    finally:
        conn.close()

def get_feedback_stats() -> Dict[str, Any]:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as count FROM feedbacks")
        total = cur.fetchone()["count"]

        cur.execute("SELECT detection_module, COUNT(*) as count FROM feedbacks GROUP BY detection_module")
        by_module = {row["detection_module"]: row["count"] for row in cur.fetchall()}

        cur.execute("SELECT review_status, COUNT(*) as count FROM feedbacks GROUP BY review_status")
        by_status = {row["review_status"]: row["count"] for row in cur.fetchall()}

        cur.execute("SELECT user_correction, COUNT(*) as count FROM feedbacks GROUP BY user_correction")
        by_corr = {row["user_correction"]: row["count"] for row in cur.fetchall()}

        cur.execute("SELECT COUNT(*) as count FROM feedbacks WHERE dataset_eligible = 1")
        dataset_count = cur.fetchone()["count"]

        return {
            "total_feedback": total,
            "by_module": by_module,
            "by_status": by_status,
            "by_correction": by_corr,
            "false_positives_count": by_corr.get("false_positive", 0),
            "false_negatives_count": by_corr.get("false_negative", 0),
            "dataset_eligible_count": dataset_count,
            "active_detector_version": "v1.2.0"
        }
    finally:
        conn.close()

def redact_sensitive_pii(text: str) -> str:
    """Safely redact emails, phone numbers, credit cards, and IP addresses."""
    if not text:
        return ""
    # Redact email addresses
    redacted = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '[REDACTED_EMAIL]', text)
    # Redact credit card numbers
    redacted = re.sub(r'\b(?:\d{4}[-\s]?){3}\d{4}\b', '[REDACTED_CARD]', redacted)
    # Redact phone numbers
    redacted = re.sub(r'(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}', '[REDACTED_PHONE]', redacted)
    # Redact IPv4 addresses
    redacted = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[REDACTED_IP]', redacted)
    return redacted

def export_curated_feedback(module: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Export reviewed, approved feedback samples for curated dataset preparation.
    - Only exports records where review_status='accepted' and dataset_eligible=1.
    - Excludes unreviewed and rejected records.
    - Strips PII and secrets.
    - Deduplicates identical targets.
    - Flags conflicting labels.
    """
    conn = get_db_connection()
    try:
        query = """
            SELECT id, analysis_id, detection_module, predicted_verdict, predicted_risk_level,
                   user_correction, corrected_risk_level, explanation, target_content,
                   reviewer_notes, detector_version, created_at, updated_at
            FROM feedbacks
            WHERE review_status = 'accepted' AND dataset_eligible = 1
        """
        params: List[Any] = []
        if module:
            query += " AND detection_module = ?"
            params.append(module)
        query += " ORDER BY created_at ASC"

        rows = conn.execute(query, tuple(params)).fetchall()

        seen_targets: Dict[str, Dict[str, Any]] = {}
        curated: List[Dict[str, Any]] = []

        for r in rows:
            raw_target = r["target_content"] or f"analysis_ref:{r['analysis_id']}"
            redacted_target = redact_sensitive_pii(raw_target)
            redacted_explanation = redact_sensitive_pii(r["explanation"] or "")

            # Normalized target key for deduplication
            target_key = redacted_target.strip().lower()

            ground_truth_label = r["corrected_risk_level"] or r["predicted_risk_level"] or "INCONCLUSIVE"
            if r["user_correction"] == "false_positive":
                ground_truth_label = "LOW_RISK"
            elif r["user_correction"] == "false_negative":
                ground_truth_label = "HIGH_RISK"

            item = {
                "feedback_id": r["id"],
                "detection_module": r["detection_module"],
                "target_content": redacted_target,
                "ground_truth_risk": ground_truth_label,
                "user_correction": r["user_correction"],
                "reviewer_notes": r["reviewer_notes"],
                "detector_version": r["detector_version"],
                "approved_at": r["updated_at"],
                "provenance": {
                    "source": "curated_reviewed_feedback",
                    "original_predicted_risk": r["predicted_risk_level"],
                    "reviewed": True,
                    "conflicting_labels": False
                }
            }

            if target_key in seen_targets:
                existing = seen_targets[target_key]
                if existing["ground_truth_risk"] != item["ground_truth_risk"]:
                    # Flag conflicting label!
                    item["provenance"]["conflicting_labels"] = True
                    existing["provenance"]["conflicting_labels"] = True
                continue # Skip near-duplicate

            seen_targets[target_key] = item
            curated.append(item)

        return curated
    finally:
        conn.close()

def log_audit(event_type: str, ip_address: str, details: str):
    try:
        conn = get_db_connection()
        try:
            import hashlib
            ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()[:16]
            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT INTO audit_logs (timestamp, event_type, ip_hash, details) VALUES (?, ?, ?, ?)",
                (now_iso, event_type, ip_hash, details)
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        import logging
        logging.getLogger("scamshield.audit").warning(f"Failed to log audit event {event_type}: {e}")
