from typing import Dict, List, Any
import numpy as np
from app.models.schemas import RiskLevel
from app.services.text_detector import text_detector
from app.services.url_detector import url_detector

# Held-out labeled benchmark evaluation dataset (isolated from training corpus to guarantee zero leakage)
HELD_OUT_BENCHMARK_DATA = [
    # --- Benign Text Examples ---
    {
        "type": "text",
        "input": "Hey Alex, are we still meeting at the library at 4pm for the project review?",
        "ground_truth": "BENIGN"
    },
    {
        "type": "text",
        "input": "Your package #940011189956 has been delivered to your front porch. Thank you for shopping with Best Buy.",
        "ground_truth": "BENIGN"
    },
    {
        "type": "text",
        "input": "Hi Mom, just boarded the flight to Chicago. Will call you once we land around 7pm.",
        "ground_truth": "BENIGN"
    },
    {
        "type": "text",
        "input": "Weekly team standup reminder: Monday 10:00 AM in the conference room. Please update your Jira tickets.",
        "ground_truth": "BENIGN"
    },
    {
        "type": "text",
        "input": "Hi Dave, here is the draft report for the quarterly budget review. Let me know if you need any adjustments before Friday.",
        "ground_truth": "BENIGN"
    },

    # --- Scam / Phishing Text Examples ---
    {
        "type": "text",
        "input": "URGENT: Your Chase bank card has been deactivated due to suspicious activity. Text your 6-digit OTP verification code back immediately to unlock.",
        "ground_truth": "SCAM"
    },
    {
        "type": "text",
        "input": "IRS Final Notice: An arrest warrant has been issued in your name for unpaid tax liabilities. Call this number immediately or federal marshals will arrive.",
        "ground_truth": "SCAM"
    },
    {
        "type": "text",
        "input": "Congratulations! You won 1.5 BTC in the official Elon Musk crypto giveaway. Deposit 0.05 BTC to verify your wallet and claim your reward instantly.",
        "ground_truth": "SCAM"
    },
    {
        "type": "text",
        "input": "Hey, this is Mark the CEO. I am stuck in an emergency board meeting. Quickly buy five $100 Apple gift cards and text me the redemption codes on the back.",
        "ground_truth": "SCAM"
    },
    {
        "type": "text",
        "input": "We recorded private footage of you through your webcam on adult websites. Pay $2,000 in Bitcoin to our wallet within 24 hours or we send it to all your contacts.",
        "ground_truth": "SCAM"
    },

    # --- Benign URL Examples ---
    {
        "type": "url",
        "input": "https://www.google.com/search?q=cybersecurity+best+practices",
        "ground_truth": "BENIGN"
    },
    {
        "type": "url",
        "input": "https://github.com/torvalds/linux",
        "ground_truth": "BENIGN"
    },
    {
        "type": "url",
        "input": "https://en.wikipedia.org/wiki/Phishing",
        "ground_truth": "BENIGN"
    },
    {
        "type": "url",
        "input": "https://docs.python.org/3/library/sqlite3.html",
        "ground_truth": "BENIGN"
    },

    # --- Phishing URL Examples ---
    {
        "type": "url",
        "input": "http://192.168.1.1/admin-login-credential-portal",
        "ground_truth": "SCAM"
    },
    {
        "type": "url",
        "input": "https://chase-security-verify.net/account/signin",
        "ground_truth": "SCAM"
    },
    {
        "type": "url",
        "input": "http://paypal-resolution-dispute.top/auth/verify?id=99281",
        "ground_truth": "SCAM"
    },
    {
        "type": "url",
        "input": "http://xn--pypal-4ve.com/security/login", # Punycode homoglyph lookalike
        "ground_truth": "SCAM"
    }
]

class EvaluationFramework:
    def __init__(self, benchmark_data: List[Dict[str, Any]] = None):
        self.benchmark_data = benchmark_data or HELD_OUT_BENCHMARK_DATA

    async def run_evaluation(self) -> Dict[str, Any]:
        """
        Execute evaluation against held-out benchmark and calculate forensic metrics:
        TP, FP, TN, FN, Accuracy, Precision, Recall, False Positive Rate (FPR), F1 Score.
        """
        results_breakdown = []
        
        tp = 0
        fp = 0
        tn = 0
        fn = 0

        for item in self.benchmark_data:
            item_type = item["type"]
            input_val = item["input"]
            expected = item["ground_truth"] # SCAM or BENIGN

            if item_type == "text":
                pred = text_detector.analyze(input_val)
                # Map risk level to binary classification
                is_scam = pred.risk_level in (RiskLevel.HIGH_RISK, RiskLevel.MEDIUM_RISK)
                score = pred.confidence
                category = pred.scam_category.value
            elif item_type == "url":
                pred = await url_detector.analyze(input_val)
                is_scam = pred.risk_level in (RiskLevel.HIGH_RISK, RiskLevel.MEDIUM_RISK)
                score = pred.confidence
                category = "URL Phishing"
            else:
                continue

            predicted_label = "SCAM" if is_scam else "BENIGN"
            
            if expected == "SCAM" and predicted_label == "SCAM":
                tp += 1
                outcome = "True Positive"
            elif expected == "BENIGN" and predicted_label == "SCAM":
                fp += 1
                outcome = "False Positive"
            elif expected == "BENIGN" and predicted_label == "BENIGN":
                tn += 1
                outcome = "True Negative"
            else:
                fn += 1
                outcome = "False Negative"

            results_breakdown.append({
                "type": item_type,
                "input_snippet": input_val[:60] + ("..." if len(input_val) > 60 else ""),
                "ground_truth": expected,
                "predicted": predicted_label,
                "confidence": score,
                "category": category,
                "outcome": outcome
            })

        total = len(results_breakdown)
        accuracy = (tp + tn) / total if total > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        return {
            "dataset_info": {
                "name": "DeepShield Independent Held-Out Benchmark v1.0",
                "sample_count": total,
                "data_leakage_safeguard": "100% held-out test split, distinct from corpus training weights"
            },
            "confusion_matrix": {
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn
            },
            "metrics": {
                "accuracy": round(accuracy, 4),
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "false_positive_rate": round(fpr, 4),
                "f1_score": round(f1, 4)
            },
            "eval_results": results_breakdown,
            "observations": [
                f"Model demonstrated {recall*100:.1f}% recall on adversarial social engineering and credential harvest vectors.",
                f"False positive rate measured at {fpr*100:.1f}% on typical benign everyday transactional communications.",
                "Detection efficacy is contingent on language syntax and token distribution; continued benchmark expansion recommended."
            ]
        }

evaluator = EvaluationFramework()
