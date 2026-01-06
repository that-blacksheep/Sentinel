import torch
import re
import hashlib
from datetime import datetime
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import mysql.connector

# ---------------- CONFIG ----------------

MODEL_NAME = "protectai/deberta-v3-base-prompt-injection-v2"
BLOCK_THRESHOLD = 0.8

FORBIDDEN_TOPICS = [
    "api key",
    "credentials",
    "salary spreadsheet",
    "project x"
]

JAILBREAK_PATTERNS = [
    r"ignore (all|previous) instructions",
    r"you are now .*bot",
    r"do not mention (rules|filters|policies)",
    r"act as .* without restrictions",
    r"decode this.*(base64|rot13)"
]

# ---------------- LOAD MODEL ----------------

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
model.eval()

# ---------------- DATABASE ----------------

def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="sentinel",
        password="sentinel123",
        database="sentinel_logs"
    )

db = get_db()
cursor = db.cursor()

# ---------------- UTILS ----------------

def hash_prompt(prompt: str) -> str:
    return hashlib.sha256(prompt.encode()).hexdigest()

def log_to_db(prompt, verdict, tag, score, notes):
    try:
        query = """
        INSERT INTO prompt_audit
        (timestamp, prompt_hash, verdict, tag, security_score, notes)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        cursor.execute(
            query,
            (
                datetime.utcnow(),
                hash_prompt(prompt),
                verdict,
                tag,
                score,
                notes
            )
        )
        db.commit()
    except Exception as e:
        print("[DB ERROR]", e)

# ---------------- SHIELD LAYERS ----------------

def ml_guard(prompt):
    inputs = tokenizer(
        prompt,
        return_tensors="pt",
        truncation=True,
        max_length=512
    )
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=1)
    return probs[0][1].item()

def heuristic_scan(prompt):
    p = prompt.lower()
    return any(re.search(pattern, p) for pattern in JAILBREAK_PATTERNS)

def semantic_firewall(prompt):
    p = prompt.lower()
    return any(term in p for term in FORBIDDEN_TOPICS)

# ---------------- MAIN PIPELINE ----------------

def shield_pipeline(prompt):
    score = ml_guard(prompt)

    if score >= BLOCK_THRESHOLD:
        log_to_db(prompt, "UNSAFE", "ML_GUARD", score, "Prompt injection detected")
        return {
            "verdict": "UNSAFE",
            "reason": "ML_GUARD",
            "security_score": round(score, 4),
            "forward_to_ayaan": False
        }

    if heuristic_scan(prompt):
        log_to_db(prompt, "UNSAFE", "HEURISTIC", score, "Jailbreak pattern detected")
        return {
            "verdict": "UNSAFE",
            "reason": "HEURISTIC_SCANNER",
            "security_score": round(score, 4),
            "forward_to_ayaan": False
        }

    if semantic_firewall(prompt):
        log_to_db(prompt, "UNSAFE", "SEMANTIC_FIREWALL", score, "Forbidden topic")
        return {
            "verdict": "UNSAFE",
            "reason": "SEMANTIC_FIREWALL",
            "security_score": round(score, 4),
            "forward_to_ayaan": False
        }

    log_to_db(prompt, "SAFE", "CLEAN", score, "Prompt allowed")
    return {
        "verdict": "SAFE",
        "reason": "CLEAN",
        "security_score": round(score, 4),
        "forward_to_ayaan": True
    }

# ---------------- CLI ENTRY ----------------

if __name__ == "__main__":
    print("\n Sentinel Shield CLI (Ctrl+C to exit)\n")

    while True:
        try:
            user_prompt = input("User Prompt ➜ ").strip()
            if not user_prompt:
                continue

            result = shield_pipeline(user_prompt)

            print("\n--- SHIELD VERDICT ---")
            for k, v in result.items():
                print(f"{k}: {v}")
            print("----------------------\n")

        except KeyboardInterrupt:
            print("\n[+] Shield shutting down.")
            break











