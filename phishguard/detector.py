"""Email/message detection: ML probability + suspicious keyword/pattern analysis."""
import os
import re
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model", "phishing_model.joblib")

_model = None

KEYWORDS = {
    "urgent": "Urgency language ('urgent')",
    "immediately": "Pressure to act immediately",
    "verify your": "Asks you to verify account details",
    "confirm your": "Asks you to confirm personal details",
    "suspended": "Claims your account is suspended",
    "locked": "Claims your account is locked",
    "password": "Mentions your password",
    "click here": "Generic 'click here' call to action",
    "winner": "Prize/winner bait",
    "congratulations": "Unexpected congratulations",
    "gift card": "Gift card request (common scam payment)",
    "bank account": "Mentions bank account",
    "credit card": "Mentions credit card details",
    "ssn": "Requests social security number",
    "pin": "Requests a PIN",
    "wire transfer": "Wire transfer request",
    "bitcoin": "Cryptocurrency payment",
    "limited time": "Limited-time pressure",
    "act now": "Pressure to 'act now'",
    "final notice": "Threatening 'final notice'",
    "login": "Login request",
    "update your": "Asks you to update account information",
    "unusual activity": "Claims unusual activity",
    "refund": "Unexpected refund offer",
    "prize": "Prize bait",
    "inheritance": "Inheritance scam pattern",
    "confidential": "Asks for secrecy",
}

PATTERNS = [
    (re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}"), "Contains a link pointing to a raw IP address", 20),
    (re.compile(r"(bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|is\.gd)/", re.I), "Contains a shortened link that hides the destination", 15),
    (re.compile(r"\b\d{2,3}\s*(hours|hrs)\b", re.I), "Gives a short deadline", 10),
    (re.compile(r"\$\s?\d[\d,]*"), "Mentions money amounts", 5),
    (re.compile(r"!{2,}"), "Excessive exclamation marks", 5),
    (re.compile(r"\b[A-Z]{5,}\b"), "Uses ALL-CAPS shouting", 5),
    (re.compile(r"\.(exe|scr|zip|js|bat)\b", re.I), "Mentions a risky file attachment type", 15),
]

URL_RE = re.compile(r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+)", re.I)


def load_model():
    global _model
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError("Model not found. Run: python train_model.py")
        _model = joblib.load(MODEL_PATH)
    return _model


def ml_score(text):
    """Return phishing probability as 0-100."""
    model = load_model()
    proba = model.predict_proba([text])[0][1]
    return round(float(proba) * 100, 1)


def keyword_analysis(text):
    """Return (score 0-100, list of warnings)."""
    lower = text.lower()
    warnings, score = [], 0
    for kw, reason in KEYWORDS.items():
        if re.search(r"\b" + re.escape(kw) + r"\b", lower):
            warnings.append(reason)
            score += 8
    for regex, reason, points in PATTERNS:
        if regex.search(text):
            warnings.append(reason)
            score += points
    return min(score, 100), warnings


def extract_urls(text):
    return URL_RE.findall(text)[:10]
