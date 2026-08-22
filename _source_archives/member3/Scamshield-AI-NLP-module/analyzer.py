"""Explainable multilingual NLP rules for the ScamSense prototype.

The service deliberately exposes every matched signal. This gives users a
verifiable explanation instead of an opaque "scam/not scam" decision.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from app.models import Evidence


Severity = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True)
class Rule:
    signal: str
    pattern: str
    severity: Severity
    score: int
    category: str
    explanation: str


RULES: tuple[Rule, ...] = (
    Rule("OTP or PIN request", r"\b(otp|pin|cvv|password|passcode)\b|ओटीपी|पिन|पासवर्ड", "critical", 35, "credential_theft", "Legitimate banks and support teams do not ask for OTP, PIN, CVV, or passwords."),
    Rule("Urgency pressure", r"\b(urgent|immediately|act now|within \d+ (minute|hour)|last chance|suspend(ed)?|blocked)\b|तुरंत|अभी|तात्काळ|लगेच", "high", 15, "social_engineering", "Scammers create urgency so that people act before verifying the claim."),
    Rule("Payment request", r"\b(pay|payment|transfer|send money|deposit|fee|processing fee|upi|scan.*qr)\b|पैसे भेज|भुगतान|पेमेंट|फीस|पैसे भरा|पैसे पाठवा", "high", 20, "payment_fraud", "Unexpected payment requests are a common fraud signal."),
    Rule("Impersonation", r"\b(bank|sbi|rbi|police|cyber ?cell|government|income tax|customer care|support team)\b|बैंक|पुलिस|सरकार|ग्राहक सेवा|बँक|पोलीस", "medium", 10, "impersonation", "The sender claims to represent an authority or trusted service. Verify via an official channel."),
    Rule("Suspicious link", r"https?://\S+|\b(bit\.ly|tinyurl\.com|t\.me)/\S*", "high", 18, "phishing", "A link was included. Do not open it until its destination is verified."),
    Rule("Reward or prize lure", r"\b(won|winner|prize|reward|cashback|lottery|gift)\b|जीत गए|इनाम|लॉटरी|बक्षीस", "medium", 12, "prize_scam", "Unexpected rewards are often used to convince victims to share details or pay a fee."),
    Rule("Job offer lure", r"\b(job offer|work from home|earn \d+|part.?time job|recruitment)\b|नौकरी|घर से काम|जॉब|नोकरी", "medium", 12, "job_scam", "Unsolicited jobs that promise quick earnings need independent verification."),
    Rule("Investment return lure", r"\b(guaranteed return|double your money|crypto profit|investment plan|daily return)\b|गारंटीड रिटर्न|पैसे दोगुने|गुंतवणूक", "high", 18, "investment_scam", "Guaranteed or unusually high returns are a common investment-scam tactic."),
    Rule("Remote access request", r"\b(anydesk|teamviewer|screen share|remote access|install app)\b|स्क्रीन शेयर|ऐप इंस्टॉल", "critical", 28, "account_takeover", "Remote-access apps can let a fraudster view or control a device."),
)


TRANSLATIONS = {
    "en": {
        "low": "No strong scam signals were found. Still verify unknown senders.",
        "medium": "Some warning signs were found. Verify before responding or clicking anything.",
        "high": "Multiple warning signs were found. Do not pay, click links, or share information.",
        "critical": "This message has severe fraud indicators. Stop interacting and secure your accounts.",
        "actions": ["Do not reply, pay, click links, or scan a QR code.", "Never share OTP, PIN, CVV, passwords, or screen access.", "Verify the sender using the official app, website, or phone number.", "Save screenshots and report suspected fraud to cybercrime.gov.in or 1930."],
    },
    "hi": {
        "low": "कोई मजबूत स्कैम संकेत नहीं मिला, फिर भी अज्ञात भेजने वाले को सत्यापित करें।",
        "medium": "कुछ चेतावनी संकेत मिले हैं। जवाब देने या लिंक खोलने से पहले सत्यापित करें।",
        "high": "कई चेतावनी संकेत मिले हैं। पैसे न भेजें, लिंक न खोलें और जानकारी साझा न करें।",
        "critical": "इस संदेश में गंभीर धोखाधड़ी संकेत हैं। बातचीत रोकें और अपने खाते सुरक्षित करें।",
        "actions": ["जवाब न दें, पैसे न भेजें, लिंक न खोलें और QR स्कैन न करें।", "OTP, PIN, CVV, पासवर्ड या स्क्रीन एक्सेस कभी साझा न करें।", "आधिकारिक ऐप, वेबसाइट या नंबर से भेजने वाले की जांच करें।", "स्क्रीनशॉट सुरक्षित रखें और cybercrime.gov.in या 1930 पर रिपोर्ट करें।"],
    },
    "mr": {
        "low": "ठोस फसवणुकीचे संकेत सापडले नाहीत; तरीही अनोळखी पाठवणाऱ्याची पडताळणी करा।",
        "medium": "काही इशारे आढळले. उत्तर देण्यापूर्वी किंवा लिंक उघडण्यापूर्वी पडताळणी करा।",
        "high": "अनेक इशारे आढळले. पैसे पाठवू नका, लिंक उघडू नका आणि माहिती देऊ नका।",
        "critical": "या संदेशात गंभीर फसवणुकीचे संकेत आहेत. संवाद थांबवा आणि खाती सुरक्षित करा।",
        "actions": ["उत्तर देऊ नका, पैसे पाठवू नका, लिंक उघडू नका आणि QR स्कॅन करू नका।", "OTP, PIN, CVV, पासवर्ड किंवा स्क्रीन अॅक्सेस कधीही देऊ नका।", "अधिकृत अॅप, वेबसाइट किंवा क्रमांकावरून पाठवणाऱ्याची पडताळणी करा।", "स्क्रीनशॉट जतन करा आणि cybercrime.gov.in किंवा 1930 वर तक्रार करा।"],
    },
}


def detect_language(text: str) -> Literal["en", "hi", "mr", "mixed"]:
    devanagari = sum("\u0900" <= char <= "\u097f" for char in text)
    if not devanagari:
        return "en"
    hindi_markers = ("है", "नहीं", "कृपया", "भेज", "आप")
    marathi_markers = ("आहे", "नाही", "कृपया", "पाठवा", "तुमचे")
    has_hindi = any(marker in text for marker in hindi_markers)
    has_marathi = any(marker in text for marker in marathi_markers)
    if has_hindi and has_marathi:
        return "mixed"
    return "mr" if has_marathi else "hi"


def _risk_level(score: int) -> Literal["low", "medium", "high", "critical"]:
    if score >= 70:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def analyze_text(text: str, preferred_language: Literal["en", "hi", "mr"] = "en") -> dict:
    normalized = re.sub(r"\s+", " ", text.strip().lower())
    evidence: list[Evidence] = []
    categories: list[str] = []
    score = 0

    for rule in RULES:
        match = re.search(rule.pattern, normalized, re.IGNORECASE)
        if not match:
            continue
        evidence.append(Evidence(
            signal=rule.signal,
            matched_text=match.group(0),
            severity=rule.severity,
            score_impact=rule.score,
            explanation=rule.explanation,
        ))
        score += rule.score
        if rule.category not in categories:
            categories.append(rule.category)

    score = min(score, 100)
    level = _risk_level(score)
    detected = detect_language(text)
    copy = TRANSLATIONS[preferred_language]
    # More independent signals means a more reliable decision. A clean message is
    # intentionally lower confidence: absence of a match is not proof of safety.
    confidence = min(95, 45 + len(evidence) * 14) if evidence else 55

    return {
        "risk_score": score,
        "risk_level": level,
        "confidence": confidence,
        "detected_language": detected,
        "scam_categories": categories or ["no_specific_category"],
        "summary": copy[level],
        "evidence": evidence,
        "recommended_actions": copy["actions"],
        "safe_to_interact": level in {"low", "medium"},
    }
