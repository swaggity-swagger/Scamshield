from urllib.parse import urlparse
import ipaddress


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "verification",
    "update",
    "kyc",
    "account",
    "password",
    "secure",
    "bank",
    "reward",
    "prize",
    "urgent",
}


URL_TRANSLATIONS = {
    "en": {
        "invalid": "The provided URL does not appear to be valid.",
        "suspicious": (
            "The URL contains one or more characteristics "
            "that may indicate a suspicious or risky link."
        ),
        "clean": (
            "No obvious suspicious URL characteristics were detected "
            "by the current rule-based checks."
        ),
        "invalid_actions": [
            "Do not open the URL",
            "Verify the website address carefully",
        ],
        "suspicious_actions": [
            "Do not enter passwords, OTPs, or banking details",
            "Verify the website through an official source",
        ],
        "clean_actions": [
            "Still verify the website before sharing sensitive information",
        ],
    },

    "hi": {
        "invalid": "दिया गया URL मान्य नहीं लगता है।",
        "suspicious": (
            "इस URL में कुछ ऐसी विशेषताएँ हैं जो इसे "
            "संदिग्ध या जोखिमपूर्ण बना सकती हैं।"
        ),
        "clean": (
            "वर्तमान नियम-आधारित जांच में URL की कोई स्पष्ट "
            "संदिग्ध विशेषता नहीं मिली।"
        ),
        "invalid_actions": [
            "URL न खोलें",
            "वेबसाइट का पता ध्यान से सत्यापित करें",
        ],
        "suspicious_actions": [
            "पासवर्ड, OTP या बैंकिंग जानकारी दर्ज न करें",
            "आधिकारिक स्रोत से वेबसाइट सत्यापित करें",
        ],
        "clean_actions": [
            "संवेदनशील जानकारी साझा करने से पहले वेबसाइट सत्यापित करें",
        ],
    },

    "mr": {
        "invalid": "दिलेला URL वैध दिसत नाही.",
        "suspicious": (
            "या URL मध्ये काही अशी वैशिष्ट्ये आहेत जी "
            "तो संशयास्पद किंवा धोकादायक असू शकतो असे दर्शवतात."
        ),
        "clean": (
            "सध्याच्या नियम-आधारित तपासणीत URL ची कोणतीही "
            "स्पष्ट संशयास्पद वैशिष्ट्ये आढळली नाहीत."
        ),
        "invalid_actions": [
            "URL उघडू नका",
            "वेबसाइटचा पत्ता काळजीपूर्वक तपासा",
        ],
        "suspicious_actions": [
            "पासवर्ड, OTP किंवा बँकिंग माहिती देऊ नका",
            "अधिकृत स्रोताद्वारे वेबसाइटची पडताळणी करा",
        ],
        "clean_actions": [
            "संवेदनशील माहिती देण्यापूर्वी वेबसाइटची पडताळणी करा",
        ],
    },
}


def normalize_url(url: str) -> str:
    """
    Normalize a user-provided URL.

    If the user does not provide a scheme,
    assume HTTPS for analysis purposes.
    """

    url = url.strip()

    if not url:
        return ""

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def analyze_url(url: str, language: str = "en") -> dict:
    """
    Perform rule-based URL analysis.
    """

    url = normalize_url(url)

    language = language if language in URL_TRANSLATIONS else "en"
    copy = URL_TRANSLATIONS[language]

    parsed_url = urlparse(url)

    indicators = []

    # Basic validation
    if parsed_url.scheme not in {"http", "https"}:
        indicators.append("Invalid URL scheme")

    if not parsed_url.netloc:
        indicators.append("Missing domain")

    # Invalid URL
    if indicators:
        return {
            "url": url,
            "language": language,
            "risk_level": "HIGH",
            "category": "INVALID_URL",
            "confidence": None,
            "indicators": indicators,
            "features": {
                "scheme": parsed_url.scheme,
                "domain": parsed_url.hostname or "",
                "uses_https": parsed_url.scheme == "https",
                "uses_ip_address": False,
                "has_at_symbol": "@" in parsed_url.netloc,
                "is_long_url": len(url) > 120,
                "has_many_subdomains": False,
                "is_punycode": False,
                "is_shortened_url": False,
                "suspicious_keywords": [],
            },
            "explanation": copy["invalid"],
            "recommended_actions": copy["invalid_actions"],
        }

    hostname = parsed_url.hostname or ""
    hostname_lower = hostname.lower()
    full_url = url.lower()

    # IP address check
    uses_ip_address = False

    try:
        ipaddress.ip_address(hostname)
        uses_ip_address = True
        indicators.append(
            "IP address used instead of a domain name"
        )
    except ValueError:
        pass

    # @ symbol check
    has_at_symbol = "@" in parsed_url.netloc

    if has_at_symbol:
        indicators.append("URL contains @ symbol")

    # URL length check
    is_long_url = len(url) > 120

    if is_long_url:
        indicators.append("Unusually long URL")

    # Subdomain check
    has_many_subdomains = hostname.count(".") >= 3

    if has_many_subdomains:
        indicators.append("Multiple subdomains detected")

    # Punycode check
    is_punycode = "xn--" in hostname_lower

    if is_punycode:
        indicators.append("Punycode domain detected")

    # URL shortener check
    is_shortened_url = hostname_lower in SHORTENER_DOMAINS

    if is_shortened_url:
        indicators.append("URL shortening service detected")

    # HTTPS check
    uses_https = parsed_url.scheme == "https"

    if not uses_https:
        indicators.append("URL does not use HTTPS")

    # Suspicious keyword check
    suspicious_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in full_url
    ]

    if suspicious_keywords:
        indicators.append(
            "Suspicious keywords detected: "
            + ", ".join(suspicious_keywords)
        )

    # Basic MVP risk scoring
    if len(indicators) >= 3:
        risk_level = "HIGH"
    elif len(indicators) >= 1:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    if indicators:
        category = "SUSPICIOUS_URL"

        explanation = copy["suspicious"]

        recommended_actions = copy["suspicious_actions"]

    else:
        category = "NO_OBVIOUS_INDICATORS"

        explanation = copy["clean"]

        recommended_actions = copy["clean_actions"]

    return {
        "url": url,
        "language": language,
        "risk_level": risk_level,
        "category": category,
        "confidence": None,
        "indicators": indicators,
        "features": {
            "scheme": parsed_url.scheme,
            "domain": hostname,
            "uses_https": uses_https,
            "uses_ip_address": uses_ip_address,
            "has_at_symbol": has_at_symbol,
            "is_long_url": is_long_url,
            "has_many_subdomains": has_many_subdomains,
            "is_punycode": is_punycode,
            "is_shortened_url": is_shortened_url,
            "suspicious_keywords": suspicious_keywords,
        },
        "explanation": explanation,
        "recommended_actions": recommended_actions,
    }