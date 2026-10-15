import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

URGENT_PATTERNS = [
    "account suspended",
    "account has been suspended",
    "immediate verification",
    "password expires",
    "verify now",
    "verify immediately",
    "urgent action",
    "urgent",
    "payment failed",
    "refund issue",
    "suspicious activity",
    "final notice",
    "limited time",
    "security alert",
    "service interruption",
]

REQUEST_PATTERNS = [
    "password",
    "otp",
    "one-time password",
    "bank account",
    "credit card",
    "routing number",
    "ssn",
    "tax id",
    "security code",
    "login credentials",
    "payment information",
]

ATTACHMENT_PATTERNS = [
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".msi",
    ".js",
    ".vbs",
    ".reg",
    ".dll",
]

SHORTENER_HOSTS = {
    "tinyurl.com",
    "bit.ly",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "tiny.cc",
    "buff.ly",
    "t.ly",
    "linktr.ee",
    "rebrand.ly",
}

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "club", "top", "bid", "loan"}
BRAND_KEYWORDS = [
    "paypal",
    "apple",
    "microsoft",
    "google",
    "amazon",
    "netflix",
    "dropbox",
    "bank",
    "office365",
    "linkedin",
    "github",
    "facebook",
    "instagram",
]


def _extract_urls(text):
    pattern = re.compile(r"https?://[^\s)\]>\"]+")
    urls = pattern.findall((text or "").strip())
    deduped = []
    seen = set()
    for value in urls:
        cleaned = value.rstrip('.,;:!')
        if cleaned not in seen:
            deduped.append(cleaned)
            seen.add(cleaned)
    return deduped


def _risk_label(score):
    if score <= 29:
        return "Low Risk"
    if score <= 59:
        return "Medium Risk"
    if score <= 79:
        return "High Risk"
    return "Critical Risk"


def _make_indicator(name, score, severity, explanation, evidence):
    return {
        "name": name,
        "score": score,
        "severity": severity,
        "explanation": explanation,
        "evidence": evidence,
    }


def _classify_error(reason):
    return {
        "risk_score": 0,
        "risk_level": "Low Risk",
        "confidence": "Very low evidence strength",
        "summary": reason,
        "indicators": [],
        "recommendations": [
            "Review the submission and provide more details before drawing a conclusion.",
            "Do not take a low score as proof the communication is safe.",
        ],
        "limitations": [
            "This assessment is based on limited evidence and heuristic rules.",
            "A definitive determination requires more context and potentially external reputation data.",
        ],
        "evidence": [],
        "analysis_type": "unknown",
        "submitted": {},
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def analyze_url(url):
    if not url:
        return _classify_error("No URL was supplied for analysis.")

    normalized = url.strip()
    parsed = urlsplit(normalized)
    host = (parsed.hostname or "").lower()
    indicators = []
    score = 0
    evidence = []

    if not parsed.scheme or not parsed.netloc:
        indicators.append(_make_indicator("Malformed URL", 12, "Medium", "The URL is missing a valid scheme or hostname, which often indicates a malformed or obfuscated destination.", [normalized]))
        score += 12
    if parsed.scheme and parsed.scheme.lower() != "https":
        indicators.append(_make_indicator("Non-HTTPS URL", 8, "Low", "HTTP is not encrypted by default and may be used to intercept credentials or redirect users to malicious pages.", [normalized]))
        score += 8
        evidence.append("URL scheme was not HTTPS")

    if re.fullmatch(r"\d+(\.\d+){3}", host):
        indicators.append(_make_indicator("Direct IP Host", 22, "High", "URLs using direct IP addresses instead of a domain name are frequently used to avoid reputation checks and hide the destination.", [host]))
        score += 22
        evidence.append("Host resolves to an IP address")
    if "@" in normalized:
        indicators.append(_make_indicator("Credential-like URL", 18, "High", "The @ symbol can hide the real hostname by shifting the browser to a different userinfo field.", [normalized]))
        score += 18
        evidence.append("URL contains userinfo data")
    if len(normalized) > 90:
        indicators.append(_make_indicator("Excessive URL Length", 12, "Medium", "Long URLs often hide extra redirect parameters, tracking tokens, or phishing payloads.", [normalized]))
        score += 12
        evidence.append("URL length exceeds 90 characters")
    if host and host.endswith(tuple(SUSPICIOUS_TLDS)):
        indicators.append(_make_indicator("Suspicious Top-Level Domain", 15, "Medium", "Some low-reputation TLDs are commonly used in phishing campaigns to impersonate legitimate services.", [host]))
        score += 15
        evidence.append(f"Host ends with suspicious TLD: {host.rsplit('.', 1)[-1]}")
    if any(s in host for s in ["login", "verify", "secure", "update", "confirm", "billing"]) and any(k in host for k in ["amazon", "paypal", "microsoft", "google"]):
        indicators.append(_make_indicator("Brand Mimicry in Hostname", 18, "High", "A host that resembles a trusted brand while using a deceptive path can be used to impersonate a legitimate service.", [host]))
        score += 18
        evidence.append("Hostname includes a trusted brand with an unusual structure")
    if any(keyword in host for keyword in BRAND_KEYWORDS):
        indicators.append(_make_indicator("Brand Keyword in Domain", 10, "Medium", "Touching a trusted brand name in the hostname may be part of impersonation or lookalike targeting.", [host]))
        score += 10
    if host.startswith("xn--") or any(ord(ch) > 127 for ch in host):
        indicators.append(_make_indicator("Punycode or Unicode Domain", 16, "High", "Internationalized domain names can be used to spoof characters and look similar to trusted domains.", [host]))
        score += 16
        evidence.append("Hostname contains punycode or Unicode characters")
    if host in SHORTENER_HOSTS or any(shortener in host for shortener in SHORTENER_HOSTS):
        indicators.append(_make_indicator("URL Shortener", 20, "High", "URL shorteners obscure the final destination and are frequently used in phishing attacks.", [host]))
        score += 20
        evidence.append("Host is a known URL shortener")
    if parsed.query:
        query_lower = parsed.query.lower()
        if any(token in query_lower for token in ["redirect", "token", "session", "utm", "verify", "login"]):
            indicators.append(_make_indicator("Suspicious Query Parameters", 12, "Medium", "Redirect or token parameters may be used to hide the final destination or maintain malicious tracking.", [parsed.query]))
            score += 12
            evidence.append("Query string includes redirect or tracking parameters")
    if parsed.path and len(parsed.path) > 40:
        indicators.append(_make_indicator("Obfuscated Path Structure", 8, "Low", "Long or layered URL paths can hide unusual redirects, script parameters, or spoofed content.", [parsed.path]))
        score += 8

    unique_indicators = []
    seen_names = set()
    for indicator in indicators:
        if indicator["name"] not in seen_names:
            unique_indicators.append(indicator)
            seen_names.add(indicator["name"])

    final_score = min(100, score)
    classification = _risk_label(final_score)
    confidence = "heuristic-based evidence" if final_score > 0 else "limited evidence"
    recommendations = [
        "Do not click the link until the destination is verified through a trusted, independent channel.",
        "If the link is expected, confirm with the sender through a known contact method before visiting it.",
        "Avoid entering credentials or payment details on pages reached via suspicious links.",
    ]
    limitations = [
        "This assessment uses explainable heuristics and cannot confirm the URL is malicious without external reputation data.",
        "A low score does not prove the website is safe, and a single factor should not be treated as definitive evidence.",
    ]

    return {
        "risk_score": final_score,
        "risk_level": classification,
        "confidence": confidence,
        "summary": "URL analysis completed using rule-based phishing indicators and domain heuristics.",
        "indicators": unique_indicators,
        "recommendations": recommendations,
        "limitations": limitations,
        "evidence": evidence,
        "analysis_type": "url",
        "submitted": {"url": normalized},
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def analyze_email(payload):
    if not payload:
        return _classify_error("No email data was provided.")

    subject = (payload.get("subject") or "").strip()
    sender = (payload.get("sender_email") or "").strip()
    display_name = (payload.get("display_name") or "").strip()
    reply_to = (payload.get("reply_to") or "").strip()
    message = (payload.get("message") or "").strip()
    attachment_text = (payload.get("attachment_hint") or "").strip()
    manual_url = (payload.get("manual_url") or "").strip()
    extracted_urls = _extract_urls(message)
    if manual_url:
        extracted_urls.append(manual_url)

    indicators = []
    evidence = []
    score = 0

    lower_message = (subject + " " + message).lower()
    for phrase in URGENT_PATTERNS:
        if phrase in lower_message:
            indicators.append(_make_indicator("Urgent or Threatening Language", 18, "High", "The message uses urgency or fear tactics that are common in phishing emails, encouraging quick action without verification.", [phrase]))
            score += 18
            evidence.append(f"Detected urgent language: {phrase}")
            break

    if any(token in lower_message for token in REQUEST_PATTERNS):
        indicators.append(_make_indicator("Credential or Financial Request", 23, "High", "The message requests sensitive information such as passwords, OTPs, or financial details, which is a common phishing tactic.", ["password", "OTP", "credit card", "bank account"]))
        score += 23
        evidence.append("Message requests sensitive information")

    if attachment_text:
        lower_attachment = attachment_text.lower()
        if any(ext in lower_attachment for ext in ATTACHMENT_PATTERNS):
            indicators.append(_make_indicator("Suspicious Attachment Hint", 16, "High", "The communication references an executable or suspicious file type, which may be used to install malware or steal data.", [attachment_text]))
            score += 16
            evidence.append("Attachment hint includes executable extension")

    if sender:
        sender_domain = sender.split("@")[-1].lower()
        if display_name:
            compact_display = display_name.lower()
            if any(brand in compact_display for brand in BRAND_KEYWORDS) and sender_domain not in compact_display and not any(brand in sender_domain for brand in BRAND_KEYWORDS):
                indicators.append(_make_indicator("Display Name and Sender Mismatch", 12, "Medium", "The sender’s display name may be impersonating a trusted brand while the email domain does not match it.", [display_name, sender]))
                score += 12
                evidence.append("Display name resembles a trusted brand but sender domain does not match")

        if any(brand in sender_domain for brand in BRAND_KEYWORDS) and not any(brand in sender.lower() for brand in BRAND_KEYWORDS):
            indicators.append(_make_indicator("Brand Impersonation Risk", 10, "Medium", "The sender address uses a brand-themed domain or naming pattern that may be intended to look legitimate.", [sender]))
            score += 10

    if sender and reply_to:
        reply_domain = reply_to.split("@")[-1].lower()
        sender_domain = sender.split("@")[-1].lower()
        if sender_domain != reply_domain:
            indicators.append(_make_indicator("Reply-to Domain Mismatch", 14, "Medium", "The sender and reply-to addresses use different domains, which is a common scam pattern when attackers hide their real return address.", [sender, reply_to]))
            score += 14
            evidence.append("Reply-to domain differs from sender domain")

    if any(brand in lower_message for brand in BRAND_KEYWORDS):
        sender_domain = sender.split("@")[-1].lower() if sender else ""
        if not sender_domain or not any(brand in sender_domain for brand in BRAND_KEYWORDS):
            indicators.append(_make_indicator("Brand Impersonation in Content", 15, "High", "The message references a trusted brand without a matching sender domain, which suggests impersonation or social engineering.", [subject, sender]))
            score += 15
            evidence.append("Message references a trusted brand without a legitimate domain match")

    if extracted_urls:
        url_findings = []
        for item in extracted_urls:
            url_result = analyze_url(item)
            url_findings.append({"url": item, "result": url_result})
            if url_result["risk_score"] >= 15:
                score += min(18, url_result["risk_score"] // 2)
                evidence.append(f"Suspicious URL detected: {item}")
        if url_findings:
            indicators.append(_make_indicator("Suspicious Embedded URL", 20, "High", "One or more embedded links were flagged by phishing heuristics and may redirect to deceptive or malicious destinations.", [f"{len(url_findings)} URL(s) found"]))
            score += 20

    if any(token in lower_message for token in ["click here", "verify account", "update details", "confirm payment", "claim prize"]):
        indicators.append(_make_indicator("Social Engineering Pattern", 12, "Medium", "The message prompts the recipient to take action using urgency or deceptive instructions, a common phishing technique.", [subject]))
        score += 12
        evidence.append("Message uses social-engineering language")

    if sender and any(block in sender.lower() for block in ["admin", "security", "alert", "verify", "service"]):
        indicators.append(_make_indicator("Suspicious Sender Address Pattern", 9, "Low", "The sender address itself contains reminder-type phrases that are often used to imitate institutional or security alerts.", [sender]))
        score += 9

    unique_indicators = []
    seen_names = set()
    for indicator in indicators:
        if indicator["name"] not in seen_names:
            unique_indicators.append(indicator)
            seen_names.add(indicator["name"])

    final_score = min(100, score)
    risk_level = _risk_label(final_score)
    recommendations = [
        "Do not click embedded links or open attachments until you verify the message through an independent channel.",
        "If the sender claims to be a trusted organization, contact the company using a known, official number or website.",
        "Avoid sharing passwords, OTPs, or payment details unless the request is independently verified.",
    ]
    limitations = [
        "This is a rule-based phishing assessment and should not be treated as a definitive verdict.",
        "A low score does not guarantee a message is safe; some targeted phishing attempts may blend in with legitimate communications.",
    ]

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "confidence": "rule-based evidence" if final_score > 0 else "limited evidence",
        "summary": "The message was evaluated for urgency, impersonation, request patterns, and suspicious URLs.",
        "indicators": unique_indicators,
        "recommendations": recommendations,
        "limitations": limitations,
        "evidence": evidence,
        "analysis_type": "email",
        "submitted": {
            "subject": subject,
            "sender_email": sender,
            "display_name": display_name,
            "reply_to": reply_to,
            "message_preview": (message[:220] + "...") if len(message) > 220 else message,
            "urls": extracted_urls,
        },
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


if __name__ == "__main__":
    sample = {
        "subject": "Urgent: Account Verification Required",
        "sender_email": "security@paypa1-update.com",
        "display_name": "PayPal Security Team",
        "reply_to": "noreply@mailer.com",
        "message": "Your account has been suspended. Verify immediately to avoid service disruption. Use the link below and provide your password and OTP.",
        "manual_url": "https://bit.ly/verify-paypal-secure-login",
    }
    print(json.dumps(analyze_email(sample), indent=2))
