import re


def detect_scam_indicators(
    description,
    salary,
    email,
    company,
    nlp_keywords=None
):
    """
    Detect potential scam indicators in a job posting.
    """

    score = 0
    indicators = []
        # --------------------------------------------------
    # NLP-based suspicious keyword detection
    # --------------------------------------------------

    suspicious_nlp_keywords = [
        "urgent",
        "immediately",
        "registration",
        "processing",
        "telegram",
        "whatsapp",
        "payment",
        "fee",
        "deposit",
        "today"
    ]

    if nlp_keywords:

        matched_nlp_keywords = [
            keyword
            for keyword in nlp_keywords
            if keyword in suspicious_nlp_keywords
        ]

        if matched_nlp_keywords:
            score += min(len(matched_nlp_keywords) * 5, 15)

            indicators.append(
                "Suspicious NLP keywords detected: "
                + ", ".join(matched_nlp_keywords)
            )

    description_lower = str(description).lower()
    email_lower = str(email).lower()
    company_lower = str(company).lower()

    # --------------------------------------------------
    # 1. Payment request
    # --------------------------------------------------

    payment_keywords = [
        "registration fee",
        "processing fee",
        "application fee",
        "pay a fee",
        "payment required",
        "pay money",
        "pay upfront",
        "security deposit"
    ]

    if any(keyword in description_lower for keyword in payment_keywords):
        score += 25
        indicators.append("Payment/registration fee requested")

    # --------------------------------------------------
    # 2. Financial information
    # --------------------------------------------------

    financial_keywords = [
        "bank information",
        "bank details",
        "account number",
        "credit card",
        "debit card",
        "bank information"
    ]

    if any(keyword in description_lower for keyword in financial_keywords):
        score += 20
        indicators.append("Financial/bank information requested")

    # --------------------------------------------------
    # 3. Personal email
    # --------------------------------------------------

    personal_email_domains = [
        "@gmail.com",
        "@yahoo.com",
        "@hotmail.com",
        "@outlook.com"
    ]

    if any(domain in email_lower for domain in personal_email_domains):
        score += 10
        indicators.append("Personal email address used")

    # --------------------------------------------------
    # 4. Urgency
    # --------------------------------------------------

    urgency_keywords = [
        "urgent",
        "immediately",
        "today only",
        "act now",
        "apply immediately",
        "limited time"
    ]

    if any(keyword in description_lower for keyword in urgency_keywords):
        score += 10
        indicators.append("Urgency/pressure language detected")

    # --------------------------------------------------
    # 5. Messaging platforms
    # --------------------------------------------------

    messaging_keywords = [
        "telegram",
        "whatsapp"
    ]

    if any(keyword in description_lower for keyword in messaging_keywords):
        score += 10
        indicators.append("Recruitment through messaging platform")

    # --------------------------------------------------
    # 6. Suspicious URLs
    # --------------------------------------------------

    url_pattern = r"https?://[^\s]+"
    urls = re.findall(url_pattern, description_lower)

    suspicious_domains = [
        "bit.ly",
        "tinyurl.com",
        "t.me",
        "wa.me"
    ]

    if any(
        any(domain in url for domain in suspicious_domains)
        for url in urls
    ):
        score += 15
        indicators.append("Suspicious or shortened URL detected")

    # --------------------------------------------------
    # 7. Missing company information
    # --------------------------------------------------

    if company_lower.strip() in ["", "unknown", "n/a", "none"]:
        score += 10
        indicators.append("Missing or unidentified company information")

    # --------------------------------------------------
    # 8. Salary anomaly
    # --------------------------------------------------

    if salary > 5000000:
        score += 15
        indicators.append("Potentially unrealistic salary")

    # --------------------------------------------------
    # Maximum score
    # --------------------------------------------------

    score = min(score, 100)

    # --------------------------------------------------
    # Risk level
    # --------------------------------------------------

    if score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return score, risk_level, indicators