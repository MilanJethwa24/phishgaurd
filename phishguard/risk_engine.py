"""Combine ML, keyword and URL scores into one 0-100 risk score."""
from detector import ml_score, keyword_analysis, extract_urls
from url_detector import analyze_url


def classify(score):
    if score >= 60:
        return "High Risk"
    if score >= 30:
        return "Suspicious"
    return "Low Risk"


def scan_message(text):
    ml = ml_score(text)
    kw, warnings = keyword_analysis(text)
    url_score = 0
    for u in extract_urls(text):
        s, w = analyze_url(u)
        if s > url_score:
            url_score = s
        warnings.extend(f"Link '{u[:60]}': {x}" for x in w)

    urls_present = bool(extract_urls(text))
    if urls_present:
        risk = 0.5 * ml + 0.25 * kw + 0.25 * url_score
    else:
        risk = 0.6 * ml + 0.4 * kw
    risk = max(risk, ml * 0.9 if ml > 85 else 0)
    risk = int(round(min(max(risk, 0), 100)))
    if ml >= 70:
        warnings.insert(0, f"Machine learning model rates this {ml}% likely phishing")
    if not warnings:
        warnings.append("No suspicious indicators found")
    return _result(risk, ml, kw, url_score, warnings)


def scan_url(url):
    url_score, warnings = analyze_url(url)
    kw, kw_warn = keyword_analysis(url.replace("/", " ").replace(".", " ").replace("-", " "))
    risk = int(round(min(0.8 * url_score + 0.2 * kw, 100)))
    warnings += [w for w in kw_warn if w not in warnings]
    if not warnings:
        warnings.append("No suspicious indicators found")
    return _result(risk, 0.0, kw, url_score, warnings)


def _result(risk, ml, kw, url_score, warnings):
    return {
        "risk_score": risk,
        "classification": classify(risk),
        "ml_score": round(ml, 1),
        "keyword_score": round(kw, 1),
        "url_score": round(url_score, 1),
        "warnings": warnings,
    }
