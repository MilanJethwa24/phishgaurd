"""Static URL analysis. The URL is ONLY parsed as text - it is never visited or opened."""
import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {"zip", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "country", "loan", "ru"}
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly"}
BRANDS = ["paypal", "apple", "microsoft", "amazon", "netflix", "google", "bank", "facebook", "instagram"]
SUSPICIOUS_WORDS = ["login", "verify", "secure", "account", "update", "signin", "banking", "confirm", "password", "wallet"]
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def analyze_url(url):
    """Return (score 0-100, warnings list). Pure string analysis."""
    warnings, score = [], 0
    raw = url.strip()
    to_parse = raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw) else "http://" + raw
    try:
        parsed = urlparse(to_parse)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return 80, ["URL could not be parsed (malformed or invalid port)"]

    if not host:
        return 60, ["URL has no valid host name"]

    if len(raw) > 75:
        warnings.append(f"Very long URL ({len(raw)} characters)")
        score += 15 if len(raw) > 100 else 10
    if IP_RE.match(host):
        warnings.append("Uses a raw IP address instead of a domain name")
        score += 25
    if "@" in raw:
        warnings.append("Contains '@' which can hide the real destination")
        score += 25
    if host.count(".") > 3:
        warnings.append(f"Many dots in host name ({host.count('.')})")
        score += 10
    if host.count("-") >= 2:
        warnings.append(f"Multiple hyphens in domain ({host.count('-')})")
        score += 10
    elif "-" in host:
        score += 4
    parts = host.split(".")
    if not IP_RE.match(host) and len(parts) > 3:
        warnings.append(f"Excessive subdomains ({len(parts) - 2})")
        score += 10
    if port and port not in (80, 443):
        warnings.append(f"Unusual port number ({port})")
        score += 15
    if "%" in raw and re.search(r"%[0-9a-fA-F]{2}", raw):
        warnings.append("Contains URL-encoded characters that may hide content")
        score += 10
    if parsed.scheme != "https":
        warnings.append("Does not use HTTPS")
        score += 10
    if "//" in parsed.path:
        warnings.append("Contains '//' redirection inside the path")
        score += 10
    if host.startswith("xn--") or ".xn--" in host:
        warnings.append("Uses punycode (possible look-alike domain)")
        score += 20
    tld = parts[-1] if parts else ""
    if tld in SUSPICIOUS_TLDS:
        warnings.append(f"Suspicious top-level domain (.{tld})")
        score += 10
    if host in SHORTENERS:
        warnings.append("URL shortener hides the final destination")
        score += 15
    lower = raw.lower()
    found = [w for w in SUSPICIOUS_WORDS if w in lower]
    if found:
        warnings.append("Suspicious words in URL: " + ", ".join(found))
        score += min(5 * len(found), 15)
    registered = ".".join(parts[-2:]) if len(parts) >= 2 else host
    for brand in BRANDS:
        if brand in host and not registered.startswith(brand + "."):
            warnings.append(f"Mentions brand '{brand}' but is not the official domain")
            score += 20
            break
    if sum(c.isdigit() for c in host) > 5:
        warnings.append("Many digits in domain name")
        score += 5

    return min(score, 100), warnings
