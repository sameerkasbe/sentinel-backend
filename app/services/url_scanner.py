import re, uuid
from urllib.parse import urlparse
import httpx
from bs4 import BeautifulSoup
from ..schemas.common import ScanResponse, Finding

SUSPICIOUS_WORDS = {"login", "verify", "verification", "password", "wallet", "bonus", "gift", "urgent", "secure", "account"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly"}

async def scan_url(url: str) -> ScanResponse:
    parsed = urlparse(url)
    findings: list[Finding] = []
    metadata = {"hostname": parsed.hostname, "scheme": parsed.scheme}
    score = 0
    if parsed.scheme != "https":
        score += 25
        findings.append(Finding(id="url-https", title="HTTPS is not used", severity="MEDIUM", description="The submitted URL does not use HTTPS.", remediation="Prefer HTTPS for sensitive traffic."))
    if parsed.hostname and parsed.hostname.lower() in SHORTENERS:
        score += 20
        findings.append(Finding(id="url-shortener", title="URL shortener detected", severity="LOW", description="The hostname is a known URL-shortening service, which can hide the final destination.", remediation="Expand and verify the final destination before trusting it."))
    if parsed.hostname and parsed.hostname.count(".") >= 3:
        score += 10
        findings.append(Finding(id="url-subdomains", title="Many subdomain levels", severity="LOW", description="The hostname contains several subdomain levels. This is not malicious by itself, but can be worth reviewing."))
    if "@" in parsed.netloc:
        score += 35
        findings.append(Finding(id="url-at", title="Credential-style URL syntax", severity="HIGH", description="An @ character appears in the authority portion of the URL, which can be used to obscure the real hostname.", evidence=parsed.netloc, remediation="Do not open the URL until its real destination is verified."))
    text = (parsed.path + "?" + parsed.query).lower()
    hits = sorted(w for w in SUSPICIOUS_WORDS if w in text)
    if hits:
        score += min(20, len(hits) * 5)
        findings.append(Finding(id="url-keywords", title="Sensitive or urgency-related URL terms", severity="LOW", description="The URL contains terms commonly seen in login, verification, or urgency-themed links.", evidence=", ".join(hits)))

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10, headers={"User-Agent": "Sentinel-Security-Scanner/1.0"}) as client:
            r = await client.get(url)
            metadata.update({"status_code": r.status_code, "final_url": str(r.url), "redirects": len(r.history), "content_type": r.headers.get("content-type")})
            if len(r.history) >= 3:
                score += 10
                findings.append(Finding(id="url-redirects", title="Multiple redirects", severity="LOW", description="The URL redirected multiple times before reaching its final destination."))
            soup = BeautifulSoup(r.text[:500_000], "html.parser")
            title = soup.title.get_text(" ", strip=True) if soup.title else None
            metadata["page_title"] = title
            forms = soup.find_all("form")
            password_forms = sum(1 for f in forms if f.find("input", attrs={"type": "password"}))
            metadata["forms"] = len(forms)
            metadata["password_forms"] = password_forms
            if password_forms and parsed.scheme != "https":
                score += 30
                findings.append(Finding(id="url-password-http", title="Password form over HTTP", severity="CRITICAL", description="A password input was detected on a page loaded without HTTPS.", remediation="Do not submit credentials; use a verified HTTPS destination."))
    except Exception as exc:
        metadata["fetch_error"] = str(exc)
        findings.append(Finding(id="url-fetch", title="Could not fetch target", severity="INFO", description="Sentinel could not retrieve the target for deeper analysis. This is not evidence that the URL is safe or malicious."))

    score = min(100, score)
    level = "SAFE" if score < 15 else "LOW" if score < 35 else "MEDIUM" if score < 60 else "HIGH" if score < 80 else "CRITICAL"
    return ScanResponse(scan_id=str(uuid.uuid4()), scan_type="url", target=url, score=score, threat_level=level, findings=findings, summary=f"Static URL/page checks produced a risk score of {score}/100.", limitations=["This is heuristic analysis, not a malware/reputation verdict.", "No commercial threat-intelligence reputation feed is queried by default."], metadata=metadata)
