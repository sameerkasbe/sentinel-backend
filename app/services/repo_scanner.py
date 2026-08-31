import base64, re, uuid
from urllib.parse import urlparse
import httpx
from ..schemas.common import ScanResponse, Finding

SECRET_PATTERNS = [
    ("AWS access key", r"\bAKIA[0-9A-Z]{16}\b", "HIGH"),
    ("Private key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "CRITICAL"),
    ("Generic API key assignment", r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "HIGH"),
    ("JWT-like token", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "HIGH"),
]

async def _github_get(client, url, headers):
    r = await client.get(url, headers=headers, timeout=20)
    r.raise_for_status()
    return r.json()

def _parse_repo(url: str):
    p = urlparse(url)
    if p.netloc.lower() not in {"github.com", "www.github.com"}:
        raise ValueError("Only public GitHub repository URLs are supported by this scanner.")
    parts = [x for x in p.path.split("/") if x]
    if len(parts) < 2:
        raise ValueError("Invalid GitHub repository URL")
    return parts[0], parts[1].removesuffix(".git")

async def scan_repo(url: str, branch: str | None, github_token: str = "") -> ScanResponse:
    owner, repo = _parse_repo(str(url))
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "Sentinel-Security-Scanner/1.0"}
    if github_token: headers["Authorization"] = f"Bearer {github_token}"
    findings=[]; metadata={"owner":owner,"repository":repo}; score=0
    async with httpx.AsyncClient(follow_redirects=True) as client:
        repo_info = await _github_get(client, f"https://api.github.com/repos/{owner}/{repo}", headers)
        ref = branch or repo_info.get("default_branch", "main")
        tree = await _github_get(client, f"https://api.github.com/repos/{owner}/{repo}/git/trees/{ref}?recursive=1", headers)
        files=[x for x in tree.get("tree",[]) if x.get("type")=="blob"]
        metadata.update({"default_branch":repo_info.get("default_branch"),"private":repo_info.get("private"),"file_count":len(files)})
        max_files=150; max_bytes=200_000; scanned=0
        for item in files[:max_files]:
            path=item.get("path","")
            if any(part.startswith(".") and part not in {".env"} for part in path.split("/")) and path.startswith(".git/"): continue
            if item.get("size",0)>max_bytes: continue
            raw_url=f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
            try:
                r=await client.get(raw_url,headers={"User-Agent":headers["User-Agent"]},timeout=15)
                if r.status_code!=200: continue
                text=r.text[:max_bytes]
                scanned+=1
                for name,pattern,severity in SECRET_PATTERNS:
                    for m in re.finditer(pattern,text):
                        line=text.count("\n",0,m.start())+1
                        findings.append(Finding(id=f"secret-{len(findings)}",title=f"Potential {name}",severity=severity,description="A credential-like pattern was found in repository content. Verify whether it is a real secret and rotate it if exposed.",evidence=m.group(0)[:80],remediation="Remove the secret, rotate/revoke it, and use a secure secret manager.",file=path,line=line))
                        score += {"CRITICAL":40,"HIGH":25,"MEDIUM":10,"LOW":5,"INFO":0}[severity]
            except Exception:
                continue
    metadata["files_scanned"]=scanned
    if repo_info.get("security_and_analysis",{}).get("secret_scanning",{}).get("status")=="enabled":
        metadata["github_secret_scanning_enabled"]=True
    score=min(100,score)
    level="SAFE" if score<15 else "LOW" if score<35 else "MEDIUM" if score<60 else "HIGH" if score<80 else "CRITICAL"
    return ScanResponse(scan_id=str(uuid.uuid4()),scan_type="repository",target=str(url),score=score,threat_level=level,findings=findings,summary=f"Scanned {scanned} repository files for common exposed-secret patterns. Score: {score}/100.",limitations=["Static pattern analysis only; it does not execute code.","This is not a complete SAST/dependency vulnerability scan.","Only public GitHub repositories are supported in this implementation."],metadata=metadata)
