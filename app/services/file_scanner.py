import re, uuid
from ..schemas.common import ScanResponse, Finding

PATTERNS=[
("Private key",r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----","CRITICAL"),
("AWS access key",r"\bAKIA[0-9A-Z]{16}\b","HIGH"),
("JWT-like token",r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b","HIGH"),
("API key assignment",r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]","HIGH"),
]

async def scan_file(filename:str,data:bytes)->ScanResponse:
    if len(data)>5*1024*1024: raise ValueError("File is larger than the 5 MB analysis limit.")
    try: text=data.decode("utf-8",errors="replace")
    except Exception: text=""
    findings=[]; score=0
    for name,pattern,severity in PATTERNS:
        for m in re.finditer(pattern,text):
            line=text.count("\n",0,m.start())+1
            findings.append(Finding(id=f"file-{len(findings)}",title=f"Potential {name}",severity=severity,description="A credential-like pattern was found in the uploaded file.",evidence=m.group(0)[:80],remediation="Remove/rotate exposed credentials and store secrets securely.",file=filename,line=line))
            score+= {"CRITICAL":40,"HIGH":25,"MEDIUM":10,"LOW":5,"INFO":0}[severity]
    score=min(100,score); level="SAFE" if score<15 else "LOW" if score<35 else "MEDIUM" if score<60 else "HIGH" if score<80 else "CRITICAL"
    return ScanResponse(scan_id=str(uuid.uuid4()),scan_type="file",target=filename,score=score,threat_level=level,findings=findings,summary=f"Static analysis found {len(findings)} credential/suspicious-pattern findings.",limitations=["This does not execute the file or perform antivirus/malware sandboxing.","Results are heuristic and should be manually verified."],metadata={"size_bytes":len(data)})
