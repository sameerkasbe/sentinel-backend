from pydantic import BaseModel, Field, HttpUrl
from typing import Literal, Any

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
ThreatLevel = Literal["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    description: str
    evidence: str | None = None
    remediation: str | None = None
    file: str | None = None
    line: int | None = None

class ScanResponse(BaseModel):
    scan_id: str
    scan_type: str
    target: str
    score: int = Field(ge=0, le=100)
    threat_level: ThreatLevel
    findings: list[Finding]
    summary: str
    limitations: list[str] = []
    metadata: dict[str, Any] = {}

class UrlScanRequest(BaseModel):
    url: HttpUrl

class RepoScanRequest(BaseModel):
    repository_url: HttpUrl
    branch: str | None = None

class AssistantRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    context: dict[str, Any] | None = None

class AssistantResponse(BaseModel):
    answer: str
    suggested_actions: list[str] = []
