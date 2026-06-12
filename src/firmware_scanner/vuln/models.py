"""Vulnerability scanning data models."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class VulnReference(BaseModel):
    url: str
    type: str = ""


class Vulnerability(BaseModel):
    id: str
    summary: str = ""
    details: str = ""
    aliases: list[str] = []
    severity: Severity = Severity.UNKNOWN
    cvss_score: float | None = None
    cvss_vector: str = ""
    affected_versions: str = ""
    fixed_version: str = ""
    references: list[VulnReference] = []
    published: str = ""
    modified: str = ""


class ComponentVulnResult(BaseModel):
    component_name: str
    component_version: str
    purl: str = ""
    cpe: str = ""
    vulnerabilities: list[Vulnerability] = []
    query_error: str = ""


class VulnScanResult(BaseModel):
    firmware_path: str = ""
    firmware_sha256: str = ""
    scan_timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    total_components_scanned: int = 0
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    unknown_count: int = 0
    results: list[ComponentVulnResult] = []
    errors: list[str] = []
