"""Data models for JimCrow"""

from pydantic import BaseModel, HttpUrl, Field
from typing import List, Dict, Any, Literal
from datetime import datetime
from enum import Enum


class RiskLevel(str, Enum):
    """Risk level for pentesting actions"""
    SAFE = "safe"
    MODERATE = "moderate"
    RISKY = "risky"


class SeverityLevel(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanMode(str, Enum):
    """Scan execution modes"""
    AUTONOMOUS = "autonomous"  # Single intelligent autonomous mode


class ScanStatus(str, Enum):
    """Scan execution status"""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class VulnerabilityType(str, Enum):
    """OWASP vulnerability categories"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    BROKEN_AUTH = "broken_authentication"
    SENSITIVE_DATA = "sensitive_data_exposure"
    BROKEN_ACCESS = "broken_access_control"
    SECURITY_MISCONFIG = "security_misconfiguration"
    XXE = "xxe"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    KNOWN_VULNERABILITIES = "known_vulnerabilities"
    INSUFFICIENT_LOGGING = "insufficient_logging"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    OPEN_REDIRECT = "open_redirect"


class Target(BaseModel):
    """Scan target configuration"""
    url: str
    authorized: bool = False
    scope_patterns: List[str] = Field(default_factory=list)
    excluded_patterns: List[str] = Field(default_factory=list)
    custom_headers: Dict[str, str] = Field(default_factory=dict)
    auth_config: Dict[str, Any] | None = None


class PentestAction(BaseModel):
    """Individual pentesting action"""
    action_id: str
    action_type: str
    description: str
    risk_level: RiskLevel
    target_url: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    requires_approval: bool = True


class Vulnerability(BaseModel):
    """Discovered vulnerability"""
    vuln_id: str
    vuln_type: VulnerabilityType
    severity: SeverityLevel
    title: str
    description: str
    affected_url: str
    evidence: str
    reproduction_steps: List[str]
    remediation: str
    cwe_id: str | None = None
    cvss_score: float | None = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    

class ScanResult(BaseModel):
    """Scan execution result"""
    scan_id: str
    target: Target
    mode: ScanMode
    status: ScanStatus
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    urls_discovered: int = 0
    actions_performed: int = 0
    start_time: datetime
    end_time: datetime | None = None
    error_message: str | None = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentState(BaseModel):
    """Agent execution state"""
    scan_id: str
    current_phase: str
    urls_to_scan: List[str] = Field(default_factory=list)
    scanned_urls: List[str] = Field(default_factory=list)
    discovered_forms: List[Dict[str, Any]] = Field(default_factory=list)
    discovered_endpoints: List[str] = Field(default_factory=list)
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    pending_actions: List[PentestAction] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict)


class ScanRequest(BaseModel):
    """Request to start a new scan"""
    target_url: str
    mode: ScanMode = ScanMode.AUTONOMOUS
    custom_headers: Dict[str, str] = Field(default_factory=dict)
    auth_config: Dict[str, Any] | None = None
    scope_patterns: List[str] = Field(default_factory=list)
    excluded_patterns: List[str] = Field(default_factory=list)


class ApprovalRequest(BaseModel):
    """Request for user approval"""
    scan_id: str
    action: PentestAction
    rationale: str


class ApprovalResponse(BaseModel):
    """User approval response"""
    approved: bool
    reason: str | None = None

