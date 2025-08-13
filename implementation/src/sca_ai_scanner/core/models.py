"""
Core data models for the AI-powered SCA vulnerability scanner.
Optimized for AI Agent First operation with structured, machine-readable formats.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Union, Any
from pydantic import BaseModel, Field, validator


class Severity(str, Enum):
    """CVE severity levels following CVSS standards."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH" 
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FileType(str, Enum):
    """Supported dependency file types."""
    REQUIREMENTS = "requirements"
    PYPROJECT_TOML = "pyproject_toml"
    PACKAGE_JSON = "package_json"
    YARN_LOCK = "yarn_lock"
    COMPOSER_JSON = "composer_json"
    GEMFILE = "gemfile"
    GO_MOD = "go_mod"


class SourceLocation(BaseModel):
    """Precise location where a dependency is declared.
    
    CRITICAL: file_path MUST be absolute path for unambiguous identification.
    """
    file_path: str = Field(..., description="ABSOLUTE path to the file containing the dependency - never relative paths")
    line_number: int = Field(..., description="Line number where dependency is declared (1-indexed)")
    declaration: str = Field(..., description="Exact text of the dependency declaration")
    file_type: FileType = Field(..., description="Type of dependency file")


class Package(BaseModel):
    """Package dependency with COMPLETE source location tracking.
    
    CRITICAL: Must include ALL locations where package appears - NO SAMPLING.
    """
    name: str = Field(..., description="Package name")
    version: str = Field(..., description="Package version")
    source_locations: List[SourceLocation] = Field(
        default_factory=list, 
        description="COMPLETE list of ALL locations where this package is declared - NEVER truncated or sampled"
    )
    ecosystem: str = Field(..., description="Package ecosystem (npm, pypi, etc.)")
    
    @validator('name')
    def validate_name(cls, v):
        if not v or not v.strip():
            raise ValueError("Package name cannot be empty")
        return v.strip()
    
    @validator('version') 
    def validate_version(cls, v):
        if not v or not v.strip():
            raise ValueError("Package version cannot be empty")
        return v.strip()
    
    @validator('source_locations')
    def validate_complete_source_locations(cls, v):
        """Ensure source location list is complete - prevent accidental truncation."""
        # This validator serves as documentation that source location lists must be complete
        if hasattr(v, '__truncated__') or hasattr(v, '__sampled__'):
            raise ValueError("Source location list appears to be truncated or sampled - this is a critical security violation")
        return v


class CVEFinding(BaseModel):
    """Individual CVE vulnerability finding."""
    id: str = Field(..., description="CVE identifier (e.g., CVE-2023-32681)")
    severity: Severity = Field(..., description="Vulnerability severity level")
    description: str = Field(..., description="Vulnerability description")
    cvss_score: Optional[float] = Field(None, description="CVSS base score (0.0-10.0)")
    publish_date: Optional[datetime] = Field(None, description="CVE publication date")
    data_source: str = Field(default="ai_knowledge", description="Source of vulnerability data")
    
    @validator('cvss_score')
    def validate_cvss_score(cls, v):
        if v is not None and (v < 0.0 or v > 10.0):
            raise ValueError("CVSS score must be between 0.0 and 10.0")
        return v


class RiskAssessment(BaseModel):
    """Business risk assessment for AI agent decision making."""
    score: float = Field(..., description="Risk score (0.0-10.0)")
    business_impact: str = Field(..., description="Business impact description")
    exploitability: str = Field(..., description="Exploitability assessment")
    status: str = Field(default="vulnerable", description="Overall security status")


class RemediationIntelligence(BaseModel):
    """Actionable remediation data optimized for AI agent consumption."""
    action: str = Field(..., description="Recommended action (upgrade, patch, etc.)")
    target_version: Optional[str] = Field(None, description="Target version for upgrade")
    urgency: str = Field(..., description="Remediation urgency level")
    estimated_effort: str = Field(..., description="Estimated implementation effort")
    affected_files: List[str] = Field(
        default_factory=list,
        description="List of files requiring changes (file:line format)"
    )
    upgrade_path: Optional[Dict[str, str]] = Field(
        None, 
        description="Version upgrade path information"
    )
    # New: Strategy-based recommendations
    strategy_used: Optional[str] = Field(None, description="Recommendation strategy used")
    alternative_options: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Alternative remediation options with different trade-offs"
    )


class PackageAnalysis(BaseModel):
    """Complete vulnerability analysis for a single package.
    
    CRITICAL: Must include ALL CVEs found - NO SAMPLING OR TRUNCATION.
    """
    cves: List[CVEFinding] = Field(
        default_factory=list, 
        description="COMPLETE list of ALL CVE findings - NEVER truncated, limited, or sampled"
    )
    confidence: float = Field(..., description="Analysis confidence (0.0-1.0)")
    analysis_timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    @validator('confidence')
    def validate_confidence(cls, v):
        if v < 0.0 or v > 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0")
        return v
    
    @validator('cves')
    def validate_complete_cves(cls, v):
        """Ensure CVE list is complete - prevent accidental truncation."""
        # This validator serves as documentation that CVE lists must be complete
        # In practice, truncation would happen at collection time, not here
        if hasattr(v, '__truncated__') or hasattr(v, '__sampled__'):
            raise ValueError("CVE list appears to be truncated or sampled - this is a critical security violation")
        return v


class VulnerabilitySummary(BaseModel):
    """Summary statistics for AI agent consumption."""
    total_packages_analyzed: int = Field(..., description="Total packages analyzed")
    vulnerable_packages: int = Field(..., description="Number of vulnerable packages")
    severity_breakdown: Dict[str, int] = Field(
        default_factory=dict,
        description="Count by severity level"
    )
    recommended_next_steps: List[str] = Field(
        default_factory=list,
        description="AI agent next steps"
    )


class AIAgentMetadata(BaseModel):
    """Metadata optimized for AI agent workflow orchestration."""
    workflow_stage: str = Field(..., description="Current workflow stage")
    confidence_level: str = Field(..., description="Overall confidence level")
    autonomous_action_recommended: bool = Field(
        ..., 
        description="Whether AI agent can proceed autonomously"
    )
    optimization_opportunities: List[str] = Field(
        default_factory=list,
        description="Detected optimization opportunities"
    )


class VulnerabilityResults(BaseModel):
    """COMPLETE vulnerability analysis results optimized for AI agent consumption.
    
    CRITICAL: Contains ALL vulnerabilities and ALL source locations - NO SAMPLING.
    Any truncation or incomplete data constitutes a security failure.
    """
    ai_agent_metadata: AIAgentMetadata = Field(..., description="AI agent workflow metadata")
    vulnerability_analysis: Dict[str, PackageAnalysis] = Field(
        default_factory=dict,
        description="COMPLETE package analysis results keyed by package:version - ALL packages included"
    )
    vulnerability_summary: VulnerabilitySummary = Field(..., description="Summary statistics")
    scan_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Scan execution metadata"
    )
    source_locations: Dict[str, List[SourceLocation]] = Field(
        default_factory=dict,
        description="COMPLETE source code locations for each package - ALL locations included, NEVER truncated"
    )
    
    def get_vulnerable_packages(self) -> List[str]:
        """Get list of vulnerable package identifiers."""
        return [
            pkg_id for pkg_id, analysis in self.vulnerability_analysis.items()
            if analysis.cves
        ]
    
    def get_packages_by_severity(self, severity: Severity) -> List[str]:
        """Get packages with findings of specified severity."""
        result = []
        for pkg_id, analysis in self.vulnerability_analysis.items():
            if any(cve.severity == severity for cve in analysis.cves):
                result.append(pkg_id)
        return result
    
    def get_high_confidence_findings(self, threshold: float = 0.9) -> Dict[str, PackageAnalysis]:
        """Get findings with confidence above threshold."""
        return {
            pkg_id: analysis 
            for pkg_id, analysis in self.vulnerability_analysis.items()
            if analysis.confidence >= threshold
        }


class ScanConfig(BaseModel):
    """Scan configuration for AI-powered analysis."""
    model: str = Field(default="gpt-4o-mini-with-search", description="AI model for analysis")
    enable_live_search: bool = Field(default=True, description="Enable live web search")
    context_optimization: bool = Field(default=True, description="Auto-optimize for model context window")
    batch_size: Optional[int] = Field(default=None, description="Override batch size (rare edge cases only)")
    confidence_threshold: float = Field(default=0.8, description="Minimum confidence")
    max_retries: int = Field(default=3, description="Max retry attempts")
    timeout_seconds: int = Field(default=30, description="Request timeout")
    budget_enabled: bool = Field(default=False, description="Enable budget limits")
    daily_budget_limit: float = Field(default=50.0, description="Daily spending limit USD (when enabled)")
    validate_critical: bool = Field(default=False, description="Validate critical findings")
    # New: Recommendation strategy configuration
    recommendation_strategy: str = Field(default="balanced_security", description="Recommendation strategy name")
    custom_strategy_path: Optional[str] = Field(None, description="Path to custom strategy YAML file")
    
    @validator('batch_size')
    def validate_batch_size(cls, v):
        if v is not None and (v < 1 or v > 200):
            raise ValueError("Batch size must be between 1 and 200")
        return v
    
    @validator('confidence_threshold')
    def validate_confidence_threshold(cls, v):
        if v < 0.0 or v > 1.0:
            raise ValueError("Confidence threshold must be between 0.0 and 1.0")
        return v


class TelemetryEvent(BaseModel):
    """Structured telemetry event for AI agent optimization."""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str = Field(..., description="Event type (scan_start, batch_complete, etc.)")
    session_id: str = Field(..., description="Unique session identifier")
    data: Dict[str, Any] = Field(default_factory=dict, description="Event-specific data")
    context: Dict[str, Any] = Field(default_factory=dict, description="Execution context")
    ai_agent_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="AI agent optimization metadata"
    )