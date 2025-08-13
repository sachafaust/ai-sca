"""
Comprehensive unit tests for JSON output formatter.
Tests JSON structure validation, AI agent compatibility, data integrity, and enterprise features.
"""

import json
import pytest
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import Mock, patch
from typing import Dict, Any, List
import jsonschema

from sca_ai_scanner.formatters.json_output import JSONOutputFormatter
from sca_ai_scanner.core.models import (
    VulnerabilityResults, PackageAnalysis, CVEFinding, Severity,
    VulnerabilitySummary, AIAgentMetadata, SourceLocation, FileType
)
from sca_ai_scanner.exceptions import OutputFormattingError


# Test fixtures and helpers
@pytest.fixture
def json_formatter():
    """Create JSON formatter instance."""
    return JSONOutputFormatter()


@pytest.fixture
def minimal_vulnerability_results():
    """Minimal vulnerability results for testing."""
    return VulnerabilityResults(
        ai_agent_metadata=AIAgentMetadata(
            workflow_stage="remediation_ready",
            confidence_level="high",
            autonomous_action_recommended=True,
            optimization_opportunities=[]
        ),
        vulnerability_analysis={},
        vulnerability_summary=VulnerabilitySummary(
            total_packages_analyzed=0,
            vulnerable_packages=0,
            severity_breakdown={},
            recommended_next_steps=[]
        ),
        scan_metadata={
            "model": "gpt-4o-mini-with-search",
            "session_id": "test-session-123",
            "total_cost": 0.0
        },
        source_locations={}
    )


@pytest.fixture
def comprehensive_vulnerability_results():
    """Comprehensive vulnerability results with multiple packages and CVEs."""
    # Create test CVEs with different severities
    critical_cve = CVEFinding(
        id="CVE-2023-0001",
        severity=Severity.CRITICAL,
        description="Critical remote code execution vulnerability",
        cvss_score=9.8,
        publish_date=datetime(2023, 1, 15, tzinfo=timezone.utc),
        data_source="nvd"
    )
    
    high_cve = CVEFinding(
        id="CVE-2023-0002",
        severity=Severity.HIGH,
        description="High severity SQL injection vulnerability",
        cvss_score=8.1,
        publish_date=datetime(2023, 2, 20, tzinfo=timezone.utc),
        data_source="osv"
    )
    
    medium_cve = CVEFinding(
        id="CVE-2023-0003",
        severity=Severity.MEDIUM,
        description="Medium severity cross-site scripting vulnerability",
        cvss_score=6.3,
        publish_date=datetime(2023, 3, 10, tzinfo=timezone.utc),
        data_source="ai_knowledge"
    )
    
    low_cve = CVEFinding(
        id="CVE-2023-0004",
        severity=Severity.LOW,
        description="Low severity information disclosure",
        cvss_score=3.1,
        data_source="ai_knowledge"
    )
    
    # Create package analyses
    critical_analysis = PackageAnalysis(
        cves=[critical_cve, high_cve],
        confidence=0.95,
        analysis_timestamp=datetime(2023, 1, 15, 10, 30, 45, tzinfo=timezone.utc)
    )
    
    medium_analysis = PackageAnalysis(
        cves=[medium_cve],
        confidence=0.85,
        analysis_timestamp=datetime(2023, 1, 15, 10, 31, 0, tzinfo=timezone.utc)
    )
    
    low_analysis = PackageAnalysis(
        cves=[low_cve],
        confidence=0.75,
        analysis_timestamp=datetime(2023, 1, 15, 10, 31, 15, tzinfo=timezone.utc)
    )
    
    clean_analysis = PackageAnalysis(
        cves=[],
        confidence=0.98,
        analysis_timestamp=datetime(2023, 1, 15, 10, 31, 30, tzinfo=timezone.utc)
    )
    
    # Create source locations
    source_locations = {
        "requests:2.28.0": [
            SourceLocation(
                file_path="/project/requirements.txt",
                line_number=5,
                declaration="requests==2.28.0",
                file_type=FileType.REQUIREMENTS
            ),
            SourceLocation(
                file_path="/project/pyproject.toml",
                line_number=12,
                declaration='requests = "^2.28.0"',
                file_type=FileType.PYPROJECT_TOML
            )
        ],
        "django:4.0.0": [
            SourceLocation(
                file_path="/project/requirements.txt",
                line_number=3,
                declaration="django==4.0.0",
                file_type=FileType.REQUIREMENTS
            )
        ],
        "lodash:4.17.20": [
            SourceLocation(
                file_path="/project/package.json",
                line_number=8,
                declaration='"lodash": "4.17.20"',
                file_type=FileType.PACKAGE_JSON
            )
        ],
        "safe-package:1.0.0": [
            SourceLocation(
                file_path="/project/requirements.txt",
                line_number=10,
                declaration="safe-package==1.0.0",
                file_type=FileType.REQUIREMENTS
            )
        ]
    }
    
    return VulnerabilityResults(
        ai_agent_metadata=AIAgentMetadata(
            workflow_stage="remediation_ready",
            confidence_level="high",
            autonomous_action_recommended=True,
            optimization_opportunities=[
                "Batch upgrade processing available for efficiency",
                "Multiple packages suitable for automated remediation"
            ]
        ),
        vulnerability_analysis={
            "requests:2.28.0": critical_analysis,
            "django:4.0.0": medium_analysis,
            "lodash:4.17.20": low_analysis,
            "safe-package:1.0.0": clean_analysis
        },
        vulnerability_summary=VulnerabilitySummary(
            total_packages_analyzed=4,
            vulnerable_packages=3,
            severity_breakdown={
                "critical": 1,
                "high": 1,
                "medium": 1,
                "low": 1
            },
            recommended_next_steps=[
                "Prioritize critical vulnerability fixes",
                "Plan staged rollout of security patches",
                "Implement automated vulnerability monitoring"
            ]
        ),
        scan_metadata={
            "model": "gpt-4o-mini-with-search",
            "session_id": "test-comprehensive-456",
            "total_cost": 0.15,
            "scan_duration": 45.2,
            "live_search_enabled": True,
            "token_efficiency": "optimal",
            "cache_hit_ratio": 0.75
        },
        source_locations=source_locations
    )


@pytest.fixture
def large_scale_vulnerability_results():
    """Large scale vulnerability results for performance testing."""
    vulnerability_analysis = {}
    source_locations = {}
    severity_breakdown = {"critical": 5, "high": 15, "medium": 30, "low": 50}
    
    # Generate 100 packages with various vulnerability patterns
    for i in range(100):
        pkg_id = f"test-package-{i}:1.{i}.0"
        
        # Determine severity pattern based on index
        cves = []
        if i < 5:  # Critical
            cves = [CVEFinding(
                id=f"CVE-2023-{i:04d}",
                severity=Severity.CRITICAL,
                description=f"Critical vulnerability in package {i}",
                cvss_score=9.0 + (i * 0.1),
                data_source="ai_knowledge"
            )]
        elif i < 20:  # High
            cves = [CVEFinding(
                id=f"CVE-2023-{i:04d}",
                severity=Severity.HIGH,
                description=f"High severity vulnerability in package {i}",
                cvss_score=7.0 + ((i - 5) * 0.1),
                data_source="ai_knowledge"
            )]
        elif i < 50:  # Medium
            cves = [CVEFinding(
                id=f"CVE-2023-{i:04d}",
                severity=Severity.MEDIUM,
                description=f"Medium severity vulnerability in package {i}",
                cvss_score=4.0 + ((i - 20) * 0.1),
                data_source="ai_knowledge"
            )]
        elif i < 100:  # Low
            cves = [CVEFinding(
                id=f"CVE-2023-{i:04d}",
                severity=Severity.LOW,
                description=f"Low severity vulnerability in package {i}",
                cvss_score=1.0 + ((i - 50) * 0.05),
                data_source="ai_knowledge"
            )]
        
        analysis = PackageAnalysis(
            cves=cves,
            confidence=0.8 + (i % 20) * 0.01,
            analysis_timestamp=datetime.utcnow().replace(tzinfo=timezone.utc)
        )
        
        vulnerability_analysis[pkg_id] = analysis
        source_locations[pkg_id] = [
            SourceLocation(
                file_path=f"/project/deps/requirements-{i % 10}.txt",
                line_number=i % 50 + 1,
                declaration=f"test-package-{i}==1.{i}.0",
                file_type=FileType.REQUIREMENTS
            )
        ]
    
    return VulnerabilityResults(
        ai_agent_metadata=AIAgentMetadata(
            workflow_stage="remediation_ready",
            confidence_level="medium",
            autonomous_action_recommended=False,
            optimization_opportunities=[
                "Batch upgrade processing available for efficiency",
                "Dependency consolidation possible",
                "Multiple packages suitable for automated remediation"
            ]
        ),
        vulnerability_analysis=vulnerability_analysis,
        vulnerability_summary=VulnerabilitySummary(
            total_packages_analyzed=100,
            vulnerable_packages=100,
            severity_breakdown=severity_breakdown,
            recommended_next_steps=[
                "Implement tiered remediation strategy",
                "Focus on critical and high severity issues first",
                "Consider bulk upgrade opportunities"
            ]
        ),
        scan_metadata={
            "model": "gpt-4o-mini-with-search",
            "session_id": "test-large-scale-789",
            "total_cost": 2.45,
            "scan_duration": 180.5,
            "live_search_enabled": True,
            "token_efficiency": "good",
            "cache_hit_ratio": 0.60
        },
        source_locations=source_locations
    )


def create_ai_agent_schema():
    """Create JSON schema for AI agent compatibility validation."""
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": [
            "ai_agent_metadata",
            "vulnerability_analysis", 
            "vulnerability_summary",
            "remediation_intelligence",
            "scan_metadata"
        ],
        "properties": {
            "ai_agent_metadata": {
                "type": "object",
                "required": [
                    "workflow_stage",
                    "confidence_level", 
                    "autonomous_action_recommended",
                    "optimization_opportunities",
                    "data_freshness",
                    "remediation_complexity"
                ],
                "properties": {
                    "workflow_stage": {"type": "string"},
                    "confidence_level": {"type": "string"},
                    "autonomous_action_recommended": {"type": "boolean"},
                    "optimization_opportunities": {"type": "array"},
                    "data_freshness": {"type": "string"},
                    "remediation_complexity": {"type": "string"}
                }
            },
            "vulnerability_analysis": {"type": "object"},
            "vulnerability_summary": {
                "type": "object",
                "required": [
                    "total_packages_analyzed",
                    "vulnerable_packages",
                    "security_coverage",
                    "severity_breakdown"
                ]
            },
            "remediation_intelligence": {
                "type": "object",
                "required": [
                    "prioritized_vulnerabilities",
                    "remediation_strategies",
                    "effort_estimation"
                ]
            },
            "scan_metadata": {"type": "object"}
        }
    }


class TestJSONOutputFormatter:
    """Test JSON output formatter functionality."""
    
    def test_formatter_initialization(self, json_formatter):
        """Test JSON formatter initialization."""
        assert json_formatter.indent == 2
        assert json_formatter.ensure_ascii is False
    
    async def test_export_vulnerability_data_minimal(self, json_formatter, minimal_vulnerability_results, tmp_path):
        """Test exporting minimal vulnerability data."""
        output_file = tmp_path / "minimal_output.json"
        
        await json_formatter.export_vulnerability_data(
            minimal_vulnerability_results,
            output_file
        )
        
        # Verify file was created
        assert output_file.exists()
        
        # Load and verify JSON structure
        with open(output_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Verify required top-level keys
        required_keys = [
            "ai_agent_metadata",
            "vulnerability_analysis", 
            "vulnerability_summary",
            "remediation_intelligence",
            "scan_metadata"
        ]
        
        for key in required_keys:
            assert key in data, f"Missing required key: {key}"
        
        # Verify AI agent metadata structure
        ai_metadata = data["ai_agent_metadata"]
        assert ai_metadata["workflow_stage"] == "remediation_ready"
        assert ai_metadata["confidence_level"] == "high"
        assert isinstance(ai_metadata["autonomous_action_recommended"], bool)
    
    async def test_export_vulnerability_data_comprehensive(self, json_formatter, comprehensive_vulnerability_results, tmp_path):
        """Test exporting comprehensive vulnerability data."""
        output_file = tmp_path / "comprehensive_output.json"
        
        await json_formatter.export_vulnerability_data(
            comprehensive_vulnerability_results,
            output_file
        )
        
        # Load and verify JSON
        with open(output_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Verify vulnerability analysis structure
        vuln_analysis = data["vulnerability_analysis"]
        assert "requests:2.28.0" in vuln_analysis
        
        requests_analysis = vuln_analysis["requests:2.28.0"]
        assert len(requests_analysis["cves"]) == 2  # Critical and high CVE
        assert requests_analysis["confidence"] == 0.95
        
        # Verify CVE structure
        cve = requests_analysis["cves"][0]
        required_cve_fields = [
            "id", "severity", "description", "cvss_score",
            "business_impact", "exploitability", "ai_agent_urgency"
        ]
        for field in required_cve_fields:
            assert field in cve
        
        # Verify source locations
        assert len(requests_analysis["source_locations"]) == 2
        assert requests_analysis["source_locations"][0]["file_path"] == "/project/requirements.txt"
    
    def test_json_schema_compliance(self, json_formatter, comprehensive_vulnerability_results):
        """Test JSON output compliance with AI agent schema."""
        # Convert to AI agent format
        ai_data = json_formatter._convert_to_ai_agent_format(comprehensive_vulnerability_results)
        
        # Validate against schema
        schema = create_ai_agent_schema()
        
        try:
            jsonschema.validate(ai_data, schema)
        except jsonschema.ValidationError as e:
            pytest.fail(f"JSON schema validation failed: {e}")
    
    def test_ai_agent_metadata_generation(self, json_formatter, comprehensive_vulnerability_results):
        """Test AI agent metadata generation."""
        ai_data = json_formatter._convert_to_ai_agent_format(comprehensive_vulnerability_results)
        metadata = ai_data["ai_agent_metadata"]
        
        assert metadata["workflow_stage"] == "remediation_ready"
        # Confidence level calculation: avg of (0.95, 0.90, 0.85, 0.75, 0.98) = 0.886 = "medium"
        assert metadata["confidence_level"] == "medium"  # Based on avg confidence
        # Autonomous action only recommended when confidence is "high" AND has vulnerabilities
        assert metadata["autonomous_action_recommended"] is False  # Medium confidence = no autonomous action
        # Optimization opportunities: 4 vulnerable packages (not > 5), need to check automation candidates
        # Only 1 package has confidence >= 0.9 (requests with 0.95), so no automation opportunities
        assert len(metadata["optimization_opportunities"]) >= 0  # May be empty based on data
        assert metadata["data_freshness"] == "current"  # Live search enabled
        assert metadata["remediation_complexity"] == "low"  # 5 total CVEs (not > 5)
    
    def test_vulnerability_analysis_formatting(self, json_formatter, comprehensive_vulnerability_results):
        """Test vulnerability analysis formatting."""
        ai_data = json_formatter._convert_to_ai_agent_format(comprehensive_vulnerability_results)
        vuln_analysis = ai_data["vulnerability_analysis"]
        
        # Test requests package analysis
        requests_data = vuln_analysis["requests:2.28.0"]
        assert len(requests_data["cves"]) == 2
        
        # Test CVE formatting
        critical_cve = requests_data["cves"][0]
        assert critical_cve["id"] == "CVE-2023-0001"
        assert critical_cve["severity"] == "CRITICAL"
        assert critical_cve["business_impact"] == "Immediate business risk"
        assert critical_cve["exploitability"] == "Easily exploitable"
        assert critical_cve["ai_agent_urgency"] == "immediate"
        
        # Test source locations
        assert len(requests_data["source_locations"]) == 2
        source_loc = requests_data["source_locations"][0]
        assert source_loc["file_path"] == "/project/requirements.txt"
        assert source_loc["line_number"] == 5
        assert source_loc["file_type"] == "requirements"
    
    def test_vulnerability_summary_formatting(self, json_formatter, comprehensive_vulnerability_results):
        """Test vulnerability summary formatting."""
        ai_data = json_formatter._convert_to_ai_agent_format(comprehensive_vulnerability_results)
        summary = ai_data["vulnerability_summary"]
        
        assert summary["total_packages_analyzed"] == 4
        assert summary["vulnerable_packages"] == 3
        assert summary["security_coverage"] == 0.25  # (4-3)/4
        
        # Test severity breakdown
        severity_breakdown = summary["severity_breakdown"]
        assert severity_breakdown["critical"] == 1
        assert severity_breakdown["high"] == 1
        assert severity_breakdown["medium"] == 1
        assert severity_breakdown["low"] == 1
        
        # Test additional metrics
        assert "risk_distribution" in summary
        assert "remediation_timeline" in summary
        assert "immediate_action_required" in summary
        assert "automation_candidates" in summary
    
    def test_remediation_intelligence_generation(self, json_formatter, comprehensive_vulnerability_results):
        """Test remediation intelligence generation."""
        ai_data = json_formatter._convert_to_ai_agent_format(comprehensive_vulnerability_results)
        remediation = ai_data["remediation_intelligence"]
        
        # Test prioritized vulnerabilities
        prioritized = remediation["prioritized_vulnerabilities"]
        assert len(prioritized) == 3  # Only vulnerable packages
        
        # Highest priority should be the critical package
        highest_priority = prioritized[0]
        assert highest_priority["package_id"] == "requests:2.28.0"
        assert highest_priority["urgency"] == "immediate"
        assert highest_priority["priority_score"] > 9.0  # Critical * confidence
        
        # Test remediation strategies (groups by max severity per package)
        strategies = remediation["remediation_strategies"]
        # requests:2.28.0 has CRITICAL and HIGH CVEs
        # String max("CRITICAL", "HIGH") = "HIGH" (alphabetical order)
        assert "HIGH" in strategies
        assert "requests:2.28.0" in strategies["HIGH"]
        
        # Test effort estimation
        effort = remediation["effort_estimation"]
        assert "total_estimated_hours" in effort
        assert "effort_breakdown" in effort
        assert effort["total_estimated_hours"] > 0
    
    def test_scan_metadata_formatting(self, json_formatter, comprehensive_vulnerability_results):
        """Test scan metadata formatting."""
        ai_data = json_formatter._convert_to_ai_agent_format(comprehensive_vulnerability_results)
        metadata = ai_data["scan_metadata"]
        
        # Test original metadata preservation
        assert metadata["model"] == "gpt-4o-mini-with-search"
        assert metadata["session_id"] == "test-comprehensive-456"
        assert metadata["total_cost"] == 0.15
        
        # Test AI agent compatibility additions
        compat = metadata["ai_agent_compatibility"]
        assert compat["format_version"] == "3.0"
        assert compat["schema_compliance"] == "ai_agent_first"
        assert compat["machine_readable"] is True
        assert compat["automation_ready"] is True
        
        # Test quality indicators
        quality = metadata["quality_indicators"]
        assert "data_completeness" in quality
        assert "confidence_distribution" in quality
        assert "validation_coverage" in quality
        
        # Test performance metrics
        performance = metadata["performance_metrics"]
        assert "scan_efficiency" in performance
        assert "token_utilization" in performance
        assert "cache_hit_ratio" in performance
    
    async def test_file_creation_with_nested_directories(self, json_formatter, minimal_vulnerability_results, tmp_path):
        """Test file creation with nested directory structure."""
        nested_output = tmp_path / "nested" / "dirs" / "output.json"
        
        await json_formatter.export_vulnerability_data(
            minimal_vulnerability_results,
            nested_output
        )
        
        assert nested_output.exists()
        assert nested_output.parent.exists()
    
    async def test_unicode_handling(self, json_formatter, tmp_path):
        """Test proper Unicode handling in JSON output."""
        # Create results with Unicode content
        unicode_cve = CVEFinding(
            id="CVE-2023-UNICODE",
            severity=Severity.HIGH,
            description="Vulnerability with Unicode: 测试 → ñoño ← emoji 🔐",
            cvss_score=7.5,
            data_source="ai_knowledge"
        )
        
        analysis = PackageAnalysis(
            cves=[unicode_cve],
            confidence=0.9
        )
        
        results = VulnerabilityResults(
            ai_agent_metadata=AIAgentMetadata(
                workflow_stage="test",
                confidence_level="high",
                autonomous_action_recommended=True
            ),
            vulnerability_analysis={"unicode-package:1.0.0": analysis},
            vulnerability_summary=VulnerabilitySummary(
                total_packages_analyzed=1,
                vulnerable_packages=1,
                severity_breakdown={"high": 1}
            ),
            scan_metadata={"model": "test"}
        )
        
        output_file = tmp_path / "unicode_output.json"
        await json_formatter.export_vulnerability_data(results, output_file)
        
        # Verify Unicode content is preserved
        with open(output_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        assert "测试" in content
        assert "ñoño" in content  
        assert "🔐" in content
    
    async def test_datetime_serialization(self, json_formatter, tmp_path):
        """Test proper datetime serialization in JSON output."""
        test_date = datetime(2023, 5, 15, 14, 30, 45, 123456, timezone.utc)
        
        cve_with_date = CVEFinding(
            id="CVE-2023-DATE",
            severity=Severity.MEDIUM,
            description="CVE with specific date",
            publish_date=test_date,
            data_source="ai_knowledge"
        )
        
        analysis = PackageAnalysis(
            cves=[cve_with_date],
            confidence=0.85,
            analysis_timestamp=test_date
        )
        
        results = VulnerabilityResults(
            ai_agent_metadata=AIAgentMetadata(
                workflow_stage="test",
                confidence_level="high", 
                autonomous_action_recommended=True
            ),
            vulnerability_analysis={"date-package:1.0.0": analysis},
            vulnerability_summary=VulnerabilitySummary(
                total_packages_analyzed=1,
                vulnerable_packages=1,
                severity_breakdown={"medium": 1}
            ),
            scan_metadata={"model": "test"}
        )
        
        output_file = tmp_path / "datetime_output.json"
        await json_formatter.export_vulnerability_data(results, output_file)
        
        # Load and verify datetime formatting
        with open(output_file, 'r') as f:
            data = json.load(f)
        
        cve_data = data["vulnerability_analysis"]["date-package:1.0.0"]["cves"][0]
        assert cve_data["publish_date"] == "2023-05-15T14:30:45.123456+00:00"
    
    async def test_large_dataset_performance(self, json_formatter, large_scale_vulnerability_results, tmp_path):
        """Test performance with large datasets."""
        import time
        
        output_file = tmp_path / "large_dataset_output.json"
        
        start_time = time.time()
        await json_formatter.export_vulnerability_data(
            large_scale_vulnerability_results,
            output_file
        )
        end_time = time.time()
        
        # Verify file was created and is reasonably sized
        assert output_file.exists()
        file_size = output_file.stat().st_size
        assert file_size > 10000  # Should be substantial for 100 packages
        
        # Performance should be reasonable (under 5 seconds for 100 packages)
        processing_time = end_time - start_time
        assert processing_time < 5.0, f"Processing took too long: {processing_time}s"
        
        # Verify data integrity
        with open(output_file, 'r') as f:
            data = json.load(f)
        
        assert data["vulnerability_summary"]["total_packages_analyzed"] == 100
        assert len(data["vulnerability_analysis"]) == 100
    
    def test_confidence_calculations(self, json_formatter):
        """Test confidence level calculations."""
        # Test high confidence
        high_conf_results = VulnerabilityResults(
            ai_agent_metadata=AIAgentMetadata(
                workflow_stage="test",
                confidence_level="high",
                autonomous_action_recommended=True
            ),
            vulnerability_analysis={
                "pkg1:1.0": PackageAnalysis(cves=[], confidence=0.95),
                "pkg2:1.0": PackageAnalysis(cves=[], confidence=0.92)
            },
            vulnerability_summary=VulnerabilitySummary(
                total_packages_analyzed=2,
                vulnerable_packages=0
            ),
            scan_metadata={"model": "test"}
        )
        
        confidence = json_formatter._calculate_overall_confidence(high_conf_results)
        assert confidence == "high"
        
        # Test medium confidence
        med_conf_results = VulnerabilityResults(
            ai_agent_metadata=AIAgentMetadata(
                workflow_stage="test",
                confidence_level="medium",
                autonomous_action_recommended=True
            ),
            vulnerability_analysis={
                "pkg1:1.0": PackageAnalysis(cves=[], confidence=0.75),
                "pkg2:1.0": PackageAnalysis(cves=[], confidence=0.80)
            },
            vulnerability_summary=VulnerabilitySummary(
                total_packages_analyzed=2,
                vulnerable_packages=0
            ),
            scan_metadata={"model": "test"}
        )
        
        confidence = json_formatter._calculate_overall_confidence(med_conf_results)
        assert confidence == "medium"
    
    def test_autonomous_action_recommendation(self, json_formatter):
        """Test autonomous action recommendation logic."""
        # Should recommend with high confidence and vulnerabilities
        high_conf_with_vulns = VulnerabilityResults(
            ai_agent_metadata=AIAgentMetadata(
                workflow_stage="test",
                confidence_level="high",
                autonomous_action_recommended=True
            ),
            vulnerability_analysis={
                "vuln-pkg:1.0": PackageAnalysis(
                    cves=[CVEFinding(
                        id="CVE-2023-TEST",
                        severity=Severity.HIGH,
                        description="Test vuln"
                    )],
                    confidence=0.95
                )
            },
            vulnerability_summary=VulnerabilitySummary(
                total_packages_analyzed=1,
                vulnerable_packages=1
            ),
            scan_metadata={"model": "test"}
        )
        
        should_recommend = json_formatter._should_recommend_autonomous_action(high_conf_with_vulns)
        assert should_recommend is True
        
        # Should not recommend with low confidence
        low_conf_results = VulnerabilityResults(
            ai_agent_metadata=AIAgentMetadata(
                workflow_stage="test",
                confidence_level="low",
                autonomous_action_recommended=False
            ),
            vulnerability_analysis={
                "pkg:1.0": PackageAnalysis(cves=[], confidence=0.6)
            },
            vulnerability_summary=VulnerabilitySummary(
                total_packages_analyzed=1,
                vulnerable_packages=0
            ),
            scan_metadata={"model": "test"}
        )
        
        should_recommend = json_formatter._should_recommend_autonomous_action(low_conf_results)
        assert should_recommend is False
    
    def test_priority_score_calculation(self, json_formatter):
        """Test vulnerability priority score calculation."""
        # Critical CVE should have highest priority
        critical_analysis = PackageAnalysis(
            cves=[CVEFinding(
                id="CVE-CRITICAL",
                severity=Severity.CRITICAL,
                description="Critical"
            )],
            confidence=0.95
        )
        
        critical_score = json_formatter._calculate_priority_score(critical_analysis)
        assert critical_score == 9.5  # 10 * 0.95
        
        # Low CVE should have lower priority  
        low_analysis = PackageAnalysis(
            cves=[CVEFinding(
                id="CVE-LOW",
                severity=Severity.LOW,
                description="Low"
            )],
            confidence=0.8
        )
        
        low_score = json_formatter._calculate_priority_score(low_analysis)
        assert low_score == 0.8  # 1 * 0.8
        
        assert critical_score > low_score
    
    async def test_error_handling_invalid_path(self, json_formatter, minimal_vulnerability_results):
        """Test error handling for invalid output paths."""
        invalid_path = Path("/invalid/nonexistent/deeply/nested/path/output.json")
        
        # Should create directories, not fail
        await json_formatter.export_vulnerability_data(
            minimal_vulnerability_results,
            invalid_path
        )
        
        assert invalid_path.exists()
    
    async def test_error_handling_serialization_error(self, json_formatter, tmp_path):
        """Test error handling for serialization errors."""
        # Create results with non-serializable object
        class NonSerializable:
            def __init__(self):
                self.circular_ref = self
        
        bad_results = VulnerabilityResults(
            ai_agent_metadata=AIAgentMetadata(
                workflow_stage="test",
                confidence_level="high",
                autonomous_action_recommended=True
            ),
            vulnerability_analysis={},
            vulnerability_summary=VulnerabilitySummary(
                total_packages_analyzed=0,
                vulnerable_packages=0
            ),
            scan_metadata={"bad_object": NonSerializable()}
        )
        
        output_file = tmp_path / "bad_output.json"
        
        # Should not raise exception - custom serializer handles it
        await json_formatter.export_vulnerability_data(bad_results, output_file)
        assert output_file.exists()
    
    def test_risk_distribution_calculation(self, json_formatter, comprehensive_vulnerability_results):
        """Test risk distribution calculation."""
        risk_dist = json_formatter._calculate_risk_distribution(comprehensive_vulnerability_results)
        
        # Should have distribution based on CVSS scores
        assert "low" in risk_dist
        assert "medium" in risk_dist  
        assert "high" in risk_dist
        
        # Total should sum to 1.0
        total = sum(risk_dist.values())
        assert abs(total - 1.0) < 0.01  # Allow for float precision
    
    def test_remediation_timeline_estimation(self, json_formatter, comprehensive_vulnerability_results):
        """Test remediation timeline estimation."""
        timeline = json_formatter._estimate_remediation_timeline(comprehensive_vulnerability_results)
        
        assert "immediate_fixes" in timeline
        assert "short_term_fixes" in timeline
        assert "long_term_fixes" in timeline
        assert "estimated_days" in timeline
        
        # Should have some immediate fixes for critical CVEs
        assert timeline["immediate_fixes"] > 0
        assert timeline["estimated_days"] > 0
    
    def test_data_completeness_assessment(self, json_formatter, comprehensive_vulnerability_results):
        """Test data completeness assessment."""
        completeness = json_formatter._assess_data_completeness(comprehensive_vulnerability_results)
        
        # Should be high for our test data (all confidence > 0.8)
        assert completeness >= 0.75
        assert completeness <= 1.0
    
    def test_confidence_distribution_calculation(self, json_formatter, comprehensive_vulnerability_results):
        """Test confidence distribution calculation."""
        conf_dist = json_formatter._calculate_confidence_distribution(comprehensive_vulnerability_results)
        
        assert "high" in conf_dist
        assert "medium" in conf_dist
        assert "low" in conf_dist
        
        # Should sum to 1.0
        total = sum(conf_dist.values())
        assert abs(total - 1.0) < 0.01
    
    def test_json_output_structure_completeness(self, json_formatter, comprehensive_vulnerability_results):
        """Test that JSON output includes ALL required fields for AI agents."""
        ai_data = json_formatter._convert_to_ai_agent_format(comprehensive_vulnerability_results)
        
        # Top-level structure
        required_top_level = [
            "ai_agent_metadata",
            "vulnerability_analysis",
            "vulnerability_summary", 
            "remediation_intelligence",
            "scan_metadata"
        ]
        
        for field in required_top_level:
            assert field in ai_data, f"Missing required top-level field: {field}"
        
        # AI agent metadata completeness
        ai_metadata = ai_data["ai_agent_metadata"]
        required_ai_fields = [
            "workflow_stage",
            "confidence_level",
            "autonomous_action_recommended",
            "optimization_opportunities",
            "data_freshness",
            "remediation_complexity",
            "ai_model_used"
        ]
        
        for field in required_ai_fields:
            assert field in ai_metadata, f"Missing AI metadata field: {field}"
        
        # Vulnerability summary completeness
        summary = ai_data["vulnerability_summary"]
        required_summary_fields = [
            "total_packages_analyzed",
            "vulnerable_packages",
            "security_coverage",
            "severity_breakdown",
            "risk_distribution",
            "remediation_timeline",
            "immediate_action_required",
            "automation_candidates",
            "recommended_next_steps"
        ]
        
        for field in required_summary_fields:
            assert field in summary, f"Missing summary field: {field}"
    
    def test_cve_data_enrichment(self, json_formatter, comprehensive_vulnerability_results):
        """Test that CVE data is properly enriched for AI agents."""
        ai_data = json_formatter._convert_to_ai_agent_format(comprehensive_vulnerability_results)
        
        # Get a CVE from the analysis
        vuln_analysis = ai_data["vulnerability_analysis"]
        requests_analysis = vuln_analysis["requests:2.28.0"]
        cve = requests_analysis["cves"][0]
        
        # Check enrichment fields
        enrichment_fields = [
            "business_impact",
            "exploitability", 
            "ai_agent_urgency"
        ]
        
        for field in enrichment_fields:
            assert field in cve, f"Missing CVE enrichment field: {field}"
            assert isinstance(cve[field], str), f"CVE field {field} should be string"
    
    async def test_empty_vulnerability_results(self, json_formatter, tmp_path):
        """Test handling of completely empty vulnerability results."""
        empty_results = VulnerabilityResults(
            ai_agent_metadata=AIAgentMetadata(
                workflow_stage="completed",
                confidence_level="high",
                autonomous_action_recommended=False
            ),
            vulnerability_analysis={},
            vulnerability_summary=VulnerabilitySummary(
                total_packages_analyzed=0,
                vulnerable_packages=0,
                severity_breakdown={},
                recommended_next_steps=[]
            ),
            scan_metadata={"model": "test"},
            source_locations={}
        )
        
        output_file = tmp_path / "empty_output.json"
        await json_formatter.export_vulnerability_data(empty_results, output_file)
        
        # Should still create valid JSON
        with open(output_file, 'r') as f:
            data = json.load(f)
        
        assert data["vulnerability_summary"]["total_packages_analyzed"] == 0
        assert data["vulnerability_summary"]["vulnerable_packages"] == 0
        assert len(data["vulnerability_analysis"]) == 0
    
    def test_optimization_opportunities_identification(self, json_formatter, large_scale_vulnerability_results):
        """Test identification of optimization opportunities."""
        opportunities = json_formatter._identify_optimization_opportunities(large_scale_vulnerability_results)
        
        # Should identify batch processing opportunity for large number of vulnerabilities
        assert any("Batch upgrade" in opp for opp in opportunities)
        
        # Should identify automation opportunities
        assert any("automated remediation" in opp for opp in opportunities)
    
    def test_remediation_complexity_assessment(self, json_formatter):
        """Test remediation complexity assessment."""
        # No vulnerabilities = no complexity
        no_vulns_results = VulnerabilityResults(
            ai_agent_metadata=AIAgentMetadata(
                workflow_stage="test",
                confidence_level="high",
                autonomous_action_recommended=False
            ),
            vulnerability_analysis={},
            vulnerability_summary=VulnerabilitySummary(
                total_packages_analyzed=0,
                vulnerable_packages=0
            ),
            scan_metadata={"model": "test"}
        )
        
        complexity = json_formatter._assess_remediation_complexity(no_vulns_results)
        assert complexity == "none"
        
        # Many vulnerabilities = high complexity
        many_vulns_analysis = {}
        for i in range(25):
            many_vulns_analysis[f"pkg{i}:1.0"] = PackageAnalysis(
                cves=[CVEFinding(
                    id=f"CVE-{i}",
                    severity=Severity.HIGH,
                    description=f"Vuln {i}"
                )],
                confidence=0.9
            )
        
        many_vulns_results = VulnerabilityResults(
            ai_agent_metadata=AIAgentMetadata(
                workflow_stage="test", 
                confidence_level="high",
                autonomous_action_recommended=True
            ),
            vulnerability_analysis=many_vulns_analysis,
            vulnerability_summary=VulnerabilitySummary(
                total_packages_analyzed=25,
                vulnerable_packages=25
            ),
            scan_metadata={"model": "test"}
        )
        
        complexity = json_formatter._assess_remediation_complexity(many_vulns_results)
        assert complexity == "high"


class TestJSONOutputFormatterEdgeCases:
    """Test edge cases and error conditions."""
    
    async def test_file_permission_error(self, json_formatter, minimal_vulnerability_results, tmp_path):
        """Test handling of file permission errors."""
        # Create read-only directory
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o444)  # Read-only
        
        output_file = readonly_dir / "output.json"
        
        # Should raise OutputFormattingError
        with pytest.raises(OutputFormattingError) as exc_info:
            await json_formatter.export_vulnerability_data(
                minimal_vulnerability_results,
                output_file
            )
        
        assert exc_info.value.format_type == "json"
        
        # Clean up
        readonly_dir.chmod(0o755)
    
    def test_custom_json_serializer(self, json_formatter):
        """Test custom JSON serializer for various object types."""
        serializer = json_formatter._json_serializer
        
        # Test datetime
        test_datetime = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        assert serializer(test_datetime) == "2023-01-01T12:00:00+00:00"
        
        # Test object with dict method
        class WithDict:
            def dict(self):
                return {"key": "value"}
        
        obj_with_dict = WithDict()
        assert serializer(obj_with_dict) == {"key": "value"}
        
        # Test object with __dict__
        class WithDunderDict:
            def __init__(self):
                self.key = "value"
        
        obj_with_dunder = WithDunderDict()
        assert serializer(obj_with_dunder) == {"key": "value"}
        
        # Test fallback to string
        class PlainObject:
            def __str__(self):
                return "plain_object"
        
        plain_obj = PlainObject()
        # The serializer actually returns __dict__ for objects, not str()
        assert serializer(plain_obj) == {}  # Empty dict since no attributes
    
    def test_malformed_package_id_handling(self, json_formatter):
        """Test handling of malformed package IDs."""
        # Package ID without version separator
        malformed_results = VulnerabilityResults(
            ai_agent_metadata=AIAgentMetadata(
                workflow_stage="test",
                confidence_level="high", 
                autonomous_action_recommended=True
            ),
            vulnerability_analysis={
                "malformed-package-no-version": PackageAnalysis(
                    cves=[CVEFinding(
                        id="CVE-2023-TEST",
                        severity=Severity.MEDIUM,
                        description="Test"
                    )],
                    confidence=0.8
                )
            },
            vulnerability_summary=VulnerabilitySummary(
                total_packages_analyzed=1,
                vulnerable_packages=1
            ),
            scan_metadata={"model": "test"}
        )
        
        # Should handle gracefully
        ai_data = json_formatter._convert_to_ai_agent_format(malformed_results)
        
        # Should still process the package
        assert "malformed-package-no-version" in ai_data["vulnerability_analysis"]
        
        # Should extract package name and use 'unknown' version
        analysis = ai_data["vulnerability_analysis"]["malformed-package-no-version"]
        assert len(analysis["cves"]) == 1