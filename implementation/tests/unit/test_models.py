"""
Unit tests for core data models.
Tests validation, serialization, and business logic.
"""

import pytest
from datetime import datetime
from pydantic import ValidationError

from sca_ai_scanner.core.models import (
    Package, CVEFinding, PackageAnalysis, VulnerabilityResults,
    Severity, SourceLocation, FileType, ScanConfig, TelemetryEvent
)


class TestPackage:
    """Test Package model."""
    
    def test_valid_package_creation(self):
        """Test creating valid package."""
        package = Package(
            name="requests",
            version="2.25.1",
            ecosystem="pypi"
        )
        
        assert package.name == "requests"
        assert package.version == "2.25.1"
        assert package.ecosystem == "pypi"
        assert package.source_locations == []
    
    def test_package_name_validation(self):
        """Test package name validation."""
        # Empty name should fail
        with pytest.raises(ValidationError):
            Package(name="", version="1.0.0", ecosystem="pypi")
        
        # Whitespace-only name should fail
        with pytest.raises(ValidationError):
            Package(name="   ", version="1.0.0", ecosystem="pypi")
    
    def test_package_version_validation(self):
        """Test package version validation."""
        # Empty version should fail
        with pytest.raises(ValidationError):
            Package(name="test", version="", ecosystem="pypi")
        
        # Whitespace-only version should fail
        with pytest.raises(ValidationError):
            Package(name="test", version="   ", ecosystem="pypi")
    
    def test_package_with_source_locations(self):
        """Test package with source locations."""
        source_location = SourceLocation(
            file_path="requirements.txt",
            line_number=15,
            declaration="requests==2.25.1",
            file_type=FileType.REQUIREMENTS
        )
        
        package = Package(
            name="requests",
            version="2.25.1",
            source_locations=[source_location],
            ecosystem="pypi"
        )
        
        assert len(package.source_locations) == 1
        assert package.source_locations[0].file_path == "requirements.txt"


class TestCVEFinding:
    """Test CVEFinding model."""
    
    def test_valid_cve_creation(self):
        """Test creating valid CVE finding."""
        cve = CVEFinding(
            id="CVE-2023-32681",
            severity=Severity.HIGH,
            description="Certificate verification bypass",
            cvss_score=8.5
        )
        
        assert cve.id == "CVE-2023-32681"
        assert cve.severity == Severity.HIGH
        assert cve.cvss_score == 8.5
        assert cve.data_source == "ai_knowledge"  # default
    
    def test_cvss_score_validation(self):
        """Test CVSS score validation."""
        # Valid scores
        CVEFinding(
            id="CVE-2023-1234",
            severity=Severity.LOW,
            description="Test",
            cvss_score=0.0
        )
        
        CVEFinding(
            id="CVE-2023-1234",
            severity=Severity.CRITICAL,
            description="Test",
            cvss_score=10.0
        )
        
        # Invalid scores
        with pytest.raises(ValidationError):
            CVEFinding(
                id="CVE-2023-1234",
                severity=Severity.LOW,
                description="Test",
                cvss_score=-1.0
            )
        
        with pytest.raises(ValidationError):
            CVEFinding(
                id="CVE-2023-1234",
                severity=Severity.CRITICAL,
                description="Test",
                cvss_score=11.0
            )
    
    def test_cve_with_publish_date(self):
        """Test CVE with publish date."""
        publish_date = datetime(2023, 5, 26, 15, 15, 9)
        
        cve = CVEFinding(
            id="CVE-2023-32681",
            severity=Severity.HIGH,
            description="Test",
            publish_date=publish_date
        )
        
        assert cve.publish_date == publish_date


class TestPackageAnalysis:
    """Test PackageAnalysis model."""
    
    def test_valid_analysis_creation(self):
        """Test creating valid package analysis."""
        cve = CVEFinding(
            id="CVE-2023-32681",
            severity=Severity.HIGH,
            description="Test vulnerability"
        )
        
        analysis = PackageAnalysis(
            cves=[cve],
            confidence=0.95
        )
        
        assert len(analysis.cves) == 1
        assert analysis.confidence == 0.95
        assert analysis.cves[0].id == "CVE-2023-32681"
        assert analysis.cves[0].severity == Severity.HIGH
    
    def test_confidence_validation(self):
        """Test confidence score validation."""
        # Valid confidence scores
        PackageAnalysis(
            cves=[],
            confidence=0.0
        )
        
        PackageAnalysis(
            cves=[],
            confidence=1.0
        )
        
        # Invalid confidence scores
        with pytest.raises(ValidationError):
            PackageAnalysis(
                cves=[],
                confidence=-0.1
            )
        
        with pytest.raises(ValidationError):
            PackageAnalysis(
                cves=[],
                confidence=1.1
            )


class TestVulnerabilityResults:
    """Test VulnerabilityResults model."""
    
    def test_get_vulnerable_packages(self, sample_packages):
        """Test getting vulnerable packages."""
        # Create analysis with CVEs
        cve = CVEFinding(
            id="CVE-2023-32681",
            severity=Severity.HIGH,
            description="Test"
        )
        
        analysis_with_cves = PackageAnalysis(
            cves=[cve],
            confidence=0.9
        )
        
        # Create analysis without CVEs
        analysis_without_cves = PackageAnalysis(
            cves=[],
            confidence=0.95
        )
        
        results = VulnerabilityResults(
            ai_agent_metadata={
                "workflow_stage": "test",
                "confidence_level": "high",
                "autonomous_action_recommended": True
            },
            vulnerability_analysis={
                "vulnerable:1.0.0": analysis_with_cves,
                "safe:2.0.0": analysis_without_cves
            },
            vulnerability_summary={
                "total_packages_analyzed": 2,
                "vulnerable_packages": 1,
                "severity_breakdown": {"HIGH": 1}
            }
        )
        
        vulnerable = results.get_vulnerable_packages()
        assert vulnerable == ["vulnerable:1.0.0"]
    
    def test_get_packages_by_severity(self):
        """Test getting packages by severity."""
        high_cve = CVEFinding(
            id="CVE-2023-1",
            severity=Severity.HIGH,
            description="High severity"
        )
        
        medium_cve = CVEFinding(
            id="CVE-2023-2",
            severity=Severity.MEDIUM,
            description="Medium severity"
        )
        
        high_analysis = PackageAnalysis(
            cves=[high_cve],
            confidence=0.9
        )
        
        medium_analysis = PackageAnalysis(
            cves=[medium_cve],
            confidence=0.85
        )
        
        results = VulnerabilityResults(
            ai_agent_metadata={
                "workflow_stage": "test",
                "confidence_level": "high",
                "autonomous_action_recommended": True
            },
            vulnerability_analysis={
                "high-pkg:1.0.0": high_analysis,
                "medium-pkg:1.0.0": medium_analysis
            },
            vulnerability_summary={
                "total_packages_analyzed": 2,
                "vulnerable_packages": 2,
                "severity_breakdown": {"HIGH": 1, "MEDIUM": 1}
            }
        )
        
        high_packages = results.get_packages_by_severity(Severity.HIGH)
        assert high_packages == ["high-pkg:1.0.0"]
        
        medium_packages = results.get_packages_by_severity(Severity.MEDIUM)
        assert medium_packages == ["medium-pkg:1.0.0"]
    
    def test_get_high_confidence_findings(self):
        """Test getting high confidence findings."""
        high_conf_analysis = PackageAnalysis(
            cves=[],
            confidence=0.95
        )
        
        low_conf_analysis = PackageAnalysis(
            cves=[],
            confidence=0.7
        )
        
        results = VulnerabilityResults(
            ai_agent_metadata={
                "workflow_stage": "test",
                "confidence_level": "high",
                "autonomous_action_recommended": True
            },
            vulnerability_analysis={
                "high-conf:1.0.0": high_conf_analysis,
                "low-conf:1.0.0": low_conf_analysis
            },
            vulnerability_summary={
                "total_packages_analyzed": 2,
                "vulnerable_packages": 0,
                "severity_breakdown": {}
            }
        )
        
        high_conf_findings = results.get_high_confidence_findings(threshold=0.9)
        assert "high-conf:1.0.0" in high_conf_findings
        assert "low-conf:1.0.0" not in high_conf_findings


class TestScanConfig:
    """Test ScanConfig model."""
    
    def test_valid_config_creation(self):
        """Test creating valid scan configuration."""
        config = ScanConfig(
            model="gpt-4o-mini-with-search",
            enable_live_search=True,
            batch_size=75,
            confidence_threshold=0.8,
            max_retries=3,
            timeout_seconds=30,
            daily_budget_limit=50.0,
            validate_critical=True
        )
        
        assert config.model == "gpt-4o-mini-with-search"
        assert config.enable_live_search is True
        assert config.batch_size == 75
        assert config.confidence_threshold == 0.8
    
    def test_batch_size_validation(self):
        """Test batch size validation."""
        # Valid batch sizes
        ScanConfig(batch_size=1)
        ScanConfig(batch_size=200)
        
        # Invalid batch sizes
        with pytest.raises(ValidationError):
            ScanConfig(batch_size=0)
        
        with pytest.raises(ValidationError):
            ScanConfig(batch_size=201)
    
    def test_confidence_threshold_validation(self):
        """Test confidence threshold validation."""
        # Valid thresholds
        ScanConfig(confidence_threshold=0.0)
        ScanConfig(confidence_threshold=1.0)
        
        # Invalid thresholds
        with pytest.raises(ValidationError):
            ScanConfig(confidence_threshold=-0.1)
        
        with pytest.raises(ValidationError):
            ScanConfig(confidence_threshold=1.1)


class TestTelemetryEvent:
    """Test TelemetryEvent model."""
    
    def test_telemetry_event_creation(self):
        """Test creating telemetry event."""
        event = TelemetryEvent(
            event_type="test_event",
            session_id="test-session-123",
            data={"key": "value"},
            context={"context_key": "context_value"}
        )
        
        assert event.event_type == "test_event"
        assert event.session_id == "test-session-123"
        assert event.data == {"key": "value"}
        assert event.context == {"context_key": "context_value"}
        assert isinstance(event.timestamp, datetime)
    
    def test_telemetry_event_defaults(self):
        """Test telemetry event default values."""
        event = TelemetryEvent(
            event_type="test_event",
            session_id="test-session-123"
        )
        
        assert event.data == {}
        assert event.context == {}
        assert event.ai_agent_metadata == {}


class TestSeverityEnum:
    """Test Severity enumeration."""
    
    def test_severity_values(self):
        """Test severity enum values."""
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"
    
    def test_severity_comparison(self):
        """Test severity comparison (if needed for sorting)."""
        # These are just string comparisons, but useful for validation
        assert Severity.CRITICAL != Severity.HIGH
        assert Severity.HIGH != Severity.MEDIUM


class TestFileTypeEnum:
    """Test FileType enumeration."""
    
    def test_file_type_values(self):
        """Test file type enum values."""
        assert FileType.REQUIREMENTS.value == "requirements"
        assert FileType.PYPROJECT_TOML.value == "pyproject_toml"
        assert FileType.PACKAGE_JSON.value == "package_json"
    
    def test_all_supported_file_types(self):
        """Test that all expected file types are defined."""
        expected_types = {
            "requirements", "pyproject_toml", "package_json", 
            "yarn_lock", "composer_json", 
            "gemfile", "go_mod"
        }
        
        actual_types = {ft.value for ft in FileType}
        assert expected_types.issubset(actual_types)