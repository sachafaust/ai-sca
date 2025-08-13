"""
Pytest configuration and fixtures for SCA scanner tests.
Provides common test utilities and mock data for fast testing.
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, AsyncMock
from typing import Dict, Any, List

from sca_ai_scanner.core.models import (
    Package, CVEFinding, PackageAnalysis, VulnerabilityResults,
    Severity, SourceLocation, FileType, ScanConfig
)


@pytest.fixture
def temp_project_dir():
    """Create a temporary project directory for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def mock_ai_client():
    """Mock AI client for fast unit tests."""
    client = AsyncMock()
    
    # Mock successful response
    client.bulk_analyze.return_value = VulnerabilityResults(
        ai_agent_metadata={
            "workflow_stage": "remediation_ready",
            "confidence_level": "high",
            "autonomous_action_recommended": True
        },
        vulnerability_analysis={
            "requests:2.25.1": PackageAnalysis(
                cves=[CVEFinding(
                    id="CVE-2023-32681",
                    severity=Severity.HIGH,
                    description="Certificate verification bypass",
                    cvss_score=8.5
                )],
                confidence=0.95
            )
        },
        vulnerability_summary={
            "total_packages_analyzed": 1,
            "vulnerable_packages": 1,
            "severity_breakdown": {"HIGH": 1},
            "recommended_next_steps": ["Upgrade packages"]
        },
        scan_metadata={
            "model": "gpt-4o-mini-with-search",
            "total_cost": 0.01
        }
    )
    
    return client


@pytest.fixture
def sample_packages():
    """Sample package data for testing."""
    return [
        Package(
            name="requests",
            version="2.25.1",
            source_locations=[
                SourceLocation(
                    file_path="requirements.txt",
                    line_number=15,
                    declaration="requests==2.25.1",
                    file_type=FileType.REQUIREMENTS
                )
            ],
            ecosystem="pypi"
        ),
        Package(
            name="django",
            version="3.2.1",
            source_locations=[
                SourceLocation(
                    file_path="pyproject.toml",
                    line_number=23,
                    declaration='django = "^3.2.1"',
                    file_type=FileType.PYPROJECT_TOML
                )
            ],
            ecosystem="pypi"
        )
    ]


@pytest.fixture
def sample_scan_config():
    """Sample scan configuration for testing."""
    return ScanConfig(
        model="gpt-4o-mini-with-search",
        enable_live_search=True,
        batch_size=10,  # Small for testing
        confidence_threshold=0.8,
        max_retries=1,
        timeout_seconds=5,
        daily_budget_limit=10.0,
        validate_critical=True
    )


@pytest.fixture
def mock_vulnerability_results():
    """Mock vulnerability results for testing."""
    return {
        "requests:2.25.1": {
            "cves": [{
                "id": "CVE-2023-32681",
                "severity": "HIGH",
                "description": "Certificate verification bypass",
                "cvss_score": 8.5,
                "data_source": "ai_knowledge"
            }],
            "confidence": 0.95,
            "analysis_timestamp": "2025-07-20T17:48:30.474Z"
        }
    }


@pytest.fixture
def create_test_files():
    """Factory for creating test dependency files."""
    
    def _create_files(project_dir: Path, file_configs: Dict[str, str]):
        """Create test files in project directory."""
        files_created = []
        
        for filename, content in file_configs.items():
            file_path = project_dir / filename
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            files_created.append(file_path)
        
        return files_created
    
    return _create_files


@pytest.fixture
def python_test_files():
    """Sample Python dependency files for testing."""
    return {
        "requirements.txt": """
# Production dependencies
requests==2.25.1
django>=3.2.0,<4.0.0
numpy==1.21.0

# Development dependencies (should be excluded by default)
pytest==6.2.4
black==21.5b2
""",
        "pyproject.toml": """
[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "test-project"
version = "1.0.0"
dependencies = [
    "fastapi>=0.68.0",
    "uvicorn[standard]>=0.15.0",
    "pydantic>=1.8.0"
]

[project.optional-dependencies]
dev = [
    "pytest>=6.0.0",
    "mypy>=0.910"
]
""",
        "setup.py": """
from setuptools import setup

setup(
    name="test-project",
    version="1.0.0",
    install_requires=[
        "click>=8.0.0",
        "rich>=10.0.0"
    ],
    setup_requires=[
        "wheel"
    ]
)
"""
    }


@pytest.fixture
def javascript_test_files():
    """Sample JavaScript dependency files for testing."""
    return {
        "package.json": """{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.17.1",
    "lodash": "4.17.20",
    "axios": ">=0.21.0"
  },
  "devDependencies": {
    "jest": "^27.0.0",
    "webpack": "^5.38.0",
    "@types/node": "^16.0.0"
  }
}""",
        "yarn.lock": """
# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.

express@^4.17.1:
  version "4.17.1"
  resolved "https://registry.yarnpkg.com/express/-/express-4.17.1.tgz"
  integrity sha512-mHJ9O79RqluphRrcw2X/GTh3k9tVv8YcoyY4Kkh4WDMUYKRZUq0h1o0w2rrrxBqM7VoeUVqgb27xlEMXTnYt4g==

lodash@4.17.20:
  version "4.17.20"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz"
  integrity sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA==
"""
    }




# Performance testing utilities

@pytest.fixture
def performance_timer():
    """Timer utility for performance tests."""
    import time
    
    class Timer:
        def __init__(self):
            self.start_time = None
            self.end_time = None
        
        def start(self):
            self.start_time = time.time()
        
        def stop(self):
            self.end_time = time.time()
        
        @property
        def elapsed(self):
            if self.start_time and self.end_time:
                return self.end_time - self.start_time
            return None
    
    return Timer()


# Async test utilities

@pytest.fixture
def event_loop():
    """Create event loop for async tests."""
    import asyncio
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# Mock external services

@pytest.fixture
def mock_nvd_api():
    """Mock NVD API responses for validation testing."""
    return {
        "CVE-2023-32681": {
            "totalResults": 1,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2023-32681",
                    "published": "2023-05-26T15:15:09.903",
                    "lastModified": "2023-05-31T17:15:09.903",
                    "descriptions": [{
                        "lang": "en",
                        "value": "Requests before 2.31.0 allows attackers to bypass SSL verification."
                    }],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH"
                            }
                        }]
                    }
                }
            }]
        }
    }


@pytest.fixture
def mock_osv_api():
    """Mock OSV.dev API responses for validation testing."""
    return {
        "CVE-2023-32681": {
            "id": "GHSA-j8r2-6x86-q33q",
            "summary": "Unintended leak of Proxy-Authorization header in requests",
            "aliases": ["CVE-2023-32681"],
            "affected": [{
                "package": {
                    "name": "requests",
                    "ecosystem": "PyPI"
                },
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "2.31.0"}
                    ]
                }]
            }]
        }
    }


# Test data generators

def generate_large_package_list(count: int) -> List[Package]:
    """Generate large package list for performance testing."""
    packages = []
    
    for i in range(count):
        package = Package(
            name=f"test-package-{i}",
            version=f"1.{i % 100}.{i % 10}",
            source_locations=[
                SourceLocation(
                    file_path=f"requirements-{i % 10}.txt",
                    line_number=i % 50 + 1,
                    declaration=f"test-package-{i}==1.{i % 100}.{i % 10}",
                    file_type=FileType.REQUIREMENTS
                )
            ],
            ecosystem="pypi"
        )
        packages.append(package)
    
    return packages


# Custom pytest markers for test organization

def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests"
    )
    config.addinivalue_line(
        "markers", "performance: marks tests as performance benchmarks"
    )