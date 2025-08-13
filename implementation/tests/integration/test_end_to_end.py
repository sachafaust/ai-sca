"""
Integration tests for end-to-end scanning workflow.
Tests complete scanning pipeline with mocked AI responses.
"""

import pytest
import asyncio
import json
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch

from sca_ai_scanner.core.client import AIVulnerabilityClient
from sca_ai_scanner.core.models import ScanConfig, VulnerabilityResults
from sca_ai_scanner.core.validator import ValidationPipeline
from sca_ai_scanner.parsers.python import PythonParser
from sca_ai_scanner.parsers.javascript import JavaScriptParser
from sca_ai_scanner.formatters.json_output import JSONOutputFormatter
from sca_ai_scanner.telemetry.engine import TelemetryEngine


class TestEndToEndScanning:
    """Test complete scanning workflow."""
    
    @pytest.fixture
    def mock_env_vars(self, monkeypatch):
        """Mock all required environment variables."""
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setenv("GOOGLE_AI_API_KEY", "test-key")
        monkeypatch.setenv("XAI_API_KEY", "test-key")
    
    @pytest.fixture
    def test_project(self, temp_project_dir, create_test_files):
        """Create a test project with multiple dependency files."""
        create_test_files(temp_project_dir, {
            "requirements.txt": """
requests==2.25.1
django==3.2.0
numpy==1.20.0
pandas==1.3.0
""",
            "package.json": """{
  "name": "test-app",
  "dependencies": {
    "express": "4.17.1",
    "lodash": "4.17.20",
    "axios": "0.21.1"
  }
}""",
        })
        return temp_project_dir
    
    @pytest.fixture
    def mock_ai_response(self):
        """Mock AI response with vulnerabilities."""
        return {
            "vulnerability_data": {
                "requests:2.25.1": {
                    "cves": [{
                        "id": "CVE-2023-32681",
                        "severity": "HIGH",
                        "description": "Certificate verification bypass in requests",
                        "cvss_score": 7.5
                    }],
                    "risk_assessment": {
                        "score": 7.5,
                        "business_impact": "Data exposure risk",
                        "exploitability": "Remote exploitation possible"
                    },
                    "remediation": {
                        "action": "upgrade",
                        "target_version": ">=2.31.0",
                        "urgency": "high",
                        "estimated_effort": "low"
                    },
                    "confidence": 0.95
                },
                "lodash:4.17.20": {
                    "cves": [{
                        "id": "CVE-2021-23337",
                        "severity": "HIGH",
                        "description": "Command injection via template function",
                        "cvss_score": 7.2
                    }],
                    "risk_assessment": {
                        "score": 7.2,
                        "business_impact": "Remote code execution risk",
                        "exploitability": "Requires template usage"
                    },
                    "remediation": {
                        "action": "upgrade",
                        "target_version": ">=4.17.21",
                        "urgency": "high",
                        "estimated_effort": "low"
                    },
                    "confidence": 0.92
                }
            },
            "cost": 0.05,
            "tokens": {"input": 500, "output": 1000}
        }
    
    @pytest.mark.asyncio
    async def test_complete_scanning_workflow(
        self, 
        mock_env_vars, 
        test_project, 
        mock_ai_response,
        temp_project_dir
    ):
        """Test complete scanning workflow from discovery to output."""
        
        # 1. Discover dependencies
        all_packages = []
        parsers = [
            PythonParser(str(test_project)),
            JavaScriptParser(str(test_project))
        ]
        
        for parser in parsers:
            packages = parser.parse_all_files()
            all_packages.extend(packages)
        
        # Verify we found packages from all sources
        assert len(all_packages) > 0
        package_names = {pkg.name for pkg in all_packages}
        assert "requests" in package_names  # Python
        assert "express" in package_names   # JavaScript
        
        # 2. Run AI vulnerability analysis
        config = ScanConfig(
            model="gpt-4o-mini-with-search",
            batch_size=10,
            daily_budget_limit=10.0
        )
        
        client = AIVulnerabilityClient(config)
        
        # Mock the AI analysis
        with patch.object(client, '_analyze_with_live_search', new_callable=AsyncMock) as mock_analyze:
            mock_analyze.return_value = mock_ai_response
            
            async with client:
                results = await client.bulk_analyze(all_packages)
        
        # Verify results
        assert results.vulnerability_summary.vulnerable_packages == 2
        assert "requests:2.25.1" in results.vulnerability_analysis
        assert "lodash:4.17.20" in results.vulnerability_analysis
        
        # 3. Validate critical findings
        validation_config = {
            'validate_critical': True,
            'validate_high': True,
            'spot_check_medium': False
        }
        
        # Mock validation responses
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = Mock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={
                "totalResults": 1,
                "vulnerabilities": [{
                    "cve": {
                        "id": "CVE-2023-32681",
                        "descriptions": [{"lang": "en", "value": "Validated description"}],
                        "metrics": {
                            "cvssMetricV31": [{
                                "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}
                            }]
                        }
                    }
                }]
            })
            
            # Properly mock the session with async close
            async def mock_close():
                pass
            
            mock_session_instance = Mock()
            mock_session_instance.close = mock_close
            
            # Mock the get context manager properly
            mock_get_context = AsyncMock()
            mock_get_context.__aenter__.return_value = mock_response
            mock_session_instance.get.return_value = mock_get_context
            
            mock_session.return_value.__aenter__.return_value = mock_session_instance
            
            validator = ValidationPipeline(validation_config)
            # Mock the validator's session directly - bypass __aenter__
            validator.session = mock_session_instance
            async with validator:
                validated_results = await validator.validate_findings(results)
        
        # 4. Export results
        output_file = temp_project_dir / "vulnerabilities.json"
        formatter = JSONOutputFormatter()
        await formatter.export_vulnerability_data(validated_results, output_file)
        
        # Verify output
        assert output_file.exists()
        
        with open(output_file) as f:
            output_data = json.load(f)
        
        assert "ai_agent_metadata" in output_data
        assert "vulnerability_analysis" in output_data
        assert output_data["ai_agent_metadata"]["workflow_stage"] == "remediation_ready"
    
    @pytest.mark.asyncio
    async def test_telemetry_integration(
        self, 
        mock_env_vars, 
        test_project,
        mock_ai_response,
        temp_project_dir
    ):
        """Test telemetry collection during scanning."""
        
        telemetry_file = temp_project_dir / "telemetry.jsonl"
        telemetry = TelemetryEngine(export_directory=str(temp_project_dir))
        
        # Log discovery event
        telemetry.log_event(
            "dependency_discovery",
            {
                "parser": "PythonParser",
                "packages_found": 4,
                "ecosystem": "pypi"
            }
        )
        
        # Log AI analysis event
        telemetry.log_event(
            "ai_analysis",
            {
                "model": "gpt-4o-mini-with-search",
                "packages_analyzed": 10,
                "average_confidence": 0.93
            }
        )
        
        # Log completion event
        telemetry.log_event(
            "scan_completed",
            {
                "duration_seconds": 45.2,
                "total_packages": 10,
                "vulnerable_packages": 2
            }
        )
        
        # Get telemetry statistics
        stats = telemetry.get_statistics()
        
        assert stats["buffer"]["events_count"] >= 3
        assert "performance" in stats
        assert "costs" in stats
        
        # Export events to file
        from sca_ai_scanner.telemetry.engine import ExportFormat
        exported_file = await telemetry.export_events(ExportFormat.JSON, "telemetry_events.json")
        
        # Verify telemetry file was written
        assert exported_file.exists()
        
        # Read and verify telemetry events
        with open(exported_file) as f:
            events = json.load(f)
        
        assert len(events) >= 3
        assert any(e["event_type"] == "dependency_discovery" for e in events)
        assert any(e["event_type"] == "scan_completed" for e in events)
    
    @pytest.mark.asyncio
    async def test_error_recovery_workflow(
        self, 
        mock_env_vars, 
        test_project,
        sample_packages
    ):
        """Test workflow continues despite partial failures."""
        
        config = ScanConfig(
            model="gpt-4o-mini",
            batch_size=5  # Small batches to test multiple failures
        )
        
        client = AIVulnerabilityClient(config)
        
        # Mock some batches failing
        call_count = 0
        async def mock_analyze(packages):
            nonlocal call_count
            call_count += 1
            
            # Fail every other batch
            if call_count % 2 == 0:
                raise Exception("Simulated API error")
            
            return {
                "vulnerability_data": {
                    f"package{call_count}:1.0": {
                        "cves": [],
                        "confidence": 0.9
                    }
                },
                "cost": 0.01,
                "tokens": {"input": 100, "output": 200}
            }
        
        with patch.object(client, '_analyze_knowledge_only', side_effect=mock_analyze):
            async with client:
                # Use many packages to create multiple batches
                many_packages = sample_packages * 10  # 20 packages = 4 batches
                results = await client.bulk_analyze(many_packages)
        
        # Should still get results despite failures
        assert results.vulnerability_summary.total_packages_analyzed == len(many_packages)
        # Only successful batches should have analysis
        assert len(results.vulnerability_analysis) > 0
    
    @pytest.mark.asyncio 
    async def test_multi_language_project_scanning(
        self,
        mock_env_vars,
        temp_project_dir,
        create_test_files,
        mock_ai_response
    ):
        """Test scanning project with multiple languages and dependency files."""
        
        # Create complex project structure
        create_test_files(temp_project_dir, {
            "backend/requirements.txt": "flask==2.0.1\nredis==3.5.3",
            "backend/pyproject.toml": """
[project]
dependencies = ["sqlalchemy>=1.4.0", "alembic>=1.7.0"]
""",
            "frontend/package.json": """{
  "dependencies": {
    "react": "17.0.2",
    "redux": "4.1.0"
  }
}""",
            "frontend/yarn.lock": """
react@17.0.2:
  version "17.0.2"
  resolved "https://registry.yarnpkg.com/react/-/react-17.0.2.tgz"
""",
        })
        
        # Discover all dependencies
        all_packages = []
        parsers = [
            PythonParser(str(temp_project_dir)),
            JavaScriptParser(str(temp_project_dir))
        ]
        
        for parser in parsers:
            packages = parser.parse_all_files()
            all_packages.extend(packages)
        
        # Verify we found packages from all locations
        package_names = {pkg.name for pkg in all_packages}
        
        # Python packages
        assert "flask" in package_names
        assert "sqlalchemy" in package_names
        
        # JavaScript packages
        assert "react" in package_names
        assert "redux" in package_names
        
        
        # Verify source tracking
        flask_pkg = next(p for p in all_packages if p.name == "flask")
        assert any("backend/requirements.txt" in loc.file_path for loc in flask_pkg.source_locations)
    
    @pytest.mark.asyncio
    async def test_performance_with_large_package_set(
        self,
        mock_env_vars,
        performance_timer
    ):
        """Test performance with large number of packages."""
        
        # Generate large package list
        from tests.conftest import generate_large_package_list
        large_package_list = generate_large_package_list(1000)
        
        config = ScanConfig(
            model="gpt-4o-mini",
            batch_size=75  # Realistic batch size
        )
        
        client = AIVulnerabilityClient(config)
        
        # Mock fast AI responses
        async def mock_analyze(packages):
            await asyncio.sleep(0.1)  # Simulate API delay
            return {
                "vulnerability_data": {
                    f"{pkg.name}:{pkg.version}": {
                        "cves": [],
                        "confidence": 0.9
                    } for pkg in packages[:5]  # Only return first 5 for speed
                },
                "cost": 0.05,
                "tokens": {"input": 300, "output": 500}
            }
        
        with patch.object(client, '_analyze_knowledge_only', side_effect=mock_analyze):
            performance_timer.start()
            
            async with client:
                results = await client.bulk_analyze(large_package_list)
            
            performance_timer.stop()
        
        # Verify performance
        assert performance_timer.elapsed < 30  # Should complete in under 30 seconds
        assert results.vulnerability_summary.total_packages_analyzed == 1000
        
        # Verify batching worked correctly
        expected_batches = (1000 + 74) // 75  # Ceiling division
        assert results.scan_metadata.get("total_cost") == expected_batches * 0.05