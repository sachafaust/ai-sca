"""
Unit tests for TokenOptimizer.
Tests prompt generation, response parsing, and optimization strategies.
"""

import pytest
import json
from unittest.mock import Mock

from sca_ai_scanner.core.optimizer import TokenOptimizer
from sca_ai_scanner.core.models import Package, ScanConfig, SourceLocation, FileType


class TestTokenOptimizer:
    """Test TokenOptimizer functionality."""
    
    @pytest.fixture
    def optimizer(self, sample_scan_config):
        """Create TokenOptimizer instance."""
        return TokenOptimizer(sample_scan_config)
    
    @pytest.fixture
    def test_packages(self):
        """Create test packages for optimization."""
        return [
            Package(
                name="requests",
                version="2.25.1",
                ecosystem="pypi",
                source_locations=[
                    SourceLocation(
                        file_path="requirements.txt",
                        line_number=10,
                        declaration="requests==2.25.1",
                        file_type=FileType.REQUIREMENTS
                    )
                ]
            ),
            Package(
                name="django",
                version="3.2.0",
                ecosystem="pypi"
            ),
            Package(
                name="express",
                version="4.17.1",
                ecosystem="npm"
            )
        ]
    
    def test_create_prompt_knowledge_only(self, optimizer, test_packages):
        """Test prompt generation for knowledge-only models."""
        prompt = optimizer.create_prompt(test_packages)
        
        # Verify optimized prompt structure
        assert "Find ALL CVEs affecting these 3 packages" in prompt
        assert "CRITICAL: Each CVE ID represents a DISTINCT vulnerability" in prompt
        assert "YEAR-BY-YEAR REASONING CHECKLIST" in prompt
        assert "requests:2.25.1" in prompt
        assert "django:3.2.0" in prompt
        assert "express:4.17.1" in prompt
        assert "Return ONLY vulnerable packages in JSON format" in prompt
        assert "confidence" in prompt
    
    def test_create_prompt_with_live_search(self, optimizer, test_packages):
        """Test prompt generation for live search models."""
        prompt = optimizer.create_prompt_with_live_search(test_packages)
        
        # Verify optimized live search instructions
        assert "Find ALL CVEs affecting these 3 packages using live web search" in prompt
        assert "CRITICAL: Each CVE ID represents a DISTINCT vulnerability" in prompt
        assert "SYSTEMATIC LIVE SEARCH PROCEDURE" in prompt
        assert "Year-by-year CVE database searches" in prompt
        assert "Search NVD" in prompt
        assert "live_search" in prompt
        assert "Search OSV.dev" in prompt
    
    def test_format_package_list_strategies(self, optimizer, test_packages):
        """Test different formatting strategies."""
        # Test balanced format (default)
        optimizer.strategy = "balanced"
        formatted = optimizer._format_package_list(test_packages)
        assert "- requests:2.25.1 (pypi)" in formatted
        assert "- django:3.2.0 (pypi)" in formatted
        
        # Test compact format
        optimizer.strategy = "compact"
        formatted = optimizer._format_package_list(test_packages)
        assert formatted == "requests:2.25.1, django:3.2.0, express:4.17.1"
        
        # Test detailed format
        optimizer.strategy = "detailed"
        formatted = optimizer._format_package_list(test_packages)
        assert "[found in:" in formatted
    
    def test_optimize_response_parsing_valid_json(self, optimizer):
        """Test parsing valid JSON response."""
        response = """
        Here's the analysis:
        
        ```json
        {
            "requests:2.25.1": {
                "cves": [{"id": "CVE-2023-32681", "severity": "HIGH"}],
                "confidence": 0.95
            }
        }
        ```
        """
        
        result = optimizer.optimize_response_parsing(response)
        
        assert "requests:2.25.1" in result
        assert result["requests:2.25.1"]["confidence"] == 0.95
        assert len(result["requests:2.25.1"]["cves"]) == 1
    
    def test_optimize_response_parsing_no_json(self, optimizer):
        """Test parsing response without JSON."""
        response = "No vulnerabilities found in the packages."
        
        result = optimizer.optimize_response_parsing(response)
        
        assert result.get("parsing_error") is True
        assert result.get("raw_response") == response
    
    def test_extract_complete_json_with_nested_objects(self, optimizer):
        """Test extracting JSON with nested objects."""
        response = """Some text before {
            "package1": {
                "nested": {
                    "deep": "value"
                }
            },
            "package2": {}
        } and text after"""
        
        result = optimizer._extract_complete_json(response)
        
        assert "package1" in result
        assert result["package1"]["nested"]["deep"] == "value"
    
    def test_fix_common_json_issues(self, optimizer):
        """Test fixing common JSON formatting issues."""
        # Test trailing comma fix
        bad_json = '{"key": "value",}'
        fixed = optimizer._fix_common_json_issues(bad_json)
        assert fixed == '{"key": "value"}'
        
        # Test unquoted keys
        bad_json = '{key: "value"}'
        fixed = optimizer._fix_common_json_issues(bad_json)
        assert '"key"' in fixed
        
        # Test single quotes
        bad_json = "{'key': 'value'}"
        fixed = optimizer._fix_common_json_issues(bad_json)
        assert '"key"' in fixed
        assert '"value"' in fixed
    
    def test_calculate_token_estimate(self, optimizer, test_packages):
        """Test token usage estimation."""
        estimate = optimizer.calculate_token_estimate(test_packages)
        
        assert "input_tokens" in estimate
        assert "output_tokens" in estimate
        assert "total_tokens" in estimate
        
        # Verify reasonable estimates
        assert estimate["input_tokens"] > 0
        assert estimate["output_tokens"] > 0
        assert estimate["total_tokens"] == estimate["input_tokens"] + estimate["output_tokens"]
    
    def test_optimize_batch_size(self, optimizer):
        """Test batch size optimization."""
        # Test with different package counts
        batch_size = optimizer.optimize_batch_size(1000, max_context_tokens=100000)
        assert batch_size > 0
        assert batch_size <= optimizer.config.batch_size
        
        # Test with small package count
        batch_size = optimizer.optimize_batch_size(10, max_context_tokens=100000)
        assert batch_size == 10  # Should not exceed total packages
        
        # Test with limited context
        batch_size = optimizer.optimize_batch_size(1000, max_context_tokens=1500)
        assert batch_size < 75  # Should be reduced due to context limit
    
    def test_get_optimization_metrics(self, optimizer):
        """Test optimization metrics generation."""
        metrics = optimizer.get_optimization_metrics()
        
        assert metrics["strategy"] == "balanced"
        assert metrics["batch_size"] == optimizer.config.batch_size
        assert "optimization_opportunities" in metrics
        assert "performance_indicators" in metrics
        assert isinstance(metrics["optimization_opportunities"], list)
    
    def test_validate_response_structure(self, optimizer):
        """Test response structure validation."""
        # Valid response
        valid_response = {
            "package:1.0.0": {
                "cves": [],
                "confidence": 0.9
            }
        }
        assert optimizer._validate_response_structure(valid_response) is True
        
        # Invalid response - has error
        invalid_response = {
            "parsing_error": True,
            "raw_response": "error"
        }
        assert optimizer._validate_response_structure(invalid_response) is False
        
        # Invalid response - not a dict
        assert optimizer._validate_response_structure("not a dict") is False
        
        # Invalid response - no package data
        invalid_response = {
            "some_key": "some_value"
        }
        assert optimizer._validate_response_structure(invalid_response) is False
    
    def test_edge_cases(self, optimizer):
        """Test edge cases and error conditions."""
        # Empty package list
        prompt = optimizer.create_prompt([])
        assert "0 packages" in prompt
        
        # Package with special characters
        special_package = Package(
            name="@scope/package-name",
            version="1.0.0-beta.1",
            ecosystem="npm"
        )
        prompt = optimizer.create_prompt([special_package])
        assert "@scope/package-name:1.0.0-beta.1" in prompt
        
        # Very long package list (test truncation/batching)
        many_packages = [
            Package(name=f"package-{i}", version=f"{i}.0.0", ecosystem="pypi")
            for i in range(200)
        ]
        prompt = optimizer.create_prompt(many_packages)
        assert "200 packages" in prompt