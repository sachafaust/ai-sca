"""
Unit tests for AIVulnerabilityClient.
Tests multi-provider support, error handling, and cost tracking.
"""

import pytest
import asyncio
import os
from unittest.mock import Mock, AsyncMock, patch
import aiohttp

from sca_ai_scanner.core.client import AIVulnerabilityClient
from sca_ai_scanner.core.models import ScanConfig, Package, VulnerabilityResults
from sca_ai_scanner.exceptions import (
    AuthenticationError, RateLimitError, BudgetExceededError,
    UnsupportedModelError, AIClientError
)


class TestAIVulnerabilityClient:
    """Test AIVulnerabilityClient functionality."""
    
    @pytest.fixture
    def mock_env_vars(self, monkeypatch):
        """Mock environment variables for API keys."""
        monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
        monkeypatch.setenv("GOOGLE_AI_API_KEY", "test-google-key")
        monkeypatch.setenv("XAI_API_KEY", "test-xai-key")
    
    @pytest.fixture
    def openai_config(self):
        """Create OpenAI configuration."""
        return ScanConfig(
            model="gpt-4o-mini-with-search",
            enable_live_search=True,
            batch_size=10,
            daily_budget_limit=10.0
        )
    
    @pytest.fixture
    def anthropic_config(self):
        """Create Anthropic configuration."""
        return ScanConfig(
            model="claude-3.5-haiku-tools",
            enable_live_search=True,
            batch_size=10,
            daily_budget_limit=10.0
        )
    
    def test_provider_detection(self, mock_env_vars):
        """Test automatic provider detection from model name."""
        test_cases = [
            # OpenAI Models (comprehensive coverage)
            ("gpt-4o-mini", "openai"),
            ("gpt-4.1", "openai"),
            ("o1", "openai"),
            ("o1-mini", "openai"),
            ("o3", "openai"),
            ("o3-pro", "openai"),
            ("o4-mini", "openai"),
            # Anthropic Models  
            ("claude-3.5-sonnet", "anthropic"),
            ("claude-4", "anthropic"),
            ("claude-3.7-sonnet", "anthropic"),
            # Google Models
            ("gemini-2.0-flash", "google"),
            ("gemini-2.5-pro", "google"),
            ("gemini-2.5-flash-lite", "google"),
            # X.AI Models
            ("grok-3", "xai"),
            ("grok-4", "xai"),
            ("grok", "xai")
        ]
        
        for model, expected_provider in test_cases:
            config = ScanConfig(model=model)
            client = AIVulnerabilityClient(config)
            assert client.provider == expected_provider
    
    def test_live_search_capability_detection(self, mock_env_vars):
        """Test live search capability detection."""
        # Models with live search
        live_search_models = [
            "gpt-4o-with-search",
            "gpt-4o-mini-with-search",
            "claude-3.5-sonnet-tools",
            "claude-3.5-haiku-tools",
            "gemini-2.0-flash-search",
            "grok-3-web",
            "grok-3-mini-web"
        ]
        
        for model in live_search_models:
            config = ScanConfig(model=model)
            client = AIVulnerabilityClient(config)
            assert client.supports_live_search is True
        
        # Models without live search
        knowledge_only_models = [
            "gpt-4o-mini",
            "claude-3.5-haiku",
            "gemini-2.0-flash",
            "grok-3"
        ]
        
        for model in knowledge_only_models:
            config = ScanConfig(model=model)
            client = AIVulnerabilityClient(config)
            assert client.supports_live_search is False
    
    def test_missing_api_key(self, monkeypatch):
        """Test error when API key is missing."""
        # Clear OpenAI key
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        
        config = ScanConfig(model="gpt-4o-mini")
        
        with pytest.raises(AuthenticationError) as exc_info:
            AIVulnerabilityClient(config)
        
        assert "API key not found" in str(exc_info.value)
        assert "OPENAI_API_KEY" in str(exc_info.value)
    
    def test_unsupported_model(self, mock_env_vars):
        """Test error for unsupported model."""
        config = ScanConfig(model="unknown-model-123")
        
        with pytest.raises(UnsupportedModelError) as exc_info:
            AIVulnerabilityClient(config)
        
        assert "Unknown model provider" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_bulk_analyze_empty_packages(self, mock_env_vars, openai_config):
        """Test bulk_analyze with empty package list."""
        client = AIVulnerabilityClient(openai_config)
        
        async with client:
            results = await client.bulk_analyze([])
        
        assert results.vulnerability_summary.total_packages_analyzed == 0
        assert results.vulnerability_summary.vulnerable_packages == 0
        assert len(results.vulnerability_analysis) == 0
    
    @pytest.mark.asyncio
    async def test_bulk_analyze_with_batching(self, mock_env_vars, openai_config, sample_packages):
        """Test bulk_analyze creates correct batches."""
        client = AIVulnerabilityClient(openai_config)
        
        # Create many packages to test batching
        many_packages = sample_packages * 50  # 100 packages
        
        # Mock the AI response
        with patch.object(client, '_analyze_with_live_search', new_callable=AsyncMock) as mock_analyze:
            mock_analyze.return_value = {
                "vulnerability_data": {},
                "cost": 0.01,
                "tokens": {"input": 100, "output": 200}
            }
            
            async with client:
                results = await client.bulk_analyze(many_packages)
            
            # Should create 10 batches (100 packages / 10 batch_size)
            assert mock_analyze.call_count == 10
    
    @pytest.mark.asyncio
    async def test_budget_exceeded_error(self, mock_env_vars, openai_config):
        """Test budget exceeded error handling."""
        # Enable budget checking for this test
        openai_config.budget_enabled = True
        client = AIVulnerabilityClient(openai_config)
        client.daily_cost = 9.99  # Just under limit
        
        # Mock response with cost that exceeds budget
        with patch.object(client, '_analyze_with_live_search', new_callable=AsyncMock) as mock_analyze:
            mock_analyze.return_value = {
                "vulnerability_data": {},
                "cost": 0.02,  # This will push over the $10 limit
                "tokens": {"input": 100, "output": 200}
            }
            
            async with client:
                with pytest.raises(BudgetExceededError) as exc_info:
                    await client.bulk_analyze([Package(name="test", version="1.0", ecosystem="pypi")])
                
                assert "Daily budget limit reached" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_openai_api_response_parsing(self, mock_env_vars, openai_config):
        """Test parsing OpenAI API responses."""
        client = AIVulnerabilityClient(openai_config)
        
        # Mock OpenAI response format
        mock_response = {
            "choices": [{
                "message": {
                    "content": """{
                        "requests:2.25.1": {
                            "cves": [{
                                "id": "CVE-2023-32681",
                                "severity": "HIGH",
                                "description": "Test vulnerability"
                            }],
                            "confidence": 0.95
                        }
                    }"""
                }
            }],
            "usage": {
                "prompt_tokens": 150,
                "completion_tokens": 250
            }
        }
        
        parsed = client._parse_openai_response(mock_response)
        
        assert "vulnerability_data" in parsed
        assert "requests:2.25.1" in parsed["vulnerability_data"]
        assert parsed["tokens"]["input"] == 150
        assert parsed["tokens"]["output"] == 250
        assert parsed["cost"] > 0  # Cost should be calculated
    
    @pytest.mark.asyncio
    async def test_anthropic_api_response_parsing(self, mock_env_vars, anthropic_config):
        """Test parsing Anthropic API responses."""
        client = AIVulnerabilityClient(anthropic_config)
        
        # Mock Anthropic response format
        mock_response = {
            "content": [{
                "text": """{
                    "django:3.2.0": {
                        "cves": [],
                        "confidence": 0.99
                    }
                }"""
            }],
            "usage": {
                "input_tokens": 100,
                "output_tokens": 150
            }
        }
        
        parsed = client._parse_anthropic_response(mock_response)
        
        assert "vulnerability_data" in parsed
        assert "django:3.2.0" in parsed["vulnerability_data"]
        assert parsed["tokens"]["input"] == 100
        assert parsed["tokens"]["output"] == 150
    
    @pytest.mark.asyncio
    async def test_rate_limit_error_handling(self, mock_env_vars, openai_config):
        """Test rate limit error handling."""
        client = AIVulnerabilityClient(openai_config)
        
        # Create mock session that returns 429
        mock_response = Mock()
        mock_response.status = 429
        mock_response.text = AsyncMock(return_value="Rate limit exceeded")
        mock_response.headers = {}
        
        # Mock aiohttp.ClientSession to prevent real network calls
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = Mock()
            # Create proper async context manager mock
            mock_context_manager = AsyncMock()
            mock_context_manager.__aenter__.return_value = mock_response
            mock_session.post.return_value = mock_context_manager
            mock_session.close = AsyncMock()
            mock_session_class.return_value = mock_session
            
            async with client:
                with pytest.raises(RateLimitError) as exc_info:
                    await client._make_api_request("http://test.com", {})
                
                assert "Rate limit exceeded" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_authentication_error_handling(self, mock_env_vars, openai_config):
        """Test authentication error handling."""
        client = AIVulnerabilityClient(openai_config)
        
        # Create mock session that returns 401
        mock_response = Mock()
        mock_response.status = 401
        mock_response.headers = {}
        
        # Mock aiohttp.ClientSession to prevent real network calls
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = Mock()
            # Create proper async context manager mock
            mock_context_manager = AsyncMock()
            mock_context_manager.__aenter__.return_value = mock_response
            mock_session.post.return_value = mock_context_manager
            mock_session.close = AsyncMock()
            mock_session_class.return_value = mock_session
            
            async with client:
                with pytest.raises(AuthenticationError) as exc_info:
                    await client._make_api_request("http://test.com", {})
                
                assert "Invalid API key" in str(exc_info.value)
    
    def test_cost_calculation_openai(self, mock_env_vars, openai_config):
        """Test cost calculation for OpenAI models."""
        client = AIVulnerabilityClient(openai_config)
        
        # Test known model costs
        cost = client._calculate_openai_cost(1000, 2000)  # 1K input, 2K output
        
        # The model is "gpt-4o-mini-with-search" but cost calculation extracts "gpt-4o"
        # which has costs: $0.005/1K input, $0.015/1K output
        expected_cost = (1000 * 0.005 / 1000) + (2000 * 0.015 / 1000)
        assert abs(cost - expected_cost) < 0.0001
    
    def test_cost_calculation_anthropic(self, mock_env_vars, anthropic_config):
        """Test cost calculation for Anthropic models."""
        client = AIVulnerabilityClient(anthropic_config)
        
        # Test known model costs
        cost = client._calculate_anthropic_cost(1000, 2000)
        
        # claude-3.5-haiku costs: $0.00025/1K input, $0.00125/1K output
        expected_cost = (1000 * 0.00025 / 1000) + (2000 * 0.00125 / 1000)
        assert abs(cost - expected_cost) < 0.0001
    
    @pytest.mark.asyncio
    async def test_batch_failure_handling(self, mock_env_vars, openai_config, sample_packages):
        """Test handling of batch processing failures."""
        client = AIVulnerabilityClient(openai_config)
        
        # Mock first batch fails, second succeeds
        call_count = 0
        async def mock_analyze(packages):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise AIClientError("Network error")
            return {
                "vulnerability_data": {
                    "test:1.0": {"cves": [], "confidence": 0.9}
                },
                "cost": 0.01,
                "tokens": {"input": 100, "output": 200}
            }
        
        with patch.object(client, '_analyze_with_live_search', side_effect=mock_analyze):
            async with client:
                # Create 2 batches
                packages = sample_packages * 6  # 12 packages = 2 batches
                results = await client.bulk_analyze(packages)
                
                # Should still get partial results
                assert results.vulnerability_summary.total_packages_analyzed == len(packages)
    
    def test_extract_vulnerability_json_edge_cases(self, mock_env_vars, openai_config):
        """Test JSON extraction from various response formats."""
        client = AIVulnerabilityClient(openai_config)
        
        # Test with markdown code block
        response = """
        Here's the analysis:
        
        ```json
        {"test": "value"}
        ```
        
        Done.
        """
        result = client._extract_vulnerability_json(response)
        assert result == {"test": "value"}
        
        # Test with no JSON
        response = "No vulnerabilities found."
        result = client._extract_vulnerability_json(response)
        assert result.get("parsing_failed") is True
        
        # Test with malformed JSON
        response = '{"incomplete": '
        result = client._extract_vulnerability_json(response)
        assert result.get("parsing_failed") is True
    
    @pytest.mark.asyncio
    async def test_session_management(self, mock_env_vars, openai_config):
        """Test async session management."""
        client = AIVulnerabilityClient(openai_config)
        
        # Session should be None initially
        assert client.session is None
        
        # Session should be created in context manager
        async with client:
            assert client.session is not None
            assert isinstance(client.session, aiohttp.ClientSession)
        
        # Session should be closed after context
        assert client.session.closed