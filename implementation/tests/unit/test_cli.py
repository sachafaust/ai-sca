"""
Unit tests for CLI interface.
Tests command parsing, error handling, and output formatting.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from pathlib import Path
import json

from click.testing import CliRunner
from sca_ai_scanner.cli import main, validate_environment
from sca_ai_scanner.core.models import ScanConfig
from sca_ai_scanner.exceptions import (
    AuthenticationError, BudgetExceededError, UnsupportedModelError
)


class TestCLI:
    """Test CLI functionality."""
    
    @pytest.fixture
    def runner(self):
        """Create CLI test runner."""
        return CliRunner()
    
    @pytest.fixture
    def mock_env_vars(self, monkeypatch):
        """Mock required environment variables."""
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    
    def test_help_command(self, runner):
        """Test help command output."""
        result = runner.invoke(main, ['--help'])
        
        assert result.exit_code == 0
        assert "AI-Powered SCA Vulnerability Scanner" in result.output
        assert "TARGET_PATH" in result.output
        assert "--model" in result.output
        assert "--vulnerability-data" in result.output
    
    def test_missing_target_path(self, runner):
        """Test error when target path is missing."""
        result = runner.invoke(main, [])
        
        assert result.exit_code != 0
        assert "TARGET_PATH is required" in result.output
    
    def test_invalid_target_path(self, runner, mock_env_vars):
        """Test error when target path doesn't exist."""
        result = runner.invoke(main, ['/nonexistent/path'])
        
        assert result.exit_code != 0
        # Click validates path existence
    
    def test_model_selection(self, runner, mock_env_vars, temp_project_dir):
        """Test different model selections."""
        with patch('sca_ai_scanner.cli.async_main', new_callable=AsyncMock) as mock_async_main:
            # Test default model
            result = runner.invoke(main, [str(temp_project_dir)])
            assert result.exit_code == 0
            mock_async_main.assert_called_once()
            call_args = mock_async_main.call_args[1]
            assert call_args['model'] == 'gpt-4o-mini-with-search'
            
            # Test custom model
            mock_async_main.reset_mock()
            result = runner.invoke(main, [
                str(temp_project_dir),
                '--model', 'claude-3.5-haiku-tools'
            ])
            assert result.exit_code == 0
            call_args = mock_async_main.call_args[1]
            assert call_args['model'] == 'claude-3.5-haiku-tools'
    
    def test_knowledge_only_flag(self, runner, mock_env_vars, temp_project_dir):
        """Test knowledge-only mode flag."""
        with patch('sca_ai_scanner.cli.async_main', new_callable=AsyncMock) as mock_async_main:
            result = runner.invoke(main, [
                str(temp_project_dir),
                '--knowledge-only'
            ])
            
            assert result.exit_code == 0
            call_args = mock_async_main.call_args[1]
            assert call_args['knowledge_only'] is True
    
    def test_budget_configuration(self, runner, mock_env_vars, temp_project_dir):
        """Test budget configuration."""
        with patch('sca_ai_scanner.cli.async_main', new_callable=AsyncMock) as mock_async_main:
            result = runner.invoke(main, [
                str(temp_project_dir),
                '--budget', '25.50'
            ])
            
            assert result.exit_code == 0
            call_args = mock_async_main.call_args[1]
            assert call_args['budget'] == 25.50
    
    def test_output_formats(self, runner, mock_env_vars, temp_project_dir):
        """Test different output format options."""
        valid_formats = ['json', 'table', 'summary']
        
        for fmt in valid_formats:
            with patch('sca_ai_scanner.cli.async_main', new_callable=AsyncMock) as mock_async_main:
                result = runner.invoke(main, [
                    str(temp_project_dir),
                    '--output-format', fmt
                ])
                
                assert result.exit_code == 0
                call_args = mock_async_main.call_args[1]
                assert call_args['output_format'] == fmt
    
    def test_quiet_and_verbose_flags(self, runner, mock_env_vars, temp_project_dir):
        """Test quiet and verbose output flags."""
        with patch('sca_ai_scanner.cli.async_main', new_callable=AsyncMock) as mock_async_main:
            # Test quiet mode
            result = runner.invoke(main, [
                str(temp_project_dir),
                '--quiet'
            ])
            assert result.exit_code == 0
            call_args = mock_async_main.call_args[1]
            assert call_args['quiet'] is True
            
            # Test verbose mode
            result = runner.invoke(main, [
                str(temp_project_dir),
                '--verbose'
            ])
            assert result.exit_code == 0
            call_args = mock_async_main.call_args[1]
            assert call_args['verbose'] is True
    
    def test_vulnerability_data_export(self, runner, mock_env_vars, temp_project_dir):
        """Test vulnerability data export option."""
        output_file = temp_project_dir / "vulns.json"
        
        with patch('sca_ai_scanner.cli.async_main', new_callable=AsyncMock) as mock_async_main:
            result = runner.invoke(main, [
                str(temp_project_dir),
                '--vulnerability-data', str(output_file)
            ])
            
            assert result.exit_code == 0
            call_args = mock_async_main.call_args[1]
            assert call_args['vulnerability_data'] == output_file
    
    def test_telemetry_options(self, runner, mock_env_vars, temp_project_dir):
        """Test telemetry configuration options."""
        telemetry_file = temp_project_dir / "telemetry.jsonl"
        
        with patch('sca_ai_scanner.cli.async_main', new_callable=AsyncMock) as mock_async_main:
            result = runner.invoke(main, [
                str(temp_project_dir),
                '--telemetry-file', str(telemetry_file),
                '--telemetry-level', 'debug'
            ])
            
            assert result.exit_code == 0
            call_args = mock_async_main.call_args[1]
            assert call_args['telemetry_file'] == telemetry_file
            assert call_args['telemetry_level'] == 'debug'
    
    def test_authentication_error_handling(self, runner, temp_project_dir):
        """Test handling of missing API keys."""
        # No environment variables set
        with patch('sca_ai_scanner.cli.async_main', new_callable=AsyncMock) as mock_async_main:
            mock_async_main.side_effect = AuthenticationError(
                "API key not found for openai. Set environment variable: OPENAI_API_KEY"
            )
            
            result = runner.invoke(main, [str(temp_project_dir)])
            
            assert result.exit_code == 1
            # The Click framework might wrap the error message
            assert ("Authentication Error" in result.output or 
                    "API key not found" in result.output)
            assert "OPENAI_API_KEY" in result.output
    
    def test_budget_exceeded_error_handling(self, runner, mock_env_vars, temp_project_dir):
        """Test handling of budget exceeded errors."""
        with patch('sca_ai_scanner.cli.async_main', new_callable=AsyncMock) as mock_async_main:
            mock_async_main.side_effect = BudgetExceededError(
                "Daily budget limit reached: $52.30 >= $50.00"
            )
            
            result = runner.invoke(main, [str(temp_project_dir)])
            
            assert result.exit_code == 1
            assert ("Budget Exceeded" in result.output or 
                    "Daily budget limit reached" in result.output)
            assert ("Increase budget with: --budget" in result.output or
                    "budget" in result.output.lower())
    
    def test_unsupported_model_error_handling(self, runner, mock_env_vars, temp_project_dir):
        """Test handling of unsupported model errors."""
        with patch('sca_ai_scanner.cli.async_main', new_callable=AsyncMock) as mock_async_main:
            mock_async_main.side_effect = UnsupportedModelError(
                "Unknown model provider for: invalid-model"
            )
            
            result = runner.invoke(main, [
                str(temp_project_dir),
                '--model', 'invalid-model'
            ])
            
            assert result.exit_code == 1
            assert ("Unsupported Model" in result.output or 
                    "Unknown model provider" in result.output)
    
    def test_keyboard_interrupt_handling(self, runner, mock_env_vars, temp_project_dir):
        """Test handling of keyboard interrupts."""
        with patch('sca_ai_scanner.cli.async_main', new_callable=AsyncMock) as mock_async_main:
            mock_async_main.side_effect = KeyboardInterrupt()
            
            result = runner.invoke(main, [str(temp_project_dir)])
            
            assert result.exit_code == 1
            assert "Scan interrupted by user" in result.output
    
    def test_validate_environment_function(self, monkeypatch):
        """Test environment validation function."""
        # Test with valid OpenAI key
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        config = ScanConfig(model="gpt-4o-mini")
        
        # Should not raise
        validate_environment(config)
        
        # Test with missing key
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        
        with pytest.raises(AuthenticationError) as exc_info:
            validate_environment(config)
        
        assert "API key not found" in str(exc_info.value)
        assert "OPENAI_API_KEY" in str(exc_info.value)
        
        # Test with unsupported model
        config = ScanConfig(model="unknown-model")
        
        with pytest.raises(UnsupportedModelError) as exc_info:
            validate_environment(config)
        
        assert "Unknown model provider" in str(exc_info.value)
    
    def test_batch_size_validation(self, runner, mock_env_vars, temp_project_dir):
        """Test batch size parameter validation."""
        with patch('sca_ai_scanner.cli.async_main', new_callable=AsyncMock) as mock_async_main:
            # Valid batch size
            result = runner.invoke(main, [
                str(temp_project_dir),
                '--batch-size', '100'
            ])
            assert result.exit_code == 0
            
            # Invalid batch size (handled by click's int type)
            result = runner.invoke(main, [
                str(temp_project_dir),
                '--batch-size', 'invalid'
            ])
            assert result.exit_code != 0
            assert "Invalid value" in result.output
    
    def test_config_file_option(self, runner, mock_env_vars, temp_project_dir):
        """Test configuration file option."""
        config_file = temp_project_dir / "config.yml"
        config_file.write_text("model: gpt-4o-mini")
        
        with patch('sca_ai_scanner.cli.async_main', new_callable=AsyncMock) as mock_async_main:
            result = runner.invoke(main, [
                str(temp_project_dir),
                '--config', str(config_file)
            ])
            
            assert result.exit_code == 0
            call_args = mock_async_main.call_args[1]
            assert call_args['config'] == config_file
    
    def test_force_fresh_flag(self, runner, mock_env_vars, temp_project_dir):
        """Test force fresh scan flag."""
        with patch('sca_ai_scanner.cli.async_main', new_callable=AsyncMock) as mock_async_main:
            result = runner.invoke(main, [
                str(temp_project_dir),
                '--force-fresh'
            ])
            
            assert result.exit_code == 0
            call_args = mock_async_main.call_args[1]
            assert call_args['force_fresh'] is True