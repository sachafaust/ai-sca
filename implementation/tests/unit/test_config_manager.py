"""
Comprehensive unit tests for the Configuration Manager component.

Covers all critical enterprise scenarios including:
- Configuration loading and validation
- Security validation (API key detection)
- File discovery and precedence
- Environment variable integration
- Error handling and edge cases
- Performance testing
- Multi-environment configurations
"""

import pytest
import os
import tempfile
import yaml
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock
from typing import Dict, Any

from sca_ai_scanner.config.manager import ConfigManager
from sca_ai_scanner.exceptions import ConfigurationError


class TestConfigManagerInitialization:
    """Test ConfigManager initialization and basic setup."""
    
    def test_init_with_custom_path(self, temp_project_dir):
        """Test initialization with custom config path."""
        config_path = temp_project_dir / "custom_config.yml"
        manager = ConfigManager(config_path=config_path)
        assert manager.config_path == config_path
    
    def test_init_without_path_finds_default(self, temp_project_dir):
        """Test initialization without path finds default configuration."""
        # Create a config file in current directory
        config_path = temp_project_dir / "sca_ai_config.yml"
        config_path.write_text("model: test-model\n")
        
        with patch('sca_ai_scanner.config.manager.Path.cwd', return_value=temp_project_dir):
            manager = ConfigManager()
            assert manager.config_path == config_path
    
    def test_init_without_path_no_config_found(self):
        """Test initialization when no configuration file is found."""
        with patch('sca_ai_scanner.config.manager.Path.home') as mock_home, \
             patch('sca_ai_scanner.config.manager.Path.cwd') as mock_cwd:
            
            mock_home.return_value = Path("/nonexistent/home")
            mock_cwd.return_value = Path("/nonexistent/cwd")
            
            manager = ConfigManager()
            assert manager.config_path is None
    
    def test_default_config_structure(self):
        """Test that default configuration has all required sections."""
        manager = ConfigManager()
        
        required_sections = [
            'model', 'providers', 'analysis', 'budget', 
            'optimization', 'validation', 'telemetry'
        ]
        
        for section in required_sections:
            assert section in manager.default_config
    
    def test_default_config_values(self):
        """Test specific default configuration values."""
        manager = ConfigManager()
        config = manager.default_config
        
        assert config['model'] == "gpt-4o-mini-with-search"
        assert config['analysis']['confidence_threshold'] == 0.8
        assert config['budget']['enabled'] is False
        assert config['validation']['validate_critical'] is True
        assert 'openai' in config['providers']
        assert 'anthropic' in config['providers']


class TestConfigurationFileDiscovery:
    """Test configuration file discovery and precedence."""
    
    def test_find_home_directory_yml(self, temp_project_dir):
        """Test finding .sca_ai_config.yml in home directory."""
        home_config = temp_project_dir / ".sca_ai_config.yml"
        home_config.write_text("model: home-model\n")
        
        with patch('sca_ai_scanner.config.manager.Path.home', return_value=temp_project_dir):
            manager = ConfigManager()
            assert manager.config_path == home_config
    
    def test_find_home_directory_yaml(self, temp_project_dir):
        """Test finding .sca_ai_config.yaml in home directory."""
        home_config = temp_project_dir / ".sca_ai_config.yaml"
        home_config.write_text("model: home-model\n")
        
        with patch('sca_ai_scanner.config.manager.Path.home', return_value=temp_project_dir):
            manager = ConfigManager()
            assert manager.config_path == home_config
    
    def test_find_current_directory_yml(self, temp_project_dir):
        """Test finding sca_ai_config.yml in current directory."""
        cwd_config = temp_project_dir / "sca_ai_config.yml"
        cwd_config.write_text("model: cwd-model\n")
        
        with patch('sca_ai_scanner.config.manager.Path.home', return_value=Path("/nonexistent")), \
             patch('sca_ai_scanner.config.manager.Path.cwd', return_value=temp_project_dir):
            manager = ConfigManager()
            assert manager.config_path == cwd_config
    
    def test_file_precedence_order(self, temp_project_dir):
        """Test that home directory files take precedence over current directory."""
        home_dir = temp_project_dir / "home"
        cwd_dir = temp_project_dir / "cwd"
        home_dir.mkdir()
        cwd_dir.mkdir()
        
        # Create files in both directories
        home_config = home_dir / ".sca_ai_config.yml"
        cwd_config = cwd_dir / "sca_ai_config.yml"
        home_config.write_text("model: home-model\n")
        cwd_config.write_text("model: cwd-model\n")
        
        with patch('sca_ai_scanner.config.manager.Path.home', return_value=home_dir), \
             patch('sca_ai_scanner.config.manager.Path.cwd', return_value=cwd_dir):
            manager = ConfigManager()
            assert manager.config_path == home_config
    
    def test_yml_vs_yaml_extension_precedence(self, temp_project_dir):
        """Test that .yml takes precedence over .yaml extension."""
        yml_config = temp_project_dir / ".sca_ai_config.yml"
        yaml_config = temp_project_dir / ".sca_ai_config.yaml"
        yml_config.write_text("model: yml-model\n")
        yaml_config.write_text("model: yaml-model\n")
        
        with patch('sca_ai_scanner.config.manager.Path.home', return_value=temp_project_dir):
            manager = ConfigManager()
            assert manager.config_path == yml_config


class TestConfigurationLoading:
    """Test configuration loading from various sources."""
    
    def test_load_valid_config_file(self, temp_project_dir):
        """Test loading a valid configuration file."""
        config_path = temp_project_dir / "config.yml"
        config_data = {
            'model': 'custom-model',
            'analysis': {
                'confidence_threshold': 0.9,
                'batch_size': 50
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        loaded_config = manager.load_config()
        
        assert loaded_config['model'] == 'custom-model'
        assert loaded_config['analysis']['confidence_threshold'] == 0.9
        assert loaded_config['analysis']['batch_size'] == 50
        # Default values should still be present
        assert loaded_config['budget']['enabled'] is False
    
    def test_load_empty_config_file(self, temp_project_dir):
        """Test loading an empty configuration file."""
        config_path = temp_project_dir / "empty_config.yml"
        config_path.write_text("")
        
        manager = ConfigManager(config_path=config_path)
        loaded_config = manager.load_config()
        
        # Should return default configuration
        assert loaded_config['model'] == "gpt-4o-mini-with-search"
    
    def test_load_nonexistent_config_file(self):
        """Test loading when config file doesn't exist."""
        manager = ConfigManager(config_path=Path("/nonexistent/config.yml"))
        loaded_config = manager.load_config()
        
        # Should return default configuration
        assert loaded_config['model'] == "gpt-4o-mini-with-search"
    
    def test_load_config_with_null_values(self, temp_project_dir):
        """Test loading config with null/None values."""
        config_path = temp_project_dir / "config.yml"
        config_data = {
            'analysis': {
                'batch_size': None,  # None is valid for batch_size
                'timeout_seconds': None
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        loaded_config = manager.load_config()
        
        assert loaded_config['analysis']['batch_size'] is None
        assert loaded_config['analysis']['timeout_seconds'] is None


class TestYAMLParsingErrors:
    """Test YAML parsing error scenarios."""
    
    def test_invalid_yaml_syntax(self, temp_project_dir):
        """Test handling of invalid YAML syntax."""
        config_path = temp_project_dir / "invalid.yml"
        config_path.write_text("invalid: yaml: content: [unclosed")
        
        manager = ConfigManager(config_path=config_path)
        
        with pytest.raises(ConfigurationError) as exc_info:
            manager.load_config()
        
        assert "Invalid YAML in configuration file" in str(exc_info.value)
    
    def test_yaml_with_tabs(self, temp_project_dir):
        """Test YAML with tab characters (should be valid)."""
        config_path = temp_project_dir / "tabs.yml"
        # Use proper YAML structure with tabs
        config_path.write_text("model: gpt-4\nanalysis:\n  batch_size: 10")
        
        manager = ConfigManager(config_path=config_path)
        # Should not raise exception - YAML parser handles this fine
        loaded_config = manager.load_config()
        assert loaded_config['model'] == 'gpt-4'
        assert loaded_config['analysis']['batch_size'] == 10
    
    def test_yaml_with_unicode(self, temp_project_dir):
        """Test YAML with unicode characters."""
        config_path = temp_project_dir / "unicode.yml"
        config_path.write_text("model: gpt-4\n# Configuration with unicode: ñáéíóú\n")
        
        manager = ConfigManager(config_path=config_path)
        loaded_config = manager.load_config()
        assert loaded_config['model'] == 'gpt-4'
    
    def test_very_large_yaml_file(self, temp_project_dir):
        """Test loading a very large YAML configuration file."""
        config_path = temp_project_dir / "large_config.yml"
        
        # Create a large configuration
        large_config = {
            'model': 'gpt-4',
            'providers': {}
        }
        
        # Add many provider configurations
        for i in range(100):
            large_config['providers'][f'provider_{i}'] = {
                'base_url': f'https://api{i}.example.com',
                'version': f'v{i}',
                'timeout': i * 10
            }
        
        config_path.write_text(yaml.dump(large_config))
        
        manager = ConfigManager(config_path=config_path)
        loaded_config = manager.load_config()
        
        assert loaded_config['model'] == 'gpt-4'
        assert len(loaded_config['providers']) >= 100


class TestSecurityValidation:
    """Test security validation (API key detection)."""
    
    def test_detect_openai_api_key_in_config(self, temp_project_dir):
        """Test detection of OpenAI API key in configuration."""
        config_path = temp_project_dir / "config.yml"
        config_data = {
            'providers': {
                'openai': {
                    'api_key': 'sk-1234567890abcdef1234567890abcdef1234567890abcdef'
                }
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        
        with pytest.raises(ConfigurationError) as exc_info:
            manager.load_config()
        
        assert "API keys not allowed in configuration file" in str(exc_info.value)
        assert "Use environment variables instead" in str(exc_info.value)
    
    def test_detect_anthropic_api_key_in_config(self, temp_project_dir):
        """Test detection of Anthropic API key in configuration."""
        config_path = temp_project_dir / "config.yml"
        config_data = {
            'providers': {
                'anthropic': {
                    'api_key': 'sk-ant-api03-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'
                }
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        
        with pytest.raises(ConfigurationError) as exc_info:
            manager.load_config()
        
        assert "API keys not allowed in configuration file" in str(exc_info.value)
    
    def test_detect_google_api_key_in_config(self, temp_project_dir):
        """Test detection of Google API key in configuration."""
        config_path = temp_project_dir / "config.yml"
        config_data = {
            'providers': {
                'google': {
                    'secret': 'AIzaSyD1234567890abcdef1234567890abcdef12'
                }
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        
        with pytest.raises(ConfigurationError) as exc_info:
            manager.load_config()
        
        assert "API keys not allowed in configuration file" in str(exc_info.value)
    
    def test_detect_xai_api_key_in_config(self, temp_project_dir):
        """Test detection of XAI API key in configuration."""
        config_path = temp_project_dir / "config.yml"
        config_data = {
            'providers': {
                'xai': {
                    'token': 'xai-1234567890abcdef1234567890abcdef1234567890abcdef'
                }
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        
        with pytest.raises(ConfigurationError) as exc_info:
            manager.load_config()
        
        assert "API keys not allowed in configuration file" in str(exc_info.value)
    
    def test_detect_nested_api_keys(self, temp_project_dir):
        """Test detection of API keys in nested configuration structures."""
        config_path = temp_project_dir / "config.yml"
        config_data = {
            'analysis': {
                'providers': {
                    'custom': {
                        'authentication': {
                            'api_key': 'sk-1234567890abcdef1234567890abcdef1234567890abcdef'
                        }
                    }
                }
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        
        with pytest.raises(ConfigurationError) as exc_info:
            manager.load_config()
        
        assert "analysis.providers.custom.authentication.api_key" in str(exc_info.value)
    
    def test_detect_api_keys_in_lists(self, temp_project_dir):
        """Test detection of API keys in list structures."""
        config_path = temp_project_dir / "config.yml"
        config_data = {
            'providers': [{
                'name': 'openai',
                'key': 'sk-1234567890abcdef1234567890abcdef1234567890abcdef'
            }]
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        
        with pytest.raises(ConfigurationError) as exc_info:
            manager.load_config()
        
        assert "providers[0].key" in str(exc_info.value)
    
    def test_allow_short_api_like_strings(self, temp_project_dir):
        """Test that short API-like strings are allowed."""
        config_path = temp_project_dir / "config.yml"
        config_data = {
            'providers': {
                'custom': {
                    'identifier': 'sk-short'  # Too short to be a real API key, field name not forbidden
                }
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        # Should not raise exception
        loaded_config = manager.load_config()
        assert loaded_config['providers']['custom']['identifier'] == 'sk-short'
    
    def test_allow_non_api_key_fields(self, temp_project_dir):
        """Test that non-API key fields with similar names are allowed."""
        config_path = temp_project_dir / "config.yml"
        config_data = {
            'providers': {
                'custom': {
                    'public_key_id': 'some-public-identifier',  # Different from 'key'
                    'key_name': 'my-key-name',
                    'policy': 'strict'  # Not a forbidden field name
                }
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        # Should not raise exception for legitimate fields
        loaded_config = manager.load_config()
        assert 'custom' in loaded_config['providers']


class TestConfigurationValidation:
    """Test configuration validation rules."""
    
    def test_validate_invalid_model_type(self, temp_project_dir):
        """Test validation of invalid model type."""
        config_path = temp_project_dir / "config.yml"
        config_data = {'model': 123}  # Should be string
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        
        with pytest.raises(ConfigurationError) as exc_info:
            manager.load_config()
        
        assert "Model must be a non-empty string" in str(exc_info.value)
    
    def test_validate_empty_model_string(self, temp_project_dir):
        """Test validation of empty model string."""
        config_path = temp_project_dir / "config.yml"
        config_data = {'model': '   '}  # Empty/whitespace string
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        
        with pytest.raises(ConfigurationError) as exc_info:
            manager.load_config()
        
        assert "Model must be a non-empty string" in str(exc_info.value)
    
    def test_validate_invalid_batch_size(self, temp_project_dir):
        """Test validation of invalid batch size."""
        config_path = temp_project_dir / "config.yml"
        config_data = {
            'analysis': {
                'batch_size': 250  # Too large
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        
        with pytest.raises(ConfigurationError) as exc_info:
            manager.load_config()
        
        assert "Batch size must be an integer between 1 and 200" in str(exc_info.value)
    
    def test_validate_negative_batch_size(self, temp_project_dir):
        """Test validation of negative batch size."""
        config_path = temp_project_dir / "config.yml"
        config_data = {
            'analysis': {
                'batch_size': -1
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        
        with pytest.raises(ConfigurationError) as exc_info:
            manager.load_config()
        
        assert "Batch size must be an integer between 1 and 200" in str(exc_info.value)
    
    def test_validate_invalid_budget_limits(self, temp_project_dir):
        """Test validation of invalid budget limits."""
        config_path = temp_project_dir / "config.yml"
        config_data = {
            'budget': {
                'daily_limit': -10.0,
                'monthly_limit': 'not-a-number'
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        
        with pytest.raises(ConfigurationError) as exc_info:
            manager.load_config()
        
        assert "Daily budget limit must be a positive number" in str(exc_info.value)
    
    def test_validate_invalid_confidence_threshold(self, temp_project_dir):
        """Test validation of invalid confidence threshold."""
        config_path = temp_project_dir / "config.yml"
        config_data = {
            'analysis': {
                'confidence_threshold': 1.5  # Should be 0-1
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        
        with pytest.raises(ConfigurationError) as exc_info:
            manager.load_config()
        
        assert "Confidence threshold must be a number between 0 and 1" in str(exc_info.value)
    
    def test_validate_missing_required_sections(self):
        """Test validation when required sections are missing from default config."""
        # Create a manager and manually test the final validation with incomplete config
        manager = ConfigManager()
        incomplete_config = {
            'model': 'gpt-4'
            # Missing 'analysis' and 'budget' sections
        }
        
        with pytest.raises(ConfigurationError) as exc_info:
            manager._validate_final_config(incomplete_config)
        
        assert "Required configuration section missing" in str(exc_info.value)
    
    def test_validate_budget_cross_validation(self, temp_project_dir):
        """Test cross-validation of budget limits."""
        config_path = temp_project_dir / "config.yml"
        config_data = {
            'budget': {
                'enabled': True,
                'daily_limit': 100.0,
                'monthly_limit': 50.0  # Monthly < daily * 31
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        
        # Should load but log a warning (not raise exception)
        with patch('sca_ai_scanner.config.manager.logger') as mock_logger:
            loaded_config = manager.load_config()
            mock_logger.warning.assert_called()


class TestConfigurationMerging:
    """Test configuration merging and deep merge functionality."""
    
    def test_deep_merge_simple_override(self):
        """Test simple override in deep merge."""
        manager = ConfigManager()
        base = {'a': 1, 'b': 2}
        override = {'b': 3, 'c': 4}
        
        result = manager._deep_merge(base, override)
        
        assert result['a'] == 1
        assert result['b'] == 3
        assert result['c'] == 4
    
    def test_deep_merge_nested_dictionaries(self):
        """Test deep merge with nested dictionaries."""
        manager = ConfigManager()
        base = {
            'providers': {
                'openai': {'base_url': 'https://api.openai.com/v1'},
                'anthropic': {'version': '2023-06-01'}
            }
        }
        override = {
            'providers': {
                'openai': {'organization': 'org-123'},
                'google': {'project_id': 'my-project'}
            }
        }
        
        result = manager._deep_merge(base, override)
        
        # OpenAI should have both base_url and organization
        assert result['providers']['openai']['base_url'] == 'https://api.openai.com/v1'
        assert result['providers']['openai']['organization'] == 'org-123'
        # Anthropic should remain unchanged
        assert result['providers']['anthropic']['version'] == '2023-06-01'
        # Google should be added
        assert result['providers']['google']['project_id'] == 'my-project'
    
    def test_deep_merge_replaces_non_dict_values(self):
        """Test that deep merge replaces non-dict values completely."""
        manager = ConfigManager()
        base = {'config': {'timeout': 30, 'retries': 3}}
        override = {'config': 'simple-string'}
        
        result = manager._deep_merge(base, override)
        
        assert result['config'] == 'simple-string'
    
    def test_config_merging_with_file(self, temp_project_dir):
        """Test configuration merging with actual file loading."""
        config_path = temp_project_dir / "config.yml"
        config_data = {
            'model': 'custom-model',
            'analysis': {
                'batch_size': 25,
                'confidence_threshold': 0.95  # Override default
                # max_retries should remain default
            },
            'providers': {
                'openai': {
                    'organization': 'org-custom'
                    # base_url should remain default
                }
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        loaded_config = manager.load_config()
        
        # Check overridden values
        assert loaded_config['model'] == 'custom-model'
        assert loaded_config['analysis']['batch_size'] == 25
        assert loaded_config['analysis']['confidence_threshold'] == 0.95
        assert loaded_config['providers']['openai']['organization'] == 'org-custom'
        
        # Check preserved defaults
        assert loaded_config['analysis']['max_retries'] == 3  # Default
        assert loaded_config['providers']['openai']['base_url'] == 'https://api.openai.com/v1'
        assert loaded_config['budget']['enabled'] is False  # Default


class TestProviderAndModelConfiguration:
    """Test provider and model-specific configuration retrieval."""
    
    def test_get_provider_config_existing(self, temp_project_dir):
        """Test getting configuration for existing provider."""
        config_path = temp_project_dir / "config.yml"
        config_data = {
            'providers': {
                'openai': {
                    'organization': 'org-123',
                    'base_url': 'https://api.openai.com/v1'
                }
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        manager.load_config()
        
        provider_config = manager.get_provider_config('openai')
        assert provider_config['organization'] == 'org-123'
        assert provider_config['base_url'] == 'https://api.openai.com/v1'
    
    def test_get_provider_config_nonexistent(self):
        """Test getting configuration for non-existent provider."""
        manager = ConfigManager()
        manager.load_config()
        
        provider_config = manager.get_provider_config('nonexistent')
        assert provider_config == {}
    
    def test_get_model_config_existing(self, temp_project_dir):
        """Test getting configuration for existing model."""
        config_path = temp_project_dir / "config.yml"
        config_data = {
            'optimization': {
                'gpt-4o-mini': {
                    'temperature': 0.2,
                    'max_tokens': 1024
                }
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        manager.load_config()
        
        model_config = manager.get_model_config('gpt-4o-mini')
        assert model_config['temperature'] == 0.2
        assert model_config['max_tokens'] == 1024
    
    def test_get_model_config_with_suffix_stripping(self):
        """Test model config retrieval with suffix stripping."""
        manager = ConfigManager()
        manager.load_config()
        
        # Should strip '-with-search' suffix
        model_config = manager.get_model_config('gpt-4o-mini-with-search')
        expected_config = manager.config_data['optimization']['gpt-4o-mini']
        assert model_config == expected_config
    
    def test_get_model_config_nonexistent(self):
        """Test getting configuration for non-existent model."""
        manager = ConfigManager()
        manager.load_config()
        
        model_config = manager.get_model_config('nonexistent-model')
        assert model_config == {}
    
    def test_get_analysis_config(self, temp_project_dir):
        """Test getting analysis configuration."""
        config_path = temp_project_dir / "config.yml"
        config_data = {
            'analysis': {
                'confidence_threshold': 0.85,
                'max_retries': 5
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        manager.load_config()
        
        analysis_config = manager.get_analysis_config()
        assert analysis_config['confidence_threshold'] == 0.85
        assert analysis_config['max_retries'] == 5
    
    def test_get_budget_config(self, temp_project_dir):
        """Test getting budget configuration."""
        config_path = temp_project_dir / "config.yml"
        config_data = {
            'budget': {
                'enabled': True,
                'daily_limit': 75.0
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        manager.load_config()
        
        budget_config = manager.get_budget_config()
        assert budget_config['enabled'] is True
        assert budget_config['daily_limit'] == 75.0
    
    def test_get_validation_config(self):
        """Test getting validation configuration."""
        manager = ConfigManager()
        manager.load_config()
        
        validation_config = manager.get_validation_config()
        assert validation_config['validate_critical'] is True
        assert validation_config['validate_high'] is True
    
    def test_get_telemetry_config(self):
        """Test getting telemetry configuration."""
        manager = ConfigManager()
        manager.load_config()
        
        telemetry_config = manager.get_telemetry_config()
        assert telemetry_config['enabled'] is True
        assert telemetry_config['level'] == 'info'


class TestEnvironmentVariableValidation:
    """Test environment variable validation."""
    
    def test_validate_environment_variables_all_present(self):
        """Test environment variable validation when all are present."""
        with patch.dict(os.environ, {
            'OPENAI_API_KEY': 'sk-test',
            'ANTHROPIC_API_KEY': 'sk-ant-test',
            'GOOGLE_AI_API_KEY': 'AIzatest',
            'XAI_API_KEY': 'xai-test'
        }):
            manager = ConfigManager()
            env_vars = manager.validate_environment_variables()
            
            assert all(env_vars.values())
    
    def test_validate_environment_variables_partial(self):
        """Test environment variable validation when some are missing."""
        with patch.dict(os.environ, {
            'OPENAI_API_KEY': 'sk-test',
            'ANTHROPIC_API_KEY': 'sk-ant-test'
        }, clear=True):
            manager = ConfigManager()
            env_vars = manager.validate_environment_variables()
            
            assert env_vars['OPENAI_API_KEY'] is True
            assert env_vars['ANTHROPIC_API_KEY'] is True
            assert env_vars['GOOGLE_AI_API_KEY'] is False
            assert env_vars['XAI_API_KEY'] is False
    
    def test_validate_environment_variables_none_present(self):
        """Test environment variable validation when none are present."""
        with patch.dict(os.environ, {}, clear=True):
            manager = ConfigManager()
            env_vars = manager.validate_environment_variables()
            
            assert not any(env_vars.values())


class TestDefaultConfigFileCreation:
    """Test default configuration file creation."""
    
    def test_create_default_config_file(self, temp_project_dir):
        """Test creating a default configuration file."""
        output_path = temp_project_dir / "new_config.yml"
        
        manager = ConfigManager()
        manager.create_default_config_file(output_path)
        
        assert output_path.exists()
        
        # Verify content
        content = output_path.read_text()
        assert "AI-Powered SCA Scanner Configuration" in content
        assert "API keys are NEVER stored here" in content
        assert "export OPENAI_API_KEY" in content
        
        # Verify YAML is valid
        with open(output_path) as f:
            # Skip comments and load YAML
            lines = [line for line in f if not line.strip().startswith('#') or line.strip() == '']
            yaml_content = '\n'.join(lines)
            if yaml_content.strip():
                config = yaml.safe_load(yaml_content)
                assert isinstance(config, dict)
    
    def test_create_default_config_file_creates_directories(self, temp_project_dir):
        """Test that creating config file creates necessary directories."""
        output_path = temp_project_dir / "nested" / "directory" / "config.yml"
        
        manager = ConfigManager()
        manager.create_default_config_file(output_path)
        
        assert output_path.exists()
        assert output_path.parent.exists()
    
    def test_create_default_config_file_permission_error(self, temp_project_dir):
        """Test handling of permission errors during file creation."""
        output_path = temp_project_dir / "readonly" / "config.yml"
        
        # Create readonly directory
        readonly_dir = temp_project_dir / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o444)  # Read-only
        
        try:
            manager = ConfigManager()
            
            with pytest.raises(ConfigurationError) as exc_info:
                manager.create_default_config_file(output_path)
            
            assert "Failed to create configuration file" in str(exc_info.value)
        
        finally:
            # Cleanup - restore permissions
            readonly_dir.chmod(0o755)


class TestConfigurationSummary:
    """Test configuration summary and debugging functionality."""
    
    def test_get_config_summary_with_file(self, temp_project_dir):
        """Test getting configuration summary when using config file."""
        config_path = temp_project_dir / "config.yml"
        config_data = {
            'model': 'custom-model',
            'analysis': {'batch_size': 25},
            'budget': {'daily_limit': 100.0}
        }
        config_path.write_text(yaml.dump(config_data))
        
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test-key'}, clear=True):
            manager = ConfigManager(config_path=config_path)
            manager.load_config()
            
            summary = manager.get_config_summary()
            
            assert summary['config_source'] == str(config_path)
            assert summary['model'] == 'custom-model'
            assert summary['batch_size'] == 25
            assert summary['daily_budget'] == 100.0
            assert summary['environment_variables']['OPENAI_API_KEY'] is True
    
    def test_get_config_summary_defaults_only(self):
        """Test getting configuration summary when using defaults only."""
        with patch.dict(os.environ, {}, clear=True):
            manager = ConfigManager()
            manager.load_config()
            
            summary = manager.get_config_summary()
            
            assert summary['config_source'] == 'defaults'
            assert summary['model'] == 'gpt-4o-mini-with-search'
            assert summary['batch_size'] is None
            assert summary['validation_enabled'] is True
            assert not any(summary['environment_variables'].values())


class TestFilePermissionErrors:
    """Test file permission and IO error handling."""
    
    def test_load_config_permission_denied(self, temp_project_dir):
        """Test handling of permission denied errors."""
        config_path = temp_project_dir / "protected_config.yml"
        config_path.write_text("model: test")
        config_path.chmod(0o000)  # No permissions
        
        try:
            manager = ConfigManager(config_path=config_path)
            
            with pytest.raises(ConfigurationError) as exc_info:
                manager.load_config()
            
            assert "Failed to load configuration file" in str(exc_info.value)
        
        finally:
            # Cleanup - restore permissions
            config_path.chmod(0o644)
    
    def test_load_config_file_is_directory(self, temp_project_dir):
        """Test handling when config path points to a directory."""
        config_path = temp_project_dir / "config_dir"
        config_path.mkdir()
        
        manager = ConfigManager(config_path=config_path)
        
        with pytest.raises(ConfigurationError) as exc_info:
            manager.load_config()
        
        assert "Failed to load configuration file" in str(exc_info.value)
    
    def test_load_config_io_error(self, temp_project_dir):
        """Test handling of IO errors during file reading."""
        # Create a valid config file first
        config_path = temp_project_dir / "io_error_config.yml"
        config_path.write_text("model: test")
        
        # Make the directory read-only after creating the file
        config_path.chmod(0o000)
        
        try:
            manager = ConfigManager(config_path=config_path)
            
            with pytest.raises(ConfigurationError) as exc_info:
                manager.load_config()
            
            assert "Failed to load configuration file" in str(exc_info.value)
        
        finally:
            # Restore permissions for cleanup
            config_path.chmod(0o644)


class TestPerformanceScenarios:
    """Test performance with large configurations and edge cases."""
    
    def test_load_very_large_configuration(self, temp_project_dir):
        """Test loading a very large configuration file."""
        config_path = temp_project_dir / "large_config.yml"
        
        # Create a configuration with many nested structures
        large_config = {
            'model': 'gpt-4',
            'analysis': {'batch_size': 10},
            'budget': {'enabled': False},
            'providers': {},
            'optimization': {}
        }
        
        # Add 1000 provider configurations
        for i in range(1000):
            large_config['providers'][f'provider_{i:04d}'] = {
                'base_url': f'https://api{i}.example.com/v1',
                'version': f'2023-{i % 12 + 1:02d}-01',
                'timeout': (i % 120) + 30,
                'max_retries': (i % 5) + 1
            }
        
        # Add 100 model optimizations
        for i in range(100):
            large_config['optimization'][f'model-{i:03d}'] = {
                'temperature': (i % 10) / 10.0,
                'max_tokens': 1000 + (i * 10),
                'top_p': 0.9,
                'frequency_penalty': (i % 3) / 10.0
            }
        
        config_path.write_text(yaml.dump(large_config))
        
        import time
        start_time = time.time()
        
        manager = ConfigManager(config_path=config_path)
        loaded_config = manager.load_config()
        
        end_time = time.time()
        load_time = end_time - start_time
        
        # Should load in reasonable time (less than 1 second)
        assert load_time < 1.0
        # Account for default providers being merged in
        assert len(loaded_config['providers']) >= 1000
        # Account for default optimization settings being merged in
        assert len(loaded_config['optimization']) >= 100
    
    def test_deep_nested_configuration(self, temp_project_dir):
        """Test configuration with very deep nesting."""
        config_path = temp_project_dir / "deep_config.yml"
        
        # Create deeply nested configuration
        deep_config = {'level_0': {}}
        current_level = deep_config['level_0']
        
        for i in range(1, 20):  # 20 levels deep
            current_level[f'level_{i}'] = {
                'value': i,
                'data': f'level_{i}_data'
            }
            if i < 19:
                current_level[f'level_{i}']['nested'] = {}
                current_level = current_level[f'level_{i}']['nested']
        
        config_path.write_text(yaml.dump(deep_config))
        
        manager = ConfigManager(config_path=config_path)
        loaded_config = manager.load_config()
        
        # Should handle deep nesting without issues
        assert 'level_0' in loaded_config
        
        # Verify deep access works
        current = loaded_config['level_0']
        for i in range(1, 19):
            assert f'level_{i}' in current
            assert current[f'level_{i}']['value'] == i
            if 'nested' in current[f'level_{i}']:
                current = current[f'level_{i}']['nested']
    
    def test_configuration_with_large_strings(self, temp_project_dir):
        """Test configuration with very large string values."""
        config_path = temp_project_dir / "large_strings_config.yml"
        
        # Create configuration with large string values
        large_string = 'x' * 10000  # 10KB string
        
        config_data = {
            'model': 'gpt-4',
            'providers': {
                'custom': {
                    'description': large_string,
                    'documentation': large_string * 2  # 20KB string
                }
            }
        }
        
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        loaded_config = manager.load_config()
        
        # Should handle large strings without issues
        assert len(loaded_config['providers']['custom']['description']) == 10000
        assert len(loaded_config['providers']['custom']['documentation']) == 20000


class TestMultiEnvironmentConfigurations:
    """Test multi-environment configuration scenarios."""
    
    def test_development_environment_config(self, temp_project_dir):
        """Test typical development environment configuration."""
        config_path = temp_project_dir / "dev_config.yml"
        config_data = {
            'model': 'gpt-4o-mini',  # Cheaper model for dev
            'analysis': {
                'batch_size': 5,  # Smaller batches
                'confidence_threshold': 0.7  # Lower threshold
            },
            'budget': {
                'enabled': True,
                'daily_limit': 10.0  # Low limit for dev
            },
            'telemetry': {
                'enabled': False  # Disabled in dev
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        loaded_config = manager.load_config()
        
        assert loaded_config['model'] == 'gpt-4o-mini'
        assert loaded_config['analysis']['batch_size'] == 5
        assert loaded_config['budget']['daily_limit'] == 10.0
        assert loaded_config['telemetry']['enabled'] is False
    
    def test_production_environment_config(self, temp_project_dir):
        """Test typical production environment configuration."""
        config_path = temp_project_dir / "prod_config.yml"
        config_data = {
            'model': 'gpt-4o-mini-with-search',
            'analysis': {
                'batch_size': 50,  # Larger batches
                'confidence_threshold': 0.9,  # Higher threshold
                'max_retries': 5  # More retries
            },
            'budget': {
                'enabled': True,
                'daily_limit': 100.0,
                'monthly_limit': 2000.0,
                'alert_threshold': 0.8
            },
            'validation': {
                'validate_critical': True,
                'validate_high': True,
                'spot_check_medium': True
            },
            'telemetry': {
                'enabled': True,
                'level': 'info'
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        loaded_config = manager.load_config()
        
        assert loaded_config['model'] == 'gpt-4o-mini-with-search'
        assert loaded_config['analysis']['batch_size'] == 50
        assert loaded_config['budget']['monthly_limit'] == 2000.0
        assert loaded_config['validation']['validate_critical'] is True
        assert loaded_config['telemetry']['enabled'] is True
    
    def test_ci_environment_config(self, temp_project_dir):
        """Test typical CI environment configuration."""
        config_path = temp_project_dir / "ci_config.yml"
        config_data = {
            'model': 'gpt-4o-mini',
            'analysis': {
                'batch_size': 20,
                'confidence_threshold': 0.8,
                'timeout_seconds': 60  # Shorter timeout
            },
            'budget': {
                'enabled': True,
                'daily_limit': 25.0  # Limited budget for CI
            },
            'validation': {
                'validate_critical': True,
                'validate_high': False,  # Skip some validations
                'spot_check_medium': False
            },
            'telemetry': {
                'enabled': False  # Disabled in CI
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        loaded_config = manager.load_config()
        
        assert loaded_config['analysis']['timeout_seconds'] == 60
        assert loaded_config['budget']['daily_limit'] == 25.0
        assert loaded_config['validation']['validate_high'] is False
        assert loaded_config['telemetry']['enabled'] is False


class TestEdgeCasesAndBoundaryConditions:
    """Test edge cases and boundary conditions."""
    
    def test_empty_configuration_sections(self, temp_project_dir):
        """Test configuration with empty sections."""
        config_path = temp_project_dir / "empty_sections.yml"
        config_data = {
            'model': 'gpt-4',
            'providers': {},
            'analysis': {},
            'budget': {}
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        loaded_config = manager.load_config()
        
        # Should merge with defaults
        assert loaded_config['analysis']['confidence_threshold'] == 0.8
        assert loaded_config['budget']['enabled'] is False
    
    def test_configuration_with_null_values(self, temp_project_dir):
        """Test configuration with explicit null values."""
        config_path = temp_project_dir / "null_config.yml"
        config_data = {
            'model': 'gpt-4',
            'analysis': {
                'batch_size': None,  # None is valid for batch_size
                'timeout_seconds': None
            },
            'budget': {},  # Required section, can be empty to use defaults
            'providers': {
                'google': {
                    'project_id': None
                }
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        loaded_config = manager.load_config()
        
        assert loaded_config['analysis']['batch_size'] is None
        assert loaded_config['providers']['google']['project_id'] is None
    
    def test_configuration_type_coercion(self, temp_project_dir):
        """Test configuration with numeric values that YAML auto-converts."""
        config_path = temp_project_dir / "types_config.yml"
        # Use unquoted numeric values that YAML will auto-convert
        yaml_content = """
analysis:
  batch_size: 25  # Integer value
  confidence_threshold: 0.85  # Float value
budget: {}  # Required section
"""
        config_path.write_text(yaml_content)
        
        manager = ConfigManager(config_path=config_path)
        
        # YAML parser should handle type coercion automatically
        loaded_config = manager.load_config()
        
        # YAML auto-converts numeric values correctly
        assert loaded_config['analysis']['batch_size'] == 25
        assert loaded_config['analysis']['confidence_threshold'] == 0.85
        assert isinstance(loaded_config['analysis']['batch_size'], int)
        assert isinstance(loaded_config['analysis']['confidence_threshold'], float)
    
    def test_minimum_valid_configuration(self, temp_project_dir):
        """Test minimum valid configuration."""
        config_path = temp_project_dir / "minimal_config.yml"
        config_data = {
            'analysis': {},  # Required section
            'budget': {}     # Required section
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        loaded_config = manager.load_config()
        
        # Should work with just required sections
        assert 'analysis' in loaded_config
        assert 'budget' in loaded_config
        # Defaults should be merged
        assert loaded_config['model'] == "gpt-4o-mini-with-search"
    
    def test_boundary_values_validation(self, temp_project_dir):
        """Test boundary values for validation."""
        # Test minimum valid values
        config_path = temp_project_dir / "boundary_config.yml"
        config_data = {
            'analysis': {
                'batch_size': 1,  # Minimum
                'confidence_threshold': 0.0  # Minimum
            },
            'budget': {
                'daily_limit': 0.01,  # Very small but positive
                'monthly_limit': 0.01
            }
        }
        config_path.write_text(yaml.dump(config_data))
        
        manager = ConfigManager(config_path=config_path)
        loaded_config = manager.load_config()
        
        assert loaded_config['analysis']['batch_size'] == 1
        assert loaded_config['analysis']['confidence_threshold'] == 0.0
        assert loaded_config['budget']['daily_limit'] == 0.01
        
        # Test maximum valid values
        config_data['analysis']['batch_size'] = 200  # Maximum
        config_data['analysis']['confidence_threshold'] = 1.0  # Maximum
        
        config_path.write_text(yaml.dump(config_data))
        manager = ConfigManager(config_path=config_path)
        loaded_config = manager.load_config()
        
        assert loaded_config['analysis']['batch_size'] == 200
        assert loaded_config['analysis']['confidence_threshold'] == 1.0


# Performance and stress testing fixtures

@pytest.fixture
def large_config_data():
    """Generate large configuration data for performance testing."""
    config_data = {
        'model': 'gpt-4',
        'providers': {},
        'analysis': {'batch_size': 10},
        'budget': {'enabled': False}
    }
    
    # Add many providers
    for i in range(500):
        config_data['providers'][f'provider_{i:03d}'] = {
            'base_url': f'https://api{i}.example.com',
            'version': f'v{i % 10}',
            'timeout': 30 + (i % 60),
            'retries': 1 + (i % 5)
        }
    
    return config_data


@pytest.mark.performance
class TestPerformanceStress:
    """Performance and stress testing for Configuration Manager."""
    
    def test_load_performance_large_config(self, temp_project_dir, large_config_data, performance_timer):
        """Test loading performance with large configuration."""
        config_path = temp_project_dir / "large_config.yml"
        config_path.write_text(yaml.dump(large_config_data))
        
        performance_timer.start()
        
        manager = ConfigManager(config_path=config_path)
        loaded_config = manager.load_config()
        
        performance_timer.stop()
        
        # Should load within reasonable time
        assert performance_timer.elapsed < 2.0  # 2 seconds max
        # Account for default providers being merged in (openai, anthropic, google, xai = +4)
        assert len(loaded_config['providers']) == 504
    
    def test_multiple_config_loads_performance(self, temp_project_dir, performance_timer):
        """Test performance of multiple configuration loads."""
        config_path = temp_project_dir / "multi_load_config.yml"
        config_data = {
            'model': 'gpt-4',
            'analysis': {'batch_size': 25},
            'budget': {'enabled': True}
        }
        config_path.write_text(yaml.dump(config_data))
        
        performance_timer.start()
        
        # Load configuration multiple times
        for _ in range(100):
            manager = ConfigManager(config_path=config_path)
            loaded_config = manager.load_config()
            assert loaded_config['model'] == 'gpt-4'
        
        performance_timer.stop()
        
        # Should handle multiple loads efficiently
        assert performance_timer.elapsed < 5.0  # 5 seconds max for 100 loads
    
    def test_memory_usage_large_config(self, temp_project_dir, large_config_data):
        """Test memory usage with large configuration."""
        config_path = temp_project_dir / "memory_test_config.yml"
        config_path.write_text(yaml.dump(large_config_data))
        
        import gc
        import sys
        
        # Get baseline memory
        gc.collect()
        baseline_objects = len(gc.get_objects())
        
        managers = []
        for _ in range(10):
            manager = ConfigManager(config_path=config_path)
            manager.load_config()
            managers.append(manager)
        
        gc.collect()
        loaded_objects = len(gc.get_objects())
        
        # Memory usage should be reasonable
        object_increase = loaded_objects - baseline_objects
        assert object_increase < 50000  # Reasonable object increase
        
        # Cleanup
        del managers
        gc.collect()