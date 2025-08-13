"""
Configuration manager for AI-powered SCA scanner.
Handles YAML configuration with secure API key management.
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional
import logging

import yaml

from ..exceptions import ConfigurationError

logger = logging.getLogger(__name__)


class ConfigManager:
    """
    Configuration manager with secure API key handling.
    Loads configuration from YAML files while enforcing environment-only API keys.
    """
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize configuration manager."""
        self.config_path = config_path or self._find_default_config()
        self.config_data: Dict[str, Any] = {}
        
        # Default configuration
        self.default_config = {
            "model": "gpt-4o-mini-with-search",
            "providers": {
                "openai": {
                    "base_url": "https://api.openai.com/v1"
                },
                "anthropic": {
                    "version": "2023-06-01"
                },
                "google": {
                    "project_id": None
                },
                "xai": {
                    "base_url": "https://api.x.ai/v1"
                }
            },
            "analysis": {
                "context_optimization": True,
                "batch_size": None,
                "confidence_threshold": 0.8,
                "max_retries": 3,
                "timeout_seconds": 120
            },
            "budget": {
                "enabled": False,
                "daily_limit": 50.0,
                "monthly_limit": 1000.0,
                "alert_threshold": 0.8
            },
            "optimization": {
                "gpt-4o-mini": {
                    "temperature": 0.1,
                    "max_tokens": 2048
                },
                "claude-3.5-haiku": {
                    "temperature": 0.0,
                    "max_tokens": 4096
                },
                "gemini-2.0-flash": {
                    "temperature": 0.1,
                    "top_p": 0.9
                }
            },
            "validation": {
                "validate_critical": True,
                "validate_high": True,
                "spot_check_medium": True,
                "spot_check_ratio": 0.2
            },
            "telemetry": {
                "enabled": True,
                "level": "info",
                "output_file": "./sca_telemetry.jsonl"
            }
        }
    
    def _find_default_config(self) -> Optional[Path]:
        """Find default configuration file."""
        possible_paths = [
            Path.home() / ".sca_ai_config.yml",
            Path.home() / ".sca_ai_config.yaml",
            Path.cwd() / "sca_ai_config.yml",
            Path.cwd() / "sca_ai_config.yaml"
        ]
        
        for path in possible_paths:
            if path.exists():
                logger.info(f"Found configuration file: {path}")
                return path
        
        logger.info("No configuration file found, using defaults")
        return None
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file or use defaults."""
        
        # Start with default configuration
        config = self.default_config.copy()
        
        # Load from file if available
        if self.config_path and self.config_path.exists():
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    file_config = yaml.safe_load(f)
                
                if file_config:
                    # Validate configuration structure
                    self._validate_config(file_config)
                    
                    # Merge with defaults (deep merge)
                    config = self._deep_merge(config, file_config)
                    
                    logger.info(f"Loaded configuration from {self.config_path}")
                else:
                    logger.warning(f"Configuration file {self.config_path} is empty")
                    
            except yaml.YAMLError as e:
                raise ConfigurationError(f"Invalid YAML in configuration file: {e}")
            except Exception as e:
                raise ConfigurationError(f"Failed to load configuration file: {e}")
        
        # Validate final configuration
        self._validate_final_config(config)
        
        self.config_data = config
        return config
    
    def _validate_config(self, config: Dict[str, Any]) -> None:
        """Validate configuration structure and security requirements."""
        
        # Security validation: No API keys in configuration
        self._check_for_api_keys(config)
        
        # Validate model specification
        if 'model' in config:
            if not isinstance(config['model'], str) or not config['model'].strip():
                raise ConfigurationError("Model must be a non-empty string")
        
        # Validate batch size
        if 'analysis' in config and 'batch_size' in config['analysis']:
            batch_size = config['analysis']['batch_size']
            if batch_size is not None and (not isinstance(batch_size, int) or batch_size < 1 or batch_size > 200):
                raise ConfigurationError("Batch size must be an integer between 1 and 200")
        
        # Validate budget limits
        if 'budget' in config:
            budget = config['budget']
            if 'daily_limit' in budget:
                if not isinstance(budget['daily_limit'], (int, float)) or budget['daily_limit'] < 0:
                    raise ConfigurationError("Daily budget limit must be a positive number")
            
            if 'monthly_limit' in budget:
                if not isinstance(budget['monthly_limit'], (int, float)) or budget['monthly_limit'] < 0:
                    raise ConfigurationError("Monthly budget limit must be a positive number")
        
        # Validate confidence threshold
        if 'analysis' in config and 'confidence_threshold' in config['analysis']:
            threshold = config['analysis']['confidence_threshold']
            if not isinstance(threshold, (int, float)) or threshold < 0 or threshold > 1:
                raise ConfigurationError("Confidence threshold must be a number between 0 and 1")
    
    def _check_for_api_keys(self, config: Dict[str, Any], path: str = "") -> None:
        """Recursively check for API keys in configuration (security requirement)."""
        
        forbidden_keys = {
            'api_key', 'apikey', 'key', 'token', 'secret', 'password',
            'openai_api_key', 'anthropic_api_key', 'google_ai_api_key', 'xai_api_key'
        }
        
        if isinstance(config, dict):
            for key, value in config.items():
                current_path = f"{path}.{key}" if path else key
                
                # Check key names
                if key.lower() in forbidden_keys:
                    raise ConfigurationError(
                        f"API keys not allowed in configuration file at {current_path}. "
                        f"Use environment variables instead."
                    )
                
                # Check string values that look like API keys
                if isinstance(value, str):
                    if (value.startswith(('sk-', 'sk-ant-', 'AIza', 'xai-')) and len(value) > 20):
                        raise ConfigurationError(
                            f"Suspected API key found in configuration at {current_path}. "
                            f"Use environment variables instead."
                        )
                
                # Recursively check nested structures
                self._check_for_api_keys(value, current_path)
        
        elif isinstance(config, list):
            for i, item in enumerate(config):
                self._check_for_api_keys(item, f"{path}[{i}]")
    
    def _validate_final_config(self, config: Dict[str, Any]) -> None:
        """Validate final merged configuration."""
        
        # Ensure required sections exist
        required_sections = ['analysis', 'budget']
        for section in required_sections:
            if section not in config:
                raise ConfigurationError(f"Required configuration section missing: {section}")
        
        # Cross-validation (only if budget enabled)
        budget_config = config.get('budget', {})
        if budget_config.get('enabled', False):
            daily_limit = budget_config.get('daily_limit', 50.0)
            monthly_limit = budget_config.get('monthly_limit', 1000.0)
            
            if daily_limit * 31 > monthly_limit:
                logger.warning(
                    f"Daily limit ({daily_limit}) * 31 exceeds monthly limit ({monthly_limit})"
                )
    
    def _deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries."""
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def get_provider_config(self, provider: str) -> Dict[str, Any]:
        """Get configuration for specific AI provider."""
        return self.config_data.get('providers', {}).get(provider, {})
    
    def get_model_config(self, model: str) -> Dict[str, Any]:
        """Get configuration for specific AI model."""
        # Extract base model name for configuration lookup
        base_model = model.replace('-with-search', '').replace('-tools', '').replace('-web', '')
        
        return self.config_data.get('optimization', {}).get(base_model, {})
    
    def get_analysis_config(self) -> Dict[str, Any]:
        """Get analysis configuration."""
        return self.config_data.get('analysis', {})
    
    def get_budget_config(self) -> Dict[str, Any]:
        """Get budget configuration."""
        return self.config_data.get('budget', {})
    
    def get_validation_config(self) -> Dict[str, Any]:
        """Get validation configuration."""
        return self.config_data.get('validation', {})
    
    def get_telemetry_config(self) -> Dict[str, Any]:
        """Get telemetry configuration."""
        return self.config_data.get('telemetry', {})
    
    def create_default_config_file(self, output_path: Path) -> None:
        """Create a default configuration file for user customization."""
        
        config_template = {
            "# AI-Powered SCA Scanner Configuration": None,
            "# API keys are NEVER stored here - use environment variables only": None,
            "": None,
            "# Model selection (single model, no fallbacks)": None,
            "model": "gpt-4o-mini-with-search",
            "": None,
            "# Provider-specific settings": None,
            "providers": {
                "openai": {
                    "organization": "org-xxxxxxxxxxxxx",  # Optional
                    "base_url": "https://api.openai.com/v1"
                },
                "anthropic": {
                    "version": "2023-06-01"
                },
                "google": {
                    "project_id": "your-project-id"  # Google Cloud project
                },
                "xai": {
                    "base_url": "https://api.x.ai/v1"
                }
            },
            "# Analysis settings": None,
            "analysis": {
                "context_optimization": True,
                "batch_size": None,
                "confidence_threshold": 0.8,
                "max_retries": 3,
                "timeout_seconds": 120
            },
            "# Cost management (optional - disabled by default)": None,
            "budget": {
                "enabled": False,
                "daily_limit": 50.0,
                "monthly_limit": 1000.0,
                "alert_threshold": 0.8
            },
            "# Model-specific optimization": None,
            "optimization": {
                "gpt-4o-mini": {
                    "temperature": 0.1,
                    "max_tokens": 2048
                },
                "claude-3.5-haiku": {
                    "temperature": 0.0,
                    "max_tokens": 4096
                },
                "gemini-2.0-flash": {
                    "temperature": 0.1,
                    "top_p": 0.9
                }
            }
        }
        
        # Custom YAML dumper that handles comments
        def custom_representer(dumper, data):
            if data is None:
                return dumper.represent_scalar('tag:yaml.org,2002:null', '')
            return dumper.represent_data(data)
        
        yaml.add_representer(type(None), custom_representer)
        
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                # Write header
                f.write("# AI-Powered SCA Scanner Configuration\n")
                f.write("# API keys are NEVER stored here - use environment variables only\n")
                f.write("#\n")
                f.write("# Required environment variables:\n")
                f.write("# export OPENAI_API_KEY=\"sk-...\"\n")
                f.write("# export ANTHROPIC_API_KEY=\"sk-ant-...\"\n")
                f.write("# export GOOGLE_AI_API_KEY=\"AIza...\"\n")
                f.write("# export XAI_API_KEY=\"xai-...\"\n\n")
                
                # Write configuration (excluding comment keys)
                clean_config = {
                    k: v for k, v in config_template.items() 
                    if not k.startswith('#') and k != ''
                }
                
                yaml.dump(
                    clean_config,
                    f,
                    default_flow_style=False,
                    sort_keys=False,
                    indent=2
                )
            
            logger.info(f"Created default configuration file: {output_path}")
            
        except Exception as e:
            raise ConfigurationError(f"Failed to create configuration file: {e}")
    
    def validate_environment_variables(self) -> Dict[str, bool]:
        """Validate that required environment variables are set."""
        
        env_vars = {
            'OPENAI_API_KEY': os.getenv('OPENAI_API_KEY') is not None,
            'ANTHROPIC_API_KEY': os.getenv('ANTHROPIC_API_KEY') is not None,
            'GOOGLE_AI_API_KEY': os.getenv('GOOGLE_AI_API_KEY') is not None,
            'XAI_API_KEY': os.getenv('XAI_API_KEY') is not None
        }
        
        return env_vars
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Get summary of current configuration for debugging."""
        
        return {
            "config_source": str(self.config_path) if self.config_path else "defaults",
            "model": self.config_data.get('model'),
            "batch_size": self.config_data.get('analysis', {}).get('batch_size'),
            "daily_budget": self.config_data.get('budget', {}).get('daily_limit'),
            "validation_enabled": self.config_data.get('validation', {}).get('validate_critical'),
            "telemetry_enabled": self.config_data.get('telemetry', {}).get('enabled'),
            "environment_variables": self.validate_environment_variables()
        }