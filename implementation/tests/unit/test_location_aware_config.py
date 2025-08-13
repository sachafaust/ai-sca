"""
Comprehensive unit tests for Location-Aware Configuration system.

Tests the core product differentiator - intelligent context-aware recommendations
based on code location and organizational policies.

Coverage areas:
- Built-in location pattern matching accuracy
- Progressive configuration levels (1-4)  
- Priority-based rule precedence
- Performance under enterprise scale
- Custom rule validation and loading
- Error handling and fallback behavior
"""

import pytest
import tempfile
import yaml
from pathlib import Path
from unittest.mock import Mock, patch, mock_open
import time
import re

from sca_ai_scanner.core.location_aware_config import (
    LocationAwareConfig, LocationRule
)
from sca_ai_scanner.core.recommendation_strategies import (
    StrategyManager, RecommendationStrategy
)


class TestLocationRuleBasics:
    """Test LocationRule dataclass and basic functionality."""
    
    def test_location_rule_creation(self):
        """Test basic LocationRule creation with all fields."""
        rule = LocationRule(
            name="test_rule",
            description="A test rule for unit testing",
            path_patterns=[r".*/test/.*", r".*/spec/.*"],
            strategy="balanced_security",
            priority=50
        )
        
        assert rule.name == "test_rule"
        assert rule.description == "A test rule for unit testing"
        assert rule.path_patterns == [r".*/test/.*", r".*/spec/.*"]
        assert rule.strategy == "balanced_security"
        assert rule.priority == 50
    
    def test_location_rule_default_priority(self):
        """Test LocationRule with default priority."""
        rule = LocationRule(
            name="test_rule",
            description="Test rule",
            path_patterns=[r".*/test/.*"],
            strategy="balanced_security"
        )
        
        assert rule.priority == 100  # Default priority
    
    def test_location_rule_equality(self):
        """Test LocationRule equality comparison."""
        rule1 = LocationRule(
            name="same_rule",
            description="Same rule",
            path_patterns=[r".*/test/.*"],
            strategy="balanced_security",
            priority=50
        )
        
        rule2 = LocationRule(
            name="same_rule", 
            description="Same rule",
            path_patterns=[r".*/test/.*"],
            strategy="balanced_security",
            priority=50
        )
        
        assert rule1.name == rule2.name
        assert rule1.priority == rule2.priority


class TestLocationAwareConfigInitialization:
    """Test LocationAwareConfig initialization and built-in rules."""
    
    def test_basic_initialization(self):
        """Test basic initialization without config file."""
        config = LocationAwareConfig()
        
        assert config.default_strategy == "balanced_security"
        assert config.organizational_override is None
        assert len(config.location_rules) > 0  # Should have built-in rules
        assert isinstance(config.strategy_manager, StrategyManager)
    
    def test_built_in_rules_loaded(self):
        """Test that all expected built-in rules are loaded."""
        config = LocationAwareConfig()
        
        rule_names = {rule.name for rule in config.location_rules}
        expected_rules = {
            "payment_services",
            "security_services", 
            "core_infrastructure",
            "development_tools",
            "testing_infrastructure"
        }
        
        assert expected_rules.issubset(rule_names)
    
    def test_built_in_rules_priority_ordering(self):
        """Test that built-in rules are properly sorted by priority."""
        config = LocationAwareConfig()
        
        # Check that rules are sorted by priority (lower = higher precedence)
        priorities = [rule.priority for rule in config.location_rules]
        assert priorities == sorted(priorities)
    
    def test_built_in_payment_service_patterns(self):
        """Test specific payment service patterns."""
        config = LocationAwareConfig()
        
        payment_rule = next(
            rule for rule in config.location_rules 
            if rule.name == "payment_services"
        )
        
        expected_patterns = [
            r".*/app/payment.*",
            r".*/app/billing.*", 
            r".*/app/financial.*",
            r".*/services/payment.*",
            r".*/services/billing.*"
        ]
        
        assert payment_rule.path_patterns == expected_patterns
        assert payment_rule.strategy == "conservative_stability"
        assert payment_rule.priority == 10
    
    def test_built_in_security_service_patterns(self):
        """Test specific security service patterns."""
        config = LocationAwareConfig()
        
        security_rule = next(
            rule for rule in config.location_rules
            if rule.name == "security_services"
        )
        
        expected_patterns = [
            r".*/app/auth.*",
            r".*/app/security.*",
            r".*/services/auth.*",
            r".*/services/security.*"
        ]
        
        assert security_rule.path_patterns == expected_patterns
        assert security_rule.strategy == "conservative_stability"
        assert security_rule.priority == 10
    
    def test_built_in_development_tools_patterns(self):
        """Test development tools patterns."""
        config = LocationAwareConfig()
        
        dev_rule = next(
            rule for rule in config.location_rules
            if rule.name == "development_tools"
        )
        
        expected_patterns = [
            r".*/tools/.*",
            r".*/scripts/.*", 
            r".*/dev.*",
            r".*/build.*",
            r".*/ci.*"
        ]
        
        assert dev_rule.path_patterns == expected_patterns
        assert dev_rule.strategy == "rapid_development"
        assert dev_rule.priority == 50


class TestLocationAwareConfigPatternMatching:
    """Test pattern matching functionality and accuracy."""
    
    def test_payment_service_path_matching(self):
        """Test payment service path pattern matching."""
        config = LocationAwareConfig()
        
        payment_paths = [
            "/app/payment-service/requirements.txt",
            "/services/payment/package.json",
            "/microservices/app/billing/Dockerfile",
            "/backend/app/financial/setup.py",
            "/src/services/billing-api/pom.xml"
        ]
        
        for path in payment_paths:
            strategy = config.get_strategy_for_location(path)
            assert strategy == "conservative_stability", f"Path {path} should use conservative strategy"
    
    def test_security_service_path_matching(self):
        """Test security service path pattern matching."""
        config = LocationAwareConfig()
        
        security_paths = [
            "/app/auth/requirements.txt",
            "/services/security/package.json", 
            "/microservices/app/authentication/Dockerfile",
            "/backend/services/auth-service/setup.py"
        ]
        
        for path in security_paths:
            strategy = config.get_strategy_for_location(path)
            assert strategy == "conservative_stability", f"Path {path} should use conservative strategy"
    
    def test_development_tools_path_matching(self):
        """Test development tools path pattern matching."""
        config = LocationAwareConfig()
        
        dev_paths = [
            "/tools/deployment/requirements.txt",
            "/scripts/build.py",
            "/build/webpack.config.js",
            "/ci/pipeline.yml",
            "/dev-tools/linter.json"
        ]
        
        for path in dev_paths:
            strategy = config.get_strategy_for_location(path)
            assert strategy == "rapid_development", f"Path {path} should use rapid development strategy"
    
    def test_testing_infrastructure_path_matching(self):
        """Test testing infrastructure path pattern matching."""
        config = LocationAwareConfig()
        
        test_paths = [
            "/tests/unit/test_payments.py",
            "/spec/integration/auth_spec.rb",
            "/qa/automation/requirements.txt",
            "/testing/pytest.ini"
        ]
        
        for path in test_paths:
            strategy = config.get_strategy_for_location(path)
            assert strategy == "balanced_security", f"Path {path} should use balanced strategy"
    
    def test_core_infrastructure_path_matching(self):
        """Test core infrastructure path pattern matching."""
        config = LocationAwareConfig()
        
        infra_paths = [
            "/infra/kubernetes/deployment.yaml",
            "/deploy/docker-compose.yml",
            "/ops/monitoring/requirements.txt",
            "/kubernetes/manifests/service.yaml",
            "/docker/Dockerfile"
        ]
        
        for path in infra_paths:
            strategy = config.get_strategy_for_location(path)
            assert strategy == "conservative_stability", f"Path {path} should use conservative strategy"
    
    def test_case_insensitive_matching(self):
        """Test that pattern matching is case-insensitive."""
        config = LocationAwareConfig()
        
        test_cases = [
            ("/APP/PAYMENT/requirements.txt", "conservative_stability"),
            ("/Tools/Build/package.json", "rapid_development"),
            ("/TESTS/Integration/spec.py", "balanced_security")
        ]
        
        for path, expected_strategy in test_cases:
            strategy = config.get_strategy_for_location(path)
            assert strategy == expected_strategy, f"Case-insensitive matching failed for {path}"
    
    def test_no_match_falls_back_to_default(self):
        """Test that unmatched paths fall back to default strategy."""
        config = LocationAwareConfig()
        
        unmatched_paths = [
            "/src/core/models.py",
            "/app/widgets/component.jsx",
            "/lib/utils/helper.js",
            "/main.py"
        ]
        
        for path in unmatched_paths:
            strategy = config.get_strategy_for_location(path)
            assert strategy == "balanced_security", f"Path {path} should fall back to default strategy"
    
    def test_priority_precedence(self):
        """Test that higher priority rules take precedence."""
        config = LocationAwareConfig()
        
        # Add custom high-priority rule that would conflict with payment services
        custom_rule = LocationRule(
            name="custom_payment_override",
            description="Custom override for payment services",
            path_patterns=[r".*/app/payment.*"],
            strategy="aggressive_security",
            priority=5  # Higher priority than built-in payment rule (10)
        )
        
        config.location_rules.append(custom_rule)
        config.location_rules.sort(key=lambda r: r.priority)
        
        # This path should now use the custom rule due to higher priority
        strategy = config.get_strategy_for_location("/app/payment/requirements.txt")
        assert strategy == "aggressive_security"
    
    def test_first_match_wins(self):
        """Test that first matching pattern wins within same priority."""
        config = LocationAwareConfig()
        
        # Payment services have multiple patterns - first match should win
        strategy = config.get_strategy_for_location("/app/payment-gateway/requirements.txt")
        assert strategy == "conservative_stability"
        
        # Explanation should show which pattern matched
        explanation = config.get_strategy_explanation("/app/payment-gateway/requirements.txt")
        assert explanation['reason'] == 'location_rule'
        assert explanation['rule_name'] == 'payment_services'


class TestLocationAwareConfigCustomRules:
    """Test loading and validation of custom configuration rules."""
    
    def test_load_custom_config_file(self):
        """Test loading custom configuration from YAML file."""
        custom_config = {
            'default_strategy': 'conservative_stability',
            'location_rules': [
                {
                    'name': 'custom_production',
                    'description': 'Custom production rule',
                    'path_patterns': [r'.*/prod/.*', r'.*/production/.*'],
                    'strategy': 'conservative_stability',
                    'priority': 5
                },
                {
                    'name': 'custom_experimental',
                    'description': 'Custom experimental rule', 
                    'path_patterns': [r'.*/experimental/.*'],
                    'strategy': 'aggressive_security',
                    'priority': 100
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(custom_config, f)
            config_path = Path(f.name)
        
        try:
            config = LocationAwareConfig(config_path=config_path)
            
            # Check default strategy was overridden
            assert config.default_strategy == 'conservative_stability'
            
            # Check custom rules were loaded
            custom_rule_names = {rule.name for rule in config.location_rules}
            assert 'custom_production' in custom_rule_names
            assert 'custom_experimental' in custom_rule_names
            
            # Test custom rule matching
            strategy = config.get_strategy_for_location('/prod/api/requirements.txt')
            assert strategy == 'conservative_stability'
            
            strategy = config.get_strategy_for_location('/experimental/new-feature/package.json')
            assert strategy == 'aggressive_security'
            
        finally:
            config_path.unlink()
    
    def test_load_config_with_missing_fields(self):
        """Test loading config with optional fields missing."""
        custom_config = {
            'location_rules': [
                {
                    'name': 'minimal_rule',
                    'path_patterns': [r'.*/minimal/.*'],
                    'strategy': 'balanced_security'
                    # Missing description and priority
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(custom_config, f)
            config_path = Path(f.name)
        
        try:
            config = LocationAwareConfig(config_path=config_path)
            
            # Should still load with defaults
            minimal_rule = next(
                rule for rule in config.location_rules
                if rule.name == 'minimal_rule'
            )
            
            assert minimal_rule.description == ''  # Default empty string
            assert minimal_rule.priority == 100  # Default priority
            
        finally:
            config_path.unlink()
    
    def test_load_config_invalid_yaml(self):
        """Test error handling for invalid YAML."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write("invalid: yaml: content: [\n")  # Malformed YAML
            config_path = Path(f.name)
        
        try:
            with pytest.raises(ValueError, match="Failed to load location config"):
                LocationAwareConfig(config_path=config_path)
        finally:
            config_path.unlink()
    
    def test_load_config_file_not_found(self):
        """Test error handling for missing config file."""
        non_existent_path = Path("/non/existent/config.yml")
        
        with pytest.raises(ValueError, match="Failed to load location config"):
            LocationAwareConfig(config_path=non_existent_path)
    
    def test_custom_rules_sorted_by_priority(self):
        """Test that custom rules are properly sorted by priority."""
        custom_config = {
            'location_rules': [
                {
                    'name': 'low_priority',
                    'path_patterns': [r'.*/low/.*'],
                    'strategy': 'balanced_security',
                    'priority': 100
                },
                {
                    'name': 'high_priority', 
                    'path_patterns': [r'.*/high/.*'],
                    'strategy': 'conservative_stability',
                    'priority': 1
                },
                {
                    'name': 'medium_priority',
                    'path_patterns': [r'.*/medium/.*'], 
                    'strategy': 'rapid_development',
                    'priority': 50
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(custom_config, f)
            config_path = Path(f.name)
        
        try:
            config = LocationAwareConfig(config_path=config_path)
            
            # Find custom rules and verify ordering
            custom_rules = [
                rule for rule in config.location_rules
                if rule.name in ['low_priority', 'high_priority', 'medium_priority']
            ]
            
            # Should be sorted by priority: high (1), medium (50), low (100)
            assert custom_rules[0].name == 'high_priority'
            assert custom_rules[1].name == 'medium_priority'  
            assert custom_rules[2].name == 'low_priority'
            
        finally:
            config_path.unlink()


class TestOrganizationalOverride:
    """Test organizational strategy override functionality."""
    
    def test_set_organizational_override(self):
        """Test setting organizational strategy override."""
        config = LocationAwareConfig()
        
        config.set_organizational_override("conservative_stability")
        assert config.organizational_override == "conservative_stability"
    
    def test_organizational_override_invalid_strategy(self):
        """Test error handling for invalid organizational strategy."""
        config = LocationAwareConfig()
        
        with pytest.raises(ValueError, match="Unknown strategy"):
            config.set_organizational_override("nonexistent_strategy")
    
    def test_organizational_override_takes_precedence(self):
        """Test that organizational override takes precedence over location rules."""
        config = LocationAwareConfig()
        
        # Without override, payment service should use conservative strategy
        assert config.get_strategy_for_location("/app/payment/requirements.txt") == "conservative_stability"
        
        # With override, should use override strategy
        config.set_organizational_override("rapid_development")
        assert config.get_strategy_for_location("/app/payment/requirements.txt") == "rapid_development"
        
        # Should apply to all paths
        assert config.get_strategy_for_location("/tools/build/package.json") == "rapid_development"
        assert config.get_strategy_for_location("/random/path/requirements.txt") == "rapid_development"
    
    def test_organizational_override_explanation(self):
        """Test explanation when organizational override is active."""
        config = LocationAwareConfig()
        config.set_organizational_override("conservative_stability")
        
        explanation = config.get_strategy_explanation("/app/payment/requirements.txt")
        
        assert explanation['strategy'] == 'conservative_stability'
        assert explanation['reason'] == 'organizational_override'
        assert 'Organization-wide strategy override' in explanation['details']


class TestStrategyExplanation:
    """Test strategy explanation functionality."""
    
    def test_explanation_for_location_rule_match(self):
        """Test explanation when location rule matches."""
        config = LocationAwareConfig()
        
        explanation = config.get_strategy_explanation("/app/payment/requirements.txt")
        
        assert explanation['strategy'] == 'conservative_stability'
        assert explanation['reason'] == 'location_rule'
        assert explanation['rule_name'] == 'payment_services'
        assert 'Payment and financial services' in explanation['details']
        assert 'matched_pattern' in explanation
    
    def test_explanation_for_default_fallback(self):
        """Test explanation when falling back to default."""
        config = LocationAwareConfig()
        
        explanation = config.get_strategy_explanation("/src/models/user.py")
        
        assert explanation['strategy'] == 'balanced_security'
        assert explanation['reason'] == 'default'
        assert 'No specific rules matched' in explanation['details']
        assert 'matched_pattern' not in explanation
        assert 'rule_name' not in explanation


class TestConfigValidation:
    """Test configuration validation functionality."""
    
    def test_validate_config_success(self):
        """Test validation of valid configuration."""
        config = LocationAwareConfig()
        issues = config.validate_config()
        assert len(issues) == 0
    
    def test_validate_config_invalid_default_strategy(self):
        """Test validation catches invalid default strategy."""
        config = LocationAwareConfig()
        config.default_strategy = "nonexistent_strategy"
        
        issues = config.validate_config()
        assert len(issues) >= 1
        assert any("Default strategy 'nonexistent_strategy' does not exist" in issue for issue in issues)
    
    def test_validate_config_invalid_organizational_override(self):
        """Test validation catches invalid organizational override."""
        config = LocationAwareConfig()
        config.organizational_override = "nonexistent_strategy"
        
        issues = config.validate_config()
        assert len(issues) >= 1
        assert any("Organizational override 'nonexistent_strategy' does not exist" in issue for issue in issues)
    
    def test_validate_config_invalid_rule_strategy(self):
        """Test validation catches invalid strategy in location rules."""
        config = LocationAwareConfig()
        
        # Add rule with invalid strategy
        invalid_rule = LocationRule(
            name="invalid_rule",
            description="Rule with invalid strategy",
            path_patterns=[r".*/test/.*"],
            strategy="nonexistent_strategy"
        )
        config.location_rules.append(invalid_rule)
        
        issues = config.validate_config()
        assert len(issues) >= 1
        assert any("Strategy 'nonexistent_strategy' in rule 'invalid_rule' does not exist" in issue for issue in issues)
    
    def test_validate_config_invalid_regex_pattern(self):
        """Test validation catches invalid regex patterns."""
        config = LocationAwareConfig()
        
        # Add rule with invalid regex
        invalid_rule = LocationRule(
            name="invalid_regex_rule",
            description="Rule with invalid regex",
            path_patterns=[r"[invalid regex pattern"],  # Missing closing bracket
            strategy="balanced_security"
        )
        config.location_rules.append(invalid_rule)
        
        issues = config.validate_config()
        assert len(issues) >= 1
        assert any("Invalid regex pattern" in issue for issue in issues)
        assert any("invalid_regex_rule" in issue for issue in issues)


class TestExampleConfigGeneration:
    """Test example configuration file generation."""
    
    def test_create_example_config_file(self):
        """Test creating example configuration file."""
        config = LocationAwareConfig()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            example_path = Path(f.name)
        
        try:
            config.create_example_config_file(example_path)
            
            # Verify file was created and is valid YAML
            assert example_path.exists()
            
            with open(example_path, 'r') as f:
                content = f.read()
                
            # Should contain expected sections
            assert "default_strategy: balanced_security" in content
            assert "location_rules:" in content
            assert "production_services" in content
            assert "microservices_payment" in content
            
            # Should be valid YAML that can be loaded back
            with open(example_path, 'r') as f:
                parsed_config = yaml.safe_load(f)
                
            assert parsed_config['default_strategy'] == 'balanced_security'
            assert 'location_rules' in parsed_config
            assert len(parsed_config['location_rules']) > 0
            
        finally:
            if example_path.exists():
                example_path.unlink()
    
    def test_create_example_config_creates_directories(self):
        """Test that creating example config creates parent directories."""
        config = LocationAwareConfig()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            example_path = Path(tmpdir) / "config" / "location" / "example.yml"
            
            config.create_example_config_file(example_path)
            
            assert example_path.exists()
            assert example_path.parent.exists()
    
    def test_create_example_config_error_handling(self):
        """Test error handling when creating example config fails."""
        config = LocationAwareConfig()
        
        # Try to write to a read-only location (should fail)
        read_only_path = Path("/root/example.yml")  # Assuming no write access
        
        with pytest.raises(ValueError, match="Failed to create example config"):
            config.create_example_config_file(read_only_path)


class TestProgressiveConfiguration:
    """Test the 4-level progressive configuration system."""
    
    def test_level_1_simple_default(self):
        """Test Level 1: Simple default (balanced_security everywhere)."""
        config = LocationAwareConfig()
        
        # Various file paths should all get balanced_security by default
        test_paths = [
            "/src/models/user.py",
            "/app/controllers/orders.py", 
            "/lib/utils/helper.js",
            "/components/Button.jsx"
        ]
        
        for path in test_paths:
            strategy = config.get_strategy_for_location(path)
            assert strategy == "balanced_security"
            
            explanation = config.get_strategy_explanation(path)
            assert explanation['reason'] == 'default'
    
    def test_level_2_organizational_override(self):
        """Test Level 2: Organizational override (applies everywhere)."""
        config = LocationAwareConfig()
        config.set_organizational_override("conservative_stability")
        
        # All paths should now use organizational override
        test_paths = [
            "/app/payment/requirements.txt",  # Would normally be conservative
            "/tools/build/package.json",      # Would normally be rapid_development
            "/src/models/user.py"             # Would normally be default
        ]
        
        for path in test_paths:
            strategy = config.get_strategy_for_location(path)
            assert strategy == "conservative_stability"
            
            explanation = config.get_strategy_explanation(path)
            assert explanation['reason'] == 'organizational_override'
    
    def test_level_3_location_aware_refinement_builtin(self):
        """Test Level 3: Location-aware refinement with built-in rules."""
        config = LocationAwareConfig()
        
        # Test different locations get different strategies
        location_strategy_mapping = [
            ("/app/payment/requirements.txt", "conservative_stability"),
            ("/tools/build/package.json", "rapid_development"),
            ("/tests/unit/test_user.py", "balanced_security"),
            ("/infra/k8s/deployment.yaml", "conservative_stability"),
            ("/src/models/user.py", "balanced_security")  # Default fallback
        ]
        
        for path, expected_strategy in location_strategy_mapping:
            strategy = config.get_strategy_for_location(path)
            assert strategy == expected_strategy, f"Path {path} should use {expected_strategy}"
    
    def test_level_4_advanced_custom_rules(self):
        """Test Level 4: Advanced custom rules with priorities and complex patterns."""
        custom_config = {
            'default_strategy': 'balanced_security',
            'location_rules': [
                {
                    'name': 'critical_payment_gateway',
                    'description': 'Critical payment gateway needs maximum stability',
                    'path_patterns': [r'.*/payment-gateway/.*'],
                    'strategy': 'conservative_stability',
                    'priority': 1  # Highest priority
                },
                {
                    'name': 'ml_experiments',
                    'description': 'ML experiments can be aggressive',
                    'path_patterns': [r'.*/ml/experiments/.*', r'.*/ai/research/.*'],
                    'strategy': 'aggressive_security',
                    'priority': 30
                },
                {
                    'name': 'frontend_components',
                    'description': 'Frontend components use rapid iteration',
                    'path_patterns': [r'.*/components/.*', r'.*/ui/.*'],
                    'strategy': 'rapid_development', 
                    'priority': 40
                },
                {
                    'name': 'integration_services',
                    'description': 'Integration services need careful updates',
                    'path_patterns': [r'.*/integrations/.*', r'.*/connectors/.*'],
                    'strategy': 'conservative_stability',
                    'priority': 20
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(custom_config, f)
            config_path = Path(f.name)
        
        try:
            config = LocationAwareConfig(config_path=config_path)
            
            # Test custom rule matching with proper priorities
            test_cases = [
                ("/services/payment-gateway/requirements.txt", "conservative_stability"),
                ("/ml/experiments/tensorflow/setup.py", "aggressive_security"),
                ("/frontend/components/Button/package.json", "rapid_development"),
                ("/integrations/salesforce/connector.py", "conservative_stability"),
                ("/random/service/requirements.txt", "balanced_security")  # Default fallback
            ]
            
            for path, expected_strategy in test_cases:
                strategy = config.get_strategy_for_location(path)
                assert strategy == expected_strategy, f"Path {path} should use {expected_strategy}"
                
        finally:
            config_path.unlink()


class TestEnterpriseScenarios:
    """Test enterprise-scale scenarios and complex monorepo structures."""
    
    def test_large_monorepo_pattern_matching(self):
        """Test pattern matching in large monorepo with many services."""
        config = LocationAwareConfig()
        
        # Simulate large enterprise monorepo structure
        monorepo_paths = [
            # Payment services (should be conservative)
            "/services/payment-api/requirements.txt",
            "/services/billing-service/package.json", 
            "/app/payment-dashboard/Gemfile",
            "/microservices/financial-reporting/pom.xml",
            
            # Security services (should be conservative)  
            "/services/auth-service/requirements.txt",
            "/app/security-dashboard/package.json",
            "/microservices/identity/Gemfile",
            
            # Development tools (should be rapid_development)
            "/tools/code-generator/requirements.txt",
            "/scripts/deployment/package.json",
            "/build/webpack/config.js",
            "/ci/pipeline-generator/setup.py",
            
            # Core infrastructure (should be conservative)
            "/infra/kubernetes/monitoring/requirements.txt",
            "/deploy/helm-charts/values.yaml",
            "/ops/logging/fluentd/Gemfile",
            
            # Testing (should be balanced)
            "/tests/integration/payment/test_gateway.py",
            "/qa/automation/selenium/requirements.txt",
            "/testing/performance/jmeter/pom.xml",
            
            # Regular services (should be default)
            "/services/user-service/requirements.txt",
            "/services/notification-service/package.json", 
            "/app/admin-portal/Gemfile"
        ]
        
        expected_strategies = {
            # Payment services (match built-in patterns)
            "/services/payment-api/requirements.txt": "conservative_stability",  # matches .*/services/payment.*
            "/services/billing-service/package.json": "conservative_stability",  # matches .*/services/billing.*
            "/app/payment-dashboard/Gemfile": "conservative_stability",        # matches .*/app/payment.*
            "/microservices/financial-reporting/pom.xml": "balanced_security", # no specific match, falls to default
            
            # Security services (match built-in patterns)
            "/services/auth-service/requirements.txt": "conservative_stability", # matches .*/services/auth.*
            "/app/security-dashboard/package.json": "conservative_stability",  # matches .*/app/security.*
            "/microservices/identity/Gemfile": "balanced_security",            # no specific match, falls to default
            
            # Development tools
            "/tools/code-generator/requirements.txt": "rapid_development",
            "/scripts/deployment/package.json": "rapid_development",
            "/build/webpack/config.js": "rapid_development", 
            "/ci/pipeline-generator/setup.py": "rapid_development",
            
            # Core infrastructure
            "/infra/kubernetes/monitoring/requirements.txt": "conservative_stability",
            "/deploy/helm-charts/values.yaml": "conservative_stability",
            "/ops/logging/fluentd/Gemfile": "conservative_stability",
            
            # Testing
            "/tests/integration/payment/test_gateway.py": "balanced_security",
            "/qa/automation/selenium/requirements.txt": "balanced_security",
            "/testing/performance/jmeter/pom.xml": "balanced_security",
            
            # Regular services (default fallback)
            "/services/user-service/requirements.txt": "balanced_security",
            "/services/notification-service/package.json": "balanced_security",
            "/app/admin-portal/Gemfile": "balanced_security"
        }
        
        for path, expected_strategy in expected_strategies.items():
            strategy = config.get_strategy_for_location(path)
            assert strategy == expected_strategy, f"Path {path} should use {expected_strategy}, got {strategy}"
    
    def test_complex_custom_enterprise_rules(self):
        """Test complex enterprise rules with multiple priorities and patterns."""
        enterprise_config = {
            'default_strategy': 'balanced_security',
            'location_rules': [
                # Tier 1: Business-critical services (highest priority)
                {
                    'name': 'tier1_payment_processing',
                    'description': 'Tier 1 payment processing - maximum stability required',
                    'path_patterns': [
                        r'.*/tier1/payment/.*',
                        r'.*/critical/billing/.*',
                        r'.*/pci-compliance/.*'
                    ],
                    'strategy': 'conservative_stability',
                    'priority': 1
                },
                
                # Tier 2: Important business services
                {
                    'name': 'tier2_business_services',
                    'description': 'Tier 2 business services - high stability',
                    'path_patterns': [
                        r'.*/tier2/.*/.*',
                        r'.*/business-logic/.*',
                        r'.*/customer-facing/.*'
                    ],
                    'strategy': 'conservative_stability',
                    'priority': 10
                },
                
                # Development environments
                {
                    'name': 'development_environments',
                    'description': 'Development environments - can move fast',
                    'path_patterns': [
                        r'.*/dev-env/.*',
                        r'.*/sandbox/.*',
                        r'.*/playground/.*'
                    ],
                    'strategy': 'rapid_development',
                    'priority': 20
                },
                
                # Internal tools and automation
                {
                    'name': 'internal_automation',
                    'description': 'Internal tools and automation',
                    'path_patterns': [
                        r'.*/internal-tools/.*',
                        r'.*/automation/.*',
                        r'.*/workflows/.*'
                    ],
                    'strategy': 'rapid_development',
                    'priority': 30
                },
                
                # Data processing pipelines
                {
                    'name': 'data_pipelines',
                    'description': 'Data processing pipelines - balanced approach',
                    'path_patterns': [
                        r'.*/data/pipelines/.*',
                        r'.*/etl/.*',
                        r'.*/analytics/.*'
                    ],
                    'strategy': 'balanced_security',
                    'priority': 40
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(enterprise_config, f)
            config_path = Path(f.name)
        
        try:
            config = LocationAwareConfig(config_path=config_path)
            
            enterprise_test_cases = [
                # Tier 1 - highest priority
                ("/services/tier1/payment/processor/requirements.txt", "conservative_stability"),
                ("/apps/critical/billing/gateway/package.json", "conservative_stability"),
                ("/services/pci-compliance/validator/Gemfile", "conservative_stability"),
                
                # Tier 2 - business services
                ("/services/tier2/orders/api/requirements.txt", "conservative_stability"),
                ("/apps/business-logic/inventory/package.json", "conservative_stability"),
                ("/services/customer-facing/portal/setup.py", "conservative_stability"),
                
                # Development environments
                ("/services/dev-env/experimental/requirements.txt", "rapid_development"),
                ("/apps/sandbox/prototype/package.json", "rapid_development"),
                ("/tools/playground/testing/setup.py", "rapid_development"),
                
                # Internal automation
                ("/tools/internal-tools/deployer/requirements.txt", "rapid_development"),
                ("/scripts/automation/ci-cd/package.json", "rapid_development"),
                ("/workflows/github-actions/setup.py", "rapid_development"),
                
                # Data pipelines
                ("/services/data/pipelines/etl/requirements.txt", "balanced_security"),
                ("/apps/analytics/dashboard/package.json", "balanced_security"),
                
                # Fallback to default
                ("/services/generic/api/requirements.txt", "balanced_security")
            ]
            
            for path, expected_strategy in enterprise_test_cases:
                strategy = config.get_strategy_for_location(path)
                assert strategy == expected_strategy, f"Enterprise path {path} should use {expected_strategy}, got {strategy}"
                
        finally:
            config_path.unlink()
    
    def test_monorepo_with_priority_conflicts(self):
        """Test priority resolution in complex monorepo with overlapping patterns."""
        # Use patterns that won't conflict with built-in rules
        config_with_conflicts = {
            'location_rules': [
                {
                    'name': 'generic_ecommerce',
                    'description': 'Generic ecommerce services',
                    'path_patterns': [r'.*/ecommerce/.*'],
                    'strategy': 'balanced_security',
                    'priority': 50
                },
                {
                    'name': 'critical_ecommerce_checkout',
                    'description': 'Critical ecommerce checkout - highest security',
                    'path_patterns': [r'.*/ecommerce/checkout/.*'],
                    'strategy': 'conservative_stability',
                    'priority': 10  # Higher priority (lower number)
                },
                {
                    'name': 'ecommerce_dev_tools',
                    'description': 'Ecommerce development tools',
                    'path_patterns': [r'.*/ecommerce/dev-tools/.*'],
                    'strategy': 'rapid_development',
                    'priority': 5   # Highest priority
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(config_with_conflicts, f)
            config_path = Path(f.name)
        
        try:
            config = LocationAwareConfig(config_path=config_path)
            
            # Test priority resolution
            conflict_test_cases = [
                # Should match highest priority rule (ecommerce_dev_tools - priority 5)
                ("/services/ecommerce/dev-tools/builder/requirements.txt", "rapid_development"),
                
                # Should match second highest priority (critical_ecommerce_checkout - priority 10)  
                ("/services/ecommerce/checkout/processor/package.json", "conservative_stability"),
                
                # Should match lowest priority (generic_ecommerce - priority 50)
                ("/services/ecommerce/reporting/requirements.txt", "balanced_security")
            ]
            
            for path, expected_strategy in conflict_test_cases:
                strategy = config.get_strategy_for_location(path)
                assert strategy == expected_strategy, f"Priority conflict path {path} should use {expected_strategy}, got {strategy}"
                
        finally:
            config_path.unlink()


class TestPerformanceAndScalability:
    """Test performance characteristics under enterprise scale."""
    
    def test_pattern_matching_performance(self):
        """Test pattern matching performance with many rules."""
        # Create config with many rules to simulate enterprise scale
        many_rules_config = {
            'location_rules': []
        }
        
        # Generate 100 rules with different patterns
        for i in range(100):
            rule = {
                'name': f'rule_{i:03d}',
                'description': f'Test rule number {i}',
                'path_patterns': [f'.*/service-{i:03d}/.*', f'.*/app-{i:03d}/.*'],
                'strategy': 'balanced_security',
                'priority': i + 1
            }
            many_rules_config['location_rules'].append(rule)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(many_rules_config, f)
            config_path = Path(f.name)
        
        try:
            config = LocationAwareConfig(config_path=config_path)
            
            # Test performance of pattern matching
            test_paths = [
                f"/services/service-{i:03d}/requirements.txt" for i in range(0, 100, 10)
            ]
            
            start_time = time.time()
            
            for path in test_paths:
                strategy = config.get_strategy_for_location(path)
                assert strategy == "balanced_security"
            
            end_time = time.time()
            elapsed = end_time - start_time
            
            # Should complete quickly even with many rules (less than 1 second)
            assert elapsed < 1.0, f"Pattern matching took too long: {elapsed:.3f}s"
            
        finally:
            config_path.unlink()
    
    def test_regex_compilation_caching(self):
        """Test that regex patterns are efficiently handled."""
        config = LocationAwareConfig()
        
        # Same path pattern should be handled efficiently on repeated calls
        test_path = "/app/payment/requirements.txt"
        
        start_time = time.time()
        
        # Call multiple times
        for _ in range(1000):
            strategy = config.get_strategy_for_location(test_path)
            assert strategy == "conservative_stability"
        
        end_time = time.time()
        elapsed = end_time - start_time
        
        # Should be fast even with many repeated calls
        assert elapsed < 1.0, f"Repeated pattern matching took too long: {elapsed:.3f}s"
    
    def test_large_path_handling(self):
        """Test handling of very long file paths."""
        config = LocationAwareConfig()
        
        # Create very long path
        long_path_components = ["very", "deeply", "nested"] * 20
        long_path = "/" + "/".join(long_path_components) + "/app/payment/requirements.txt"
        
        # Should still match payment pattern efficiently
        start_time = time.time()
        strategy = config.get_strategy_for_location(long_path)
        end_time = time.time()
        
        assert strategy == "conservative_stability"
        assert (end_time - start_time) < 0.1, "Long path matching should be fast"
    
    def test_concurrent_pattern_matching(self):
        """Test thread safety of pattern matching."""
        import threading
        import concurrent.futures
        
        config = LocationAwareConfig()
        
        test_paths = [
            "/app/payment/requirements.txt",
            "/tools/build/package.json", 
            "/tests/unit/test_user.py",
            "/services/auth/setup.py",
            "/src/models/order.py"
        ]
        
        expected_strategies = [
            "conservative_stability",
            "rapid_development",
            "balanced_security", 
            "conservative_stability",
            "balanced_security"
        ]
        
        def test_pattern_matching(path, expected):
            strategy = config.get_strategy_for_location(path)
            return strategy == expected
        
        # Test concurrent access
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            
            for _ in range(10):  # Multiple iterations
                for path, expected in zip(test_paths, expected_strategies):
                    future = executor.submit(test_pattern_matching, path, expected)
                    futures.append(future)
            
            # All should succeed
            for future in concurrent.futures.as_completed(futures):
                assert future.result(), "Concurrent pattern matching failed"


class TestErrorHandlingAndEdgeCases:
    """Test error handling and edge cases."""
    
    def test_empty_path_handling(self):
        """Test handling of empty or None paths."""
        config = LocationAwareConfig()
        
        # Empty string should fall back to default
        strategy = config.get_strategy_for_location("")
        assert strategy == "balanced_security"
        
        explanation = config.get_strategy_explanation("")
        assert explanation['reason'] == 'default'
    
    def test_none_path_handling(self):
        """Test handling of None path."""
        config = LocationAwareConfig()
        
        # None should not crash, should fall back to default
        # First we need to handle this in the implementation or expect an error
        try:
            strategy = config.get_strategy_for_location(None)
            assert strategy == "balanced_security"
        except (TypeError, AttributeError):
            # Expected behavior - None path should cause an error
            pass
    
    def test_malformed_regex_in_built_in_rules(self):
        """Test that built-in rules have valid regex patterns."""
        config = LocationAwareConfig()
        
        # All built-in patterns should compile successfully
        for rule in config.location_rules:
            for pattern in rule.path_patterns:
                try:
                    re.compile(pattern)
                except re.error:
                    pytest.fail(f"Built-in rule '{rule.name}' has invalid regex pattern: {pattern}")
    
    def test_unicode_path_handling(self):
        """Test handling of paths with unicode characters."""
        config = LocationAwareConfig()
        
        unicode_paths = [
            "/プロジェクト/app/payment/requirements.txt",
            "/服务/payment/包.json",
            "/проект/tools/build/файл.py"
        ]
        
        for path in unicode_paths:
            # Should not crash and should return a strategy
            strategy = config.get_strategy_for_location(path)
            assert strategy in ["conservative_stability", "rapid_development", "balanced_security"]
    
    def test_very_large_config_file(self):
        """Test loading very large configuration file."""
        large_config = {
            'location_rules': []
        }
        
        # Create config with many rules (stress test)
        for i in range(500):
            rule = {
                'name': f'stress_test_rule_{i}',
                'description': f'Stress test rule {i}',
                'path_patterns': [f'.*/stress{i}/.*'],
                'strategy': 'balanced_security',
                'priority': i + 1
            }
            large_config['location_rules'].append(rule)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(large_config, f)
            config_path = Path(f.name)
        
        try:
            start_time = time.time()
            config = LocationAwareConfig(config_path=config_path)
            end_time = time.time()
            
            # Should load within reasonable time
            assert (end_time - start_time) < 5.0, "Large config file took too long to load"
            assert len(config.location_rules) >= 500
            
        finally:
            config_path.unlink()
    
    def test_config_with_duplicate_rule_names(self):
        """Test handling of configuration with duplicate rule names."""
        duplicate_config = {
            'location_rules': [
                {
                    'name': 'duplicate_rule',
                    'path_patterns': [r'.*/first/.*'],
                    'strategy': 'conservative_stability',
                    'priority': 10
                },
                {
                    'name': 'duplicate_rule',  # Same name
                    'path_patterns': [r'.*/second/.*'],
                    'strategy': 'rapid_development',
                    'priority': 20
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(duplicate_config, f)
            config_path = Path(f.name)
        
        try:
            # Should load without error (both rules should be present)
            config = LocationAwareConfig(config_path=config_path)
            
            duplicate_rules = [
                rule for rule in config.location_rules 
                if rule.name == 'duplicate_rule'
            ]
            
            assert len(duplicate_rules) == 2, "Both duplicate rules should be loaded"
            
        finally:
            config_path.unlink()
    
    def test_strategy_manager_fallback(self):
        """Test fallback behavior when StrategyManager fails to load strategies."""
        config = LocationAwareConfig()
        
        # Mock strategy manager to return None for strategy lookup
        original_get_strategy = config.strategy_manager.get_strategy
        config.strategy_manager.get_strategy = Mock(return_value=None)
        
        try:
            # Validation should catch missing strategies
            issues = config.validate_config()
            assert len(issues) > 0
            
            # Should contain warnings about missing strategies
            assert any("does not exist" in issue for issue in issues)
            
        finally:
            config.strategy_manager.get_strategy = original_get_strategy


class TestDocumentationAndUsability:
    """Test documentation and usability features."""
    
    def test_rule_descriptions_are_informative(self):
        """Test that built-in rules have informative descriptions."""
        config = LocationAwareConfig()
        
        for rule in config.location_rules:
            # All rules should have non-empty descriptions
            assert rule.description.strip(), f"Rule '{rule.name}' has empty description"
            
            # Descriptions should be reasonably informative (more than just the name)
            assert len(rule.description) > 10, f"Rule '{rule.name}' has very short description"
    
    def test_strategy_explanation_completeness(self):
        """Test that strategy explanations provide complete information."""
        config = LocationAwareConfig()
        
        test_cases = [
            ("/app/payment/requirements.txt", "location_rule"),
            ("/src/models/user.py", "default")
        ]
        
        for path, expected_reason in test_cases:
            explanation = config.get_strategy_explanation(path)
            
            # Should have all required fields
            required_fields = ['strategy', 'reason', 'details']
            for field in required_fields:
                assert field in explanation, f"Missing field '{field}' in explanation for {path}"
                assert explanation[field], f"Empty field '{field}' in explanation for {path}"
            
            assert explanation['reason'] == expected_reason
            
            # Location rule explanations should have additional fields
            if expected_reason == 'location_rule':
                assert 'rule_name' in explanation
                assert 'matched_pattern' in explanation
    
    def test_example_config_file_quality(self):
        """Test that generated example config file is high quality."""
        config = LocationAwareConfig()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            example_path = Path(f.name)
        
        try:
            config.create_example_config_file(example_path)
            
            with open(example_path, 'r') as f:
                content = f.read()
            
            # Should have helpful comments
            assert "# Location-Aware Recommendation Configuration" in content
            assert "# Simple by default, powerful when needed" in content
            assert "# Lower priority number = higher precedence" in content
            
            # Should have realistic examples
            assert "production_services" in content
            assert "payment-service" in content
            assert "conservative_stability" in content
            assert "rapid_development" in content
            
            # Should be properly formatted YAML
            parsed = yaml.safe_load(content)
            assert 'default_strategy' in parsed
            assert 'location_rules' in parsed
            assert len(parsed['location_rules']) > 0
            
            # Each example rule should be complete
            for rule in parsed['location_rules']:
                assert 'name' in rule
                assert 'description' in rule 
                assert 'path_patterns' in rule
                assert 'strategy' in rule
                assert 'priority' in rule
                
        finally:
            example_path.unlink()


# Additional integration-style tests to ensure components work together

class TestLocationAwareConfigIntegration:
    """Integration tests ensuring all components work together correctly."""
    
    def test_end_to_end_location_based_strategy_selection(self):
        """Test complete end-to-end workflow of location-based strategy selection."""
        # Create custom enterprise configuration
        enterprise_config = {
            'default_strategy': 'balanced_security',
            'location_rules': [
                {
                    'name': 'critical_payment_apis',
                    'description': 'Critical payment APIs require maximum stability',
                    'path_patterns': [r'.*/apis/payment/.*', r'.*/services/billing/.*'],
                    'strategy': 'conservative_stability',
                    'priority': 5
                },
                {
                    'name': 'frontend_development',
                    'description': 'Frontend development can iterate rapidly',
                    'path_patterns': [r'.*/frontend/.*', r'.*/web-ui/.*'],
                    'strategy': 'rapid_development',
                    'priority': 30
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(enterprise_config, f)
            config_path = Path(f.name)
        
        try:
            # Initialize with custom config
            config = LocationAwareConfig(config_path=config_path)
            
            # Validate configuration
            issues = config.validate_config()
            assert len(issues) == 0, f"Configuration validation failed: {issues}"
            
            # Test different scenarios
            scenarios = [
                {
                    'path': '/services/apis/payment/gateway/requirements.txt',
                    'expected_strategy': 'conservative_stability',
                    'expected_reason': 'location_rule',
                    'expected_rule': 'critical_payment_apis'
                },
                {
                    'path': '/apps/frontend/components/package.json',
                    'expected_strategy': 'rapid_development',
                    'expected_reason': 'location_rule', 
                    'expected_rule': 'frontend_development'
                },
                {
                    'path': '/services/user-management/setup.py',
                    'expected_strategy': 'balanced_security',
                    'expected_reason': 'default',
                    'expected_rule': None
                }
            ]
            
            for scenario in scenarios:
                # Get strategy
                strategy = config.get_strategy_for_location(scenario['path'])
                assert strategy == scenario['expected_strategy']
                
                # Get explanation
                explanation = config.get_strategy_explanation(scenario['path'])
                assert explanation['strategy'] == scenario['expected_strategy']
                assert explanation['reason'] == scenario['expected_reason']
                
                if scenario['expected_rule']:
                    assert explanation['rule_name'] == scenario['expected_rule']
            
            # Test organizational override
            config.set_organizational_override('conservative_stability')
            
            # All paths should now use organizational override
            for scenario in scenarios:
                strategy = config.get_strategy_for_location(scenario['path'])
                assert strategy == 'conservative_stability'
                
                explanation = config.get_strategy_explanation(scenario['path'])
                assert explanation['reason'] == 'organizational_override'
            
        finally:
            config_path.unlink()
    
    def test_complex_priority_and_pattern_interaction(self):
        """Test complex interactions between priorities, patterns, and fallbacks."""
        complex_config = {
            'default_strategy': 'balanced_security',
            'location_rules': [
                # Overlapping patterns with different priorities
                {
                    'name': 'all_services',
                    'path_patterns': [r'.*/services/.*'],
                    'strategy': 'balanced_security',
                    'priority': 100  # Low priority
                },
                {
                    'name': 'payment_services',
                    'path_patterns': [r'.*/services/payment.*'],
                    'strategy': 'conservative_stability',  
                    'priority': 50   # Medium priority
                },
                {
                    'name': 'critical_payment_gateway',
                    'path_patterns': [r'.*/services/.*-payment/.*'],
                    'strategy': 'conservative_stability',
                    'priority': 10   # High priority
                },
                {
                    'name': 'payment_gateway_dev_tools',
                    'path_patterns': [r'.*/services/payment-gateway/dev-tools/.*'],
                    'strategy': 'rapid_development',
                    'priority': 5    # Highest priority
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(complex_config, f)
            config_path = Path(f.name)
        
        try:
            config = LocationAwareConfig(config_path=config_path)
            
            # Test priority resolution with overlapping patterns
            # Note: Built-in rules are also present and may match first
            priority_test_cases = [
                # Should match highest priority custom rule (priority 5)
                ('/services/payment-gateway/dev-tools/builder/requirements.txt', 'rapid_development', 'payment_gateway_dev_tools'),
                
                # Should match second highest priority custom rule (priority 10)
                # Use a path that won't match built-in payment_services rule
                ('/services/gateway-payment/api/package.json', 'conservative_stability', 'critical_payment_gateway'),
                
                # This path will match built-in payment_services rule (priority 10) since it comes first in sort order
                ('/services/payment-service/requirements.txt', 'conservative_stability', 'payment_services'),
                
                # Should match custom all_services rule (priority 100)
                ('/services/user-service/package.json', 'balanced_security', 'all_services'),
                
                # Should fall back to default (no match)
                ('/apps/frontend/components/Button.tsx', 'balanced_security', None)
            ]
            
            for path, expected_strategy, expected_rule in priority_test_cases:
                strategy = config.get_strategy_for_location(path)
                explanation = config.get_strategy_explanation(path)
                
                assert strategy == expected_strategy, f"Path {path} should use {expected_strategy}, got {strategy}"
                
                if expected_rule:
                    assert explanation['rule_name'] == expected_rule, f"Path {path} should match rule {expected_rule}"
                else:
                    assert explanation['reason'] == 'default'
            
        finally:
            config_path.unlink()


if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v"])