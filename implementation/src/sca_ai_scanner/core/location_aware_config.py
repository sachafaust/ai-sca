"""
Location-Aware Configuration System

Provides progressive extensibility:
1. Simple default (balanced_security everywhere)
2. Organizational override (--recommendation-strategy conservative_stability)  
3. Location-aware refinement (config file with path-based rules)

Philosophy: Simple by default, powerful when needed.
"""

from pathlib import Path
from typing import Dict, List, Optional, Pattern
import re
import yaml
from dataclasses import dataclass

from .recommendation_strategies import StrategyManager


@dataclass
class LocationRule:
    """A rule mapping file paths to recommendation strategies."""
    name: str
    description: str
    path_patterns: List[str]
    strategy: str
    priority: int = 100  # Lower number = higher priority


class LocationAwareConfig:
    """Configuration for location-aware recommendation strategies."""
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize with optional config file."""
        self.strategy_manager = StrategyManager()
        self.default_strategy = "balanced_security"
        self.organizational_override: Optional[str] = None
        self.location_rules: List[LocationRule] = []
        
        # Load built-in rules (sensible defaults)
        self._load_built_in_rules()
        
        # Load custom rules if config provided
        if config_path:
            self._load_config_file(config_path)
    
    def _load_built_in_rules(self):
        """Load sensible default location rules."""
        
        # High priority: Critical production services
        self.location_rules.extend([
            LocationRule(
                name="payment_services",
                description="Payment and financial services require conservative approach",
                path_patterns=[
                    r".*/app/payment.*",
                    r".*/app/billing.*", 
                    r".*/app/financial.*",
                    r".*/services/payment.*",
                    r".*/services/billing.*"
                ],
                strategy="conservative_stability",
                priority=10
            ),
            
            LocationRule(
                name="security_services", 
                description="Security and auth services require conservative approach",
                path_patterns=[
                    r".*/app/auth.*",
                    r".*/app/security.*",
                    r".*/services/auth.*",
                    r".*/services/security.*"
                ],
                strategy="conservative_stability",
                priority=10
            ),
            
            LocationRule(
                name="core_infrastructure",
                description="Core infrastructure requires stability",
                path_patterns=[
                    r".*/infra/.*",
                    r".*/deploy/.*",
                    r".*/ops/.*",
                    r".*kubernetes.*",
                    r".*docker.*"
                ],
                strategy="conservative_stability", 
                priority=20
            )
        ])
        
        # Medium priority: Development and testing
        self.location_rules.extend([
            LocationRule(
                name="development_tools",
                description="Development tools can use aggressive updates",
                path_patterns=[
                    r".*/tools/.*",
                    r".*/scripts/.*", 
                    r".*/dev.*",
                    r".*/build.*",
                    r".*/ci.*"
                ],
                strategy="rapid_development",
                priority=50
            ),
            
            LocationRule(
                name="testing_infrastructure",
                description="Testing can balance security and convenience",
                path_patterns=[
                    r".*/test.*",
                    r".*/spec.*",
                    r".*pytest.*",
                    r".*/qa.*"
                ],
                strategy="balanced_security",
                priority=50
            )
        ])
    
    def _load_config_file(self, config_path: Path):
        """Load custom location rules from YAML config."""
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
            
            # Override default strategy if specified
            if 'default_strategy' in config_data:
                self.default_strategy = config_data['default_strategy']
            
            # Load custom location rules
            custom_rules = config_data.get('location_rules', [])
            for rule_data in custom_rules:
                rule = LocationRule(
                    name=rule_data['name'],
                    description=rule_data.get('description', ''),
                    path_patterns=rule_data['path_patterns'],
                    strategy=rule_data['strategy'],
                    priority=rule_data.get('priority', 100)
                )
                self.location_rules.append(rule)
            
            # Sort rules by priority (lower number = higher priority)
            self.location_rules.sort(key=lambda r: r.priority)
            
        except Exception as e:
            raise ValueError(f"Failed to load location config from {config_path}: {e}")
    
    def set_organizational_override(self, strategy_name: str):
        """Set organizational strategy override."""
        if not self.strategy_manager.get_strategy(strategy_name):
            raise ValueError(f"Unknown strategy: {strategy_name}")
        self.organizational_override = strategy_name
    
    def get_strategy_for_location(self, file_path: str) -> str:
        """Get the appropriate strategy for a specific file location."""
        
        # 1. Check organizational override first (if set, applies everywhere)
        if self.organizational_override:
            return self.organizational_override
        
        # 2. Check location rules (in priority order)
        for rule in self.location_rules:
            for pattern in rule.path_patterns:
                if re.match(pattern, file_path, re.IGNORECASE):
                    return rule.strategy
        
        # 3. Fall back to default strategy
        return self.default_strategy
    
    def get_strategy_explanation(self, file_path: str) -> Dict[str, str]:
        """Get explanation of why a particular strategy was chosen."""
        
        if self.organizational_override:
            return {
                'strategy': self.organizational_override,
                'reason': 'organizational_override',
                'details': f'Organization-wide strategy override: {self.organizational_override}'
            }
        
        for rule in self.location_rules:
            for pattern in rule.path_patterns:
                if re.match(pattern, file_path, re.IGNORECASE):
                    return {
                        'strategy': rule.strategy,
                        'reason': 'location_rule',
                        'rule_name': rule.name,
                        'details': rule.description,
                        'matched_pattern': pattern
                    }
        
        return {
            'strategy': self.default_strategy,
            'reason': 'default',
            'details': 'No specific rules matched, using default strategy'
        }
    
    def create_example_config_file(self, output_path: Path):
        """Create an example configuration file for users."""
        
        example_config = {
            '# Location-Aware Recommendation Configuration': None,
            '# Simple by default, powerful when needed': None,
            '': None,
            '# Default strategy (used when no location rules match)': None,
            'default_strategy': 'balanced_security',
            '': None,
            '# Location-specific rules (checked in priority order)': None,
            'location_rules': [
                {
                    'name': 'production_services',
                    'description': 'Production services need conservative approach',
                    'path_patterns': [
                        '.*/app/production/.*',
                        '.*/services/core/.*'
                    ],
                    'strategy': 'conservative_stability',
                    'priority': 10
                },
                {
                    'name': 'microservices_payment',
                    'description': 'Payment microservices are critical',
                    'path_patterns': [
                        '.*/payment-service/.*',
                        '.*/billing-service/.*'
                    ],
                    'strategy': 'conservative_stability', 
                    'priority': 5
                },
                {
                    'name': 'internal_tools',
                    'description': 'Internal tools can move faster',
                    'path_patterns': [
                        '.*/tools/.*',
                        '.*/admin/.*'
                    ],
                    'strategy': 'rapid_development',
                    'priority': 30
                },
                {
                    'name': 'experimental',
                    'description': 'Experimental code can be aggressive',
                    'path_patterns': [
                        '.*/experimental/.*',
                        '.*/research/.*'
                    ],
                    'strategy': 'aggressive_security',
                    'priority': 40
                }
            ]
        }
        
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                # Write header comments
                f.write("# Location-Aware Recommendation Configuration\n")
                f.write("# Simple by default, powerful when needed\n\n")
                f.write("# Default strategy (used when no location rules match)\n")
                f.write("default_strategy: balanced_security\n\n")
                f.write("# Location-specific rules (checked in priority order)\n")
                f.write("# Lower priority number = higher precedence\n")
                f.write("location_rules:\n")
                
                for rule in example_config['location_rules']:
                    f.write(f"  - name: {rule['name']}\n")
                    f.write(f"    description: {rule['description']}\n")
                    f.write(f"    priority: {rule['priority']}\n")
                    f.write(f"    strategy: {rule['strategy']}\n")
                    f.write(f"    path_patterns:\n")
                    for pattern in rule['path_patterns']:
                        f.write(f"      - '{pattern}'\n")
                    f.write("\n")
            
            print(f"Created example config: {output_path}")
            
        except Exception as e:
            raise ValueError(f"Failed to create example config: {e}")
    
    def validate_config(self) -> List[str]:
        """Validate the current configuration and return any issues."""
        
        issues = []
        
        # Check default strategy exists
        if not self.strategy_manager.get_strategy(self.default_strategy):
            issues.append(f"Default strategy '{self.default_strategy}' does not exist")
        
        # Check organizational override exists
        if self.organizational_override:
            if not self.strategy_manager.get_strategy(self.organizational_override):
                issues.append(f"Organizational override '{self.organizational_override}' does not exist")
        
        # Check all location rule strategies exist
        for rule in self.location_rules:
            if not self.strategy_manager.get_strategy(rule.strategy):
                issues.append(f"Strategy '{rule.strategy}' in rule '{rule.name}' does not exist")
            
            # Check patterns are valid regex
            for pattern in rule.path_patterns:
                try:
                    re.compile(pattern)
                except re.error as e:
                    issues.append(f"Invalid regex pattern '{pattern}' in rule '{rule.name}': {e}")
        
        return issues