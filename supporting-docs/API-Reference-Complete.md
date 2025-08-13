# Complete API Reference: Location-Aware SCA System

**Version**: 1.0  
**Date**: 2025-07-27  
**Target Audience**: Developers, AI Agents, System Integrators  

## Overview

This document provides complete API reference for the Location-Aware SCA Recommendations system. All classes, methods, configuration options, and data structures are documented with examples.

## Core Classes

### LocationAwareConfig

Main class for managing location-aware recommendation strategies.

```python
class LocationAwareConfig:
    """Configuration for location-aware recommendation strategies."""
```

#### Constructor

```python
def __init__(self, config_path: Optional[Path] = None) -> None:
    """Initialize with optional config file.
    
    Args:
        config_path: Optional path to YAML configuration file
        
    Raises:
        ValueError: If config file exists but cannot be parsed
        FileNotFoundError: If config_path provided but file doesn't exist
    """
```

**Example Usage:**
```python
# Basic usage with built-in rules
config = LocationAwareConfig()

# Load custom configuration
config = LocationAwareConfig(Path("my-location-rules.yml"))
```

#### Core Methods

##### get_strategy_for_location()

```python
def get_strategy_for_location(self, file_path: str) -> str:
    """Get the appropriate strategy for a specific file location.
    
    Args:
        file_path: Absolute or relative file path to analyze
        
    Returns:
        Strategy name (e.g., 'conservative_stability', 'rapid_development')
        
    Logic:
        1. Check organizational override first (if set, applies everywhere)
        2. Check location rules in priority order (lower number = higher priority)
        3. Fall back to default strategy
    """
```

**Example Usage:**
```python
config = LocationAwareConfig()

# Different contexts return different strategies
payment_strategy = config.get_strategy_for_location("/app/payment-service/requirements.txt")
# Returns: "conservative_stability"

tools_strategy = config.get_strategy_for_location("/tools/ci-utils/poetry.lock")  
# Returns: "rapid_development"

test_strategy = config.get_strategy_for_location("/tests/integration/requirements.txt")
# Returns: "balanced_security"
```

##### get_strategy_explanation()

```python
def get_strategy_explanation(self, file_path: str) -> Dict[str, str]:
    """Get explanation of why a particular strategy was chosen.
    
    Args:
        file_path: File path to analyze
        
    Returns:
        Dictionary with explanation details:
        {
            'strategy': str,           # Strategy name selected
            'reason': str,             # Reason type ('organizational_override', 'location_rule', 'default')
            'rule_name': str,          # Rule name (if reason='location_rule')
            'details': str,            # Human-readable explanation
            'matched_pattern': str     # Regex pattern matched (if applicable)
        }
    """
```

**Example Usage:**
```python
explanation = config.get_strategy_explanation("/app/payment-service/requirements.txt")

# Returns:
{
    'strategy': 'conservative_stability',
    'reason': 'location_rule',
    'rule_name': 'payment_services', 
    'details': 'Payment and financial services require conservative approach',
    'matched_pattern': r'.*/app/payment.*'
}
```

##### set_organizational_override()

```python
def set_organizational_override(self, strategy_name: str) -> None:
    """Set organizational strategy override.
    
    Args:
        strategy_name: Name of strategy to apply everywhere
        
    Raises:
        ValueError: If strategy_name doesn't exist in StrategyManager
        
    Note:
        When set, this strategy overrides ALL location rules.
        Use for organization-wide policy enforcement.
    """
```

**Example Usage:**
```python
config = LocationAwareConfig()

# Apply conservative approach everywhere
config.set_organizational_override("conservative_stability")

# Now ALL locations return conservative_stability
strategy = config.get_strategy_for_location("/tools/dev-scripts/requirements.txt")
# Returns: "conservative_stability" (not "rapid_development")
```

##### create_example_config_file()

```python
def create_example_config_file(self, output_path: Path) -> None:
    """Create an example configuration file for users.
    
    Args:
        output_path: Path where example config will be written
        
    Raises:
        ValueError: If file cannot be created or written
        PermissionError: If insufficient permissions for output_path
        
    Creates:
        YAML file with example location rules and documentation
    """
```

**Example Usage:**
```python
config = LocationAwareConfig()
config.create_example_config_file(Path("my-location-config.yml"))

# Creates YAML file with documented examples
```

##### validate_config()

```python
def validate_config(self) -> List[str]:
    """Validate the current configuration and return any issues.
    
    Returns:
        List of validation error messages (empty if configuration is valid)
        
    Checks:
        - Default strategy exists in StrategyManager
        - Organizational override strategy exists (if set)
        - All location rule strategies exist
        - All regex patterns are valid
    """
```

**Example Usage:**
```python
config = LocationAwareConfig()
issues = config.validate_config()

if issues:
    for issue in issues:
        print(f"Configuration issue: {issue}")
else:
    print("Configuration is valid")
```

#### Properties

```python
@property
def default_strategy(self) -> str:
    """Default strategy used when no location rules match."""

@property  
def organizational_override(self) -> Optional[str]:
    """Organizational strategy override (if set)."""

@property
def location_rules(self) -> List[LocationRule]:
    """List of location rules, sorted by priority."""
```

### LocationRule

Data class representing a single location-to-strategy mapping rule.

```python
@dataclass
class LocationRule:
    """A rule mapping file paths to recommendation strategies."""
    
    name: str                    # Human-readable rule name
    description: str             # Explanation of why this rule exists
    path_patterns: List[str]     # List of regex patterns to match file paths
    strategy: str                # Strategy name to apply when pattern matches
    priority: int = 100          # Rule priority (lower number = higher priority)
```

**Example:**
```python
rule = LocationRule(
    name="payment_services",
    description="Payment and financial services require conservative approach",
    path_patterns=[
        r".*/app/payment.*",
        r".*/services/billing.*"
    ],
    strategy="conservative_stability",
    priority=10
)
```

## Built-in Location Rules

### High Priority Rules (Conservative Strategy)

#### Payment Services
```python
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
)
```

#### Security Services
```python
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
)
```

#### Core Infrastructure
```python
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
```

### Medium Priority Rules (Development Strategy)

#### Development Tools
```python
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
)
```

#### Testing Infrastructure
```python
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
```

## CLI Interface

### Command Line Options

#### Location-Aware Options

```bash
--location-config PATH
```
**Description**: Path to location-aware recommendation configuration (advanced)  
**Type**: File path (must exist)  
**Example**: `sca-scanner . --location-config ./my-rules.yml`

```bash
--create-location-config PATH  
```
**Description**: Create example location-aware config file and exit  
**Type**: File path (will be created)  
**Example**: `sca-scanner --create-location-config ./example-config.yml`

#### Strategy Options (Enhanced)

```bash
--recommendation-strategy STRATEGY
```
**Description**: Recommendation strategy (organizational override)  
**Type**: Strategy name  
**Default**: `balanced_security`  
**Values**: `balanced_security`, `conservative_stability`, `aggressive_security`, `rapid_development`  
**Example**: `sca-scanner . --recommendation-strategy conservative_stability`

```bash
--list-strategies
```
**Description**: List available recommendation strategies and exit  
**Shows**: All strategies, usage levels, and configuration examples  
**Example**: `sca-scanner --list-strategies`

### CLI Usage Patterns

#### Progressive Configuration Levels

```bash
# Level 1: Simple Default (automatic location-aware)
sca-scanner .

# Level 2: Organizational Override  
sca-scanner . --recommendation-strategy conservative_stability

# Level 3: Location-Aware with built-in intelligence (default behavior)
sca-scanner .  # Automatic context detection

# Level 4: Custom Location Configuration
sca-scanner . --location-config my-custom-rules.yml
```

#### Configuration Management

```bash
# Create example configuration
sca-scanner --create-location-config my-locations.yml

# Validate configuration by listing strategies
sca-scanner --list-strategies

# Apply custom configuration
sca-scanner ~/my-project --location-config my-locations.yml
```

## Configuration File Format

### YAML Structure

```yaml
# Location-aware recommendation configuration

# Default strategy when no location rules match
default_strategy: balanced_security

# Location-specific rules (checked in priority order) 
# Lower priority number = higher precedence
location_rules:
  - name: rule_name
    description: Human-readable explanation
    priority: integer              # Lower = higher priority
    strategy: strategy_name        # Must exist in StrategyManager
    path_patterns:                 # List of regex patterns
      - 'regex_pattern_1'
      - 'regex_pattern_2'
```

### Complete Example Configuration

```yaml
# my-location-config.yml
default_strategy: balanced_security

location_rules:
  # Highest priority: Critical production services
  - name: microservices_payment
    description: Payment microservices are critical
    priority: 5
    strategy: conservative_stability
    path_patterns:
      - '.*/payment-service/.*'
      - '.*/billing-service/.*'
  
  - name: security_authentication  
    description: Auth services require stability
    priority: 8
    strategy: conservative_stability
    path_patterns:
      - '.*/auth-service/.*'
      - '.*/identity-service/.*'
  
  # Medium priority: Production services
  - name: production_services
    description: Production services need conservative approach
    priority: 10
    strategy: conservative_stability
    path_patterns:
      - '.*/app/production/.*'
      - '.*/services/core/.*'
  
  # Lower priority: Development and utilities
  - name: internal_tools
    description: Internal tools can move faster
    priority: 30
    strategy: rapid_development
    path_patterns:
      - '.*/tools/.*'
      - '.*/admin/.*'
      - '.*/utilities/.*'
  
  - name: testing_infrastructure
    description: Testing balances security and convenience
    priority: 40
    strategy: balanced_security
    path_patterns:
      - '.*/test/.*'
      - '.*/spec/.*'
      - '.*/qa/.*'
  
  # Lowest priority: Experimental code
  - name: experimental
    description: Experimental code can be aggressive
    priority: 50
    strategy: aggressive_security
    path_patterns:
      - '.*/experimental/.*'
      - '.*/research/.*'
      - '.*/prototype/.*'
```

### Configuration Validation Rules

1. **Strategy Names**: Must exist in StrategyManager
2. **Priority Values**: Must be positive integers
3. **Regex Patterns**: Must be valid regex expressions
4. **Required Fields**: name, strategy, path_patterns
5. **Pattern Uniqueness**: No duplicate patterns across rules
6. **Priority Uniqueness**: Duplicate priorities allowed but not recommended

## Integration APIs

### Strategy Manager Integration

```python
# Location-aware config integrates with existing strategy system
strategy_manager = StrategyManager()
location_config = LocationAwareConfig()

# Get location-appropriate strategy
file_path = "/app/payment-service/requirements.txt"
strategy_name = location_config.get_strategy_for_location(file_path)
strategy = strategy_manager.get_strategy(strategy_name)

# Use strategy in recommendation engine
engine = RecommendationEngine(strategy)
recommendations = engine.analyze_package(package_name, version, cves)
```

### CLI Integration Pattern

```python
def main(..., location_config: Optional[Path], ...):
    # Handle location config creation
    if create_location_config:
        config = LocationAwareConfig()
        config.create_example_config_file(create_location_config)
        return
    
    # Load location config if provided
    location_aware_config = None
    if location_config:
        location_aware_config = LocationAwareConfig(location_config)
    else:
        # Use built-in location intelligence
        location_aware_config = LocationAwareConfig()
    
    # Apply organizational override if specified
    if recommendation_strategy != 'balanced_security':
        location_aware_config.set_organizational_override(recommendation_strategy)
```

### Recommendation Engine Integration

```python
def generate_recommendations(
    package: Package, 
    cves: List[CVEFinding],
    location_config: Optional[LocationAwareConfig] = None
) -> PackageRecommendations:
    
    if location_config and package.source_locations:
        # Use location-specific strategy
        file_path = package.source_locations[0].file_path
        strategy_name = location_config.get_strategy_for_location(file_path)
        strategy = strategy_manager.get_strategy(strategy_name)
        
        # Add location context to recommendations
        explanation = location_config.get_strategy_explanation(file_path)
        
    else:
        # Fallback to default strategy
        strategy = strategy_manager.get_default_strategy()
        explanation = {'reason': 'default', 'details': 'No location config provided'}
    
    # Generate recommendations with context
    engine = RecommendationEngine(strategy)
    recommendations = engine.analyze_package(package.name, package.version, cves)
    
    # Enhance with location context
    recommendations.location_context = explanation
    
    return recommendations
```

## Data Structures

### Enhanced Recommendation Output

```python
class PackageRecommendations(BaseModel):
    """Enhanced recommendations with location context."""
    
    # Existing fields (unchanged)
    package_name: str
    current_version: str
    current_risk_level: str
    total_cves: int
    recommendation_options: List[RecommendationOption]
    default_choice: Optional[str]
    reasoning: str
    confidence: float
    
    # New location-aware fields
    location_context: Optional[Dict[str, str]] = None
    """Location context information:
    {
        'strategy': str,           # Strategy name used
        'reason': str,             # Why this strategy was chosen
        'rule_name': str,          # Rule name (if applicable)
        'details': str,            # Human explanation
        'matched_pattern': str     # Regex pattern matched
    }
    """
```

### Enhanced CLI Output

```json
{
  "package": "django:4.2.7",
  "current_version": "4.2.7",
  "current_risk": "medium",
  "total_cves": 3,
  "location_context": {
    "file_path": "/app/payment-service/requirements.txt",
    "strategy": "conservative_stability",
    "reason": "location_rule",
    "rule_name": "payment_services",
    "details": "Payment and financial services require conservative approach",
    "matched_pattern": ".*/app/payment.*"
  },
  "recommendation_options": [
    {
      "strategy_name": "conservative_stability",
      "action": "patch",
      "priority": "high",
      "target_version": "4.2.8",
      "effort_estimate": "low",
      "fixes_cves": ["CVE-2024-12345"],
      "remaining_risk": "low",
      "breaking_changes": "none",
      "recommendation_text": "Apply security patch with minimal changes",
      "business_justification": "Addresses security issues while maintaining payment service stability"
    }
  ],
  "default_choice": "patch",
  "reasoning": "Selected patch based on conservative_stability strategy; addresses security issues while maintaining payment service stability"
}
```

## Error Handling

### Exception Types

```python
class LocationConfigError(Exception):
    """Base exception for location configuration errors."""
    pass

class InvalidPatternError(LocationConfigError):
    """Raised when regex pattern is invalid."""
    pass

class UnknownStrategyError(LocationConfigError):
    """Raised when strategy doesn't exist in StrategyManager."""
    pass

class ConfigFileError(LocationConfigError):
    """Raised when configuration file cannot be loaded or parsed."""
    pass
```

### Error Response Patterns

```python
# Graceful degradation for missing strategies
def get_strategy_for_location(self, file_path: str) -> str:
    strategy_name = self._determine_strategy(file_path)
    
    # Validate strategy exists
    if not self.strategy_manager.get_strategy(strategy_name):
        logging.warning(f"Strategy '{strategy_name}' not found, using default")
        return self.default_strategy
    
    return strategy_name
```

```python
# Configuration validation with detailed errors
def validate_config(self) -> List[str]:
    issues = []
    
    # Check default strategy
    if not self.strategy_manager.get_strategy(self.default_strategy):
        issues.append(f"Default strategy '{self.default_strategy}' does not exist")
    
    # Check all location rules
    for rule in self.location_rules:
        if not self.strategy_manager.get_strategy(rule.strategy):
            issues.append(f"Strategy '{rule.strategy}' in rule '{rule.name}' does not exist")
        
        # Validate regex patterns
        for pattern in rule.path_patterns:
            try:
                re.compile(pattern)
            except re.error as e:
                issues.append(f"Invalid regex pattern '{pattern}' in rule '{rule.name}': {e}")
    
    return issues
```

## Performance Considerations

### Pattern Matching Optimization

```python
# Rules are sorted by priority for early exit
self.location_rules.sort(key=lambda r: r.priority)

# First match wins (higher priority rules checked first)
for rule in self.location_rules:
    for pattern in rule.path_patterns:
        if re.match(pattern, file_path, re.IGNORECASE):
            return rule.strategy  # Early exit on first match
```

### Memory Efficiency

```python
# Lazy loading of custom configuration
def __init__(self, config_path: Optional[Path] = None):
    # Always load built-in rules
    self._load_built_in_rules()
    
    # Only load custom config if provided
    if config_path:
        self._load_config_file(config_path)
```

### Caching Strategies

```python
# Optional: Cache compiled regex patterns for repeated use
@functools.lru_cache(maxsize=128)
def _compile_pattern(self, pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)
```

## Testing Interface

### Unit Test Helpers

```python
class LocationAwareConfigTest:
    """Test utilities for location-aware configuration."""
    
    @staticmethod
    def create_test_config() -> LocationAwareConfig:
        """Create configuration for testing."""
        config = LocationAwareConfig()
        return config
    
    @staticmethod
    def create_minimal_config() -> LocationAwareConfig:
        """Create minimal configuration with no custom rules."""
        config = LocationAwareConfig()
        config.location_rules = []  # Remove built-in rules for testing
        return config
    
    @staticmethod
    def assert_strategy_assignment(
        config: LocationAwareConfig,
        file_path: str, 
        expected_strategy: str
    ):
        """Assert that file path gets expected strategy."""
        actual_strategy = config.get_strategy_for_location(file_path)
        assert actual_strategy == expected_strategy, \
            f"Expected {expected_strategy}, got {actual_strategy} for {file_path}"
```

### Integration Test Patterns

```python
def test_progressive_configuration_levels():
    """Test all four configuration levels."""
    
    test_paths = [
        "/app/payment-service/requirements.txt",
        "/tools/ci-utils/poetry.lock",
        "/tests/integration/requirements.txt"
    ]
    
    # Level 1: Simple default
    config_simple = LocationAwareConfig()
    
    # Level 2: Organizational override
    config_org = LocationAwareConfig()
    config_org.set_organizational_override("conservative_stability")
    
    # Level 3: Location-aware (automatic)
    config_location = LocationAwareConfig()
    
    # Level 4: Custom configuration
    config_custom = LocationAwareConfig(Path("test-config.yml"))
    
    # Validate behavior for each level
    for path in test_paths:
        # Test each configuration level
        simple_strategy = config_simple.get_strategy_for_location(path)
        org_strategy = config_org.get_strategy_for_location(path)
        location_strategy = config_location.get_strategy_for_location(path)
        custom_strategy = config_custom.get_strategy_for_location(path)
        
        # Validate expected behavior
        assert org_strategy == "conservative_stability"  # Override works
        assert location_strategy in ['conservative_stability', 'rapid_development', 'balanced_security']
```

## Migration and Compatibility

### Backward Compatibility

All existing CLI commands continue to work unchanged:

```bash
# Existing usage (unchanged behavior)
sca-scanner .
sca-scanner . --recommendation-strategy balanced_security
sca-scanner . --custom-strategy my-strategy.yml

# New capabilities (additive)
sca-scanner . --location-config my-locations.yml
sca-scanner --create-location-config example.yml
```

### Migration Path

1. **Immediate**: Existing users get location-aware intelligence automatically
2. **Optional**: Users can explore new options with `--list-strategies`
3. **Advanced**: Users can create custom location configurations as needed
4. **Enterprise**: Full customization available for complex organizational needs

### API Stability

- **Guaranteed Stable**: All existing method signatures preserved
- **Additive Changes**: New optional parameters and return fields only
- **Deprecation Policy**: 12-month notice for any breaking changes
- **Version Compatibility**: Semantic versioning for all API changes

This complete API reference provides all necessary information for integrating with, extending, or rebuilding the Location-Aware SCA Recommendations system.