# Config-Driven Recommendation Strategies

## Overview

This document describes the **config-driven recommendation strategy system** - a breakthrough implementation from our research that shifts focus from "data accuracy first" to "outcome accuracy first".

## The Problem We Solved

Traditional SCA scanners provide one-size-fits-all recommendations:
- "Upgrade to version X.Y.Z to fix vulnerabilities"
- No consideration of organizational constraints
- No context about trade-offs between security, stability, and effort

## Our Solution: Contextual Recommendations

Instead of single recommendations, we provide **multiple recommendation options** based on:

1. **Organizational Priorities** (security vs stability)
2. **Upgrade Constraints** (patch-only vs major versions)
3. **Effort Tolerance** (trivial vs complex changes)
4. **Business Context** (development vs production)

## Built-in Strategies

### 1. `balanced_security` (Default)
**Best for: Most organizations**
- Balances security improvements with stability
- Minor version upgrades allowed
- No breaking changes
- Medium effort tolerance

```bash
sca-scanner . --recommendation-strategy balanced_security
```

### 2. `conservative_stability`
**Best for: Production systems, legacy applications**
- Prioritizes stability over speed of fixes
- Patch-level upgrades only
- Zero downtime required
- Minimal effort changes

```bash
sca-scanner . --recommendation-strategy conservative_stability
```

### 3. `aggressive_security`
**Best for: High-security environments, zero-trust**
- Immediate security fixes regardless of breaking changes
- Major version upgrades allowed
- Complex changes acceptable
- Compliance mode enabled

```bash
sca-scanner . --recommendation-strategy aggressive_security
```

### 4. `rapid_development`
**Best for: Active development, CI/CD pipelines**
- Quick fixes that don't slow development
- Focus on critical/high severity only
- Low effort changes preferred
- Minimal disruption

```bash
sca-scanner . --recommendation-strategy rapid_development
```

## Custom Strategies

### JSON Schema for Strategy Configuration

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://sca-scanner.example.com/schemas/strategy-config.json",
  "title": "Recommendation Strategy Configuration Schema",
  "type": "object",
  "properties": {
    "name": {
      "type": "string",
      "description": "Strategy identifier (alphanumeric + underscores)",
      "pattern": "^[a-zA-Z][a-zA-Z0-9_]*$",
      "minLength": 1,
      "maxLength": 50
    },
    "description": {
      "type": "string",
      "description": "Human-readable strategy description",
      "minLength": 10,
      "maxLength": 200
    },
    "severity_priorities": {
      "type": "object",
      "description": "Priority mapping for vulnerability severities",
      "properties": {
        "critical": {
          "type": "string",
          "enum": ["immediate", "high", "medium", "low", "deferred"],
          "description": "Priority for critical vulnerabilities"
        },
        "high": {
          "type": "string", 
          "enum": ["immediate", "high", "medium", "low", "deferred"],
          "description": "Priority for high vulnerabilities"
        },
        "medium": {
          "type": "string",
          "enum": ["immediate", "high", "medium", "low", "deferred"], 
          "description": "Priority for medium vulnerabilities"
        },
        "low": {
          "type": "string",
          "enum": ["immediate", "high", "medium", "low", "deferred"],
          "description": "Priority for low vulnerabilities"
        }
      },
      "required": ["critical", "high", "medium", "low"],
      "additionalProperties": false
    },
    "upgrade_constraints": {
      "type": "object",
      "description": "Constraints on version upgrades",
      "properties": {
        "max_version_jump": {
          "type": "string",
          "enum": ["patch", "minor", "major", "any"],
          "description": "Maximum allowed version jump"
        },
        "allow_breaking_changes": {
          "type": "boolean",
          "description": "Whether breaking changes are acceptable"
        },
        "max_effort_level": {
          "type": "string",
          "enum": ["trivial", "low", "medium", "high", "complex"],
          "description": "Maximum effort level acceptable for upgrades"
        },
        "prefer_stable_releases": {
          "type": "boolean",
          "description": "Prefer stable/LTS releases over latest"
        }
      },
      "required": ["max_version_jump", "allow_breaking_changes", "max_effort_level", "prefer_stable_releases"],
      "additionalProperties": false
    },
    "minimum_fix_threshold": {
      "oneOf": [
        {"type": "null"},
        {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
      ],
      "description": "Only fix vulnerabilities at this severity and above (null = all)"
    },
    "batch_upgrades_preferred": {
      "type": "boolean",
      "description": "Prefer batching multiple upgrades together",
      "default": false
    },
    "zero_downtime_required": {
      "type": "boolean", 
      "description": "Require zero-downtime deployment approaches",
      "default": false
    },
    "compliance_mode": {
      "type": "boolean",
      "description": "Enable compliance-focused recommendations",
      "default": false
    }
  },
  "required": ["name", "description", "severity_priorities", "upgrade_constraints"],
  "additionalProperties": false
}
```

### Strategy Validation Usage

```python
import jsonschema
import yaml

def validate_strategy_config(strategy_path: Path) -> List[str]:
    """Validate strategy configuration against JSON Schema."""
    schema = load_strategy_config_schema()
    
    try:
        with open(strategy_path, 'r') as f:
            config = yaml.safe_load(f)
        
        jsonschema.validate(config, schema)
        
        # Additional business rule validation
        issues = []
        
        # Validate priority consistency
        priorities = config['severity_priorities']
        priority_order = ['immediate', 'high', 'medium', 'low', 'deferred']
        critical_priority = priority_order.index(priorities['critical'])
        high_priority = priority_order.index(priorities['high'])
        
        if critical_priority > high_priority:
            issues.append("Critical vulnerabilities should have higher priority than high vulnerabilities")
            
        # Validate effort vs version jump consistency
        constraints = config['upgrade_constraints']
        if constraints['max_version_jump'] == 'major' and constraints['max_effort_level'] == 'trivial':
            issues.append("Major version upgrades cannot have trivial effort level")
            
        return issues
        
    except jsonschema.ValidationError as e:
        return [f"Strategy validation error: {e.message}"]
    except yaml.YAMLError as e:
        return [f"YAML parsing error: {e}"]
    except Exception as e:
        return [f"Unexpected error: {e}"]
```

### Creating Custom Strategies

Create custom YAML files for your specific organizational needs:

```yaml
# my-strategy.yml
name: "my_custom_strategy"
description: "Custom strategy for our organization"

severity_priorities:
  critical: "immediate"
  high: "high"
  medium: "medium"
  low: "deferred"

upgrade_constraints:
  max_version_jump: "minor"
  allow_breaking_changes: false
  max_effort_level: "medium"
  prefer_stable_releases: true

minimum_fix_threshold: "HIGH"
batch_upgrades_preferred: true
zero_downtime_required: true
```

Use with:
```bash
sca-scanner . --custom-strategy ./my-strategy.yml
```

## Example Output

### Same Package, Different Strategies

**Package**: `django:3.2.12` with 4 CVEs (2 critical, 1 high, 1 medium)

#### Conservative Strategy Output:
```json
{
  "package": "django:3.2.12",
  "current_risk": "CRITICAL",
  "recommendation_options": [
    {
      "strategy": "conservative_stability",
      "action": "patch",
      "target_version": "3.2.25",
      "effort": "low",
      "fixes": "2 critical CVEs",
      "remaining_risk": "medium",
      "breaking_changes": "none",
      "recommendation": "Safe patch-level fix for critical issues"
    }
  ],
  "default_choice": "patch",
  "reasoning": "Addresses critical vulnerabilities with minimal stability risk"
}
```

#### Aggressive Strategy Output:
```json
{
  "package": "django:3.2.12", 
  "current_risk": "CRITICAL",
  "recommendation_options": [
    {
      "strategy": "aggressive_security",
      "action": "upgrade",
      "target_version": "4.2.15",
      "effort": "high",
      "fixes": "all 4 CVEs",
      "remaining_risk": "none",
      "breaking_changes": "moderate",
      "recommendation": "Complete security resolution - upgrade to Django 4.x"
    }
  ],
  "default_choice": "upgrade",
  "reasoning": "Zero remaining vulnerabilities outweighs upgrade complexity"
}
```

## CLI Integration

### List Available Strategies
```bash
sca-scanner --list-strategies
```

### Use Specific Strategy
```bash
sca-scanner /path/to/project --recommendation-strategy aggressive_security
```

### Use Custom Strategy
```bash
sca-scanner /path/to/project --custom-strategy ./strategies/my-company.yml
```

### Configuration File Support
```yaml
# sca_ai_config.yml
recommendation_strategy: "balanced_security"
custom_strategy_path: "./strategies/my-team.yml"
```

## Key Benefits

### 1. **Organizational Alignment**
Recommendations match your organization's risk tolerance and operational constraints.

### 2. **Context-Aware Decisions**
Same vulnerability data → Different recommendations based on context.

### 3. **Multiple Options**
See trade-offs between different approaches (quick patch vs comprehensive upgrade).

### 4. **Business Justification**
Each recommendation includes business reasoning and effort estimates.

### 5. **Extensible**
Create custom strategies for your specific needs without code changes.

## Implementation Architecture

```
┌─────────────────────┐
│   CLI Interface     │
│  --strategy option  │
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│  StrategyManager    │
│ - Built-in strategies
│ - Custom YAML loader │
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│ RecommendationEngine│
│ - CVE analysis      │
│ - Option generation │
│ - Trade-off scoring │
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│ Multiple Options    │
│ - Security impact   │
│ - Stability risk    │
│ - Effort estimate   │
│ - Business justific.│
└─────────────────────┘
```

## Research Foundation

This implementation is based on our research findings:

1. **Decision Convergence**: 100% of remediation decisions converged despite 53.8% CVE data reduction
2. **Outcome Focus**: Correct remediation matters more than complete CVE enumeration  
3. **Context Matters**: Organizational constraints significantly impact optimal recommendations
4. **AI Variance**: Structured approaches more reliable than deterministic settings

## Future Enhancements

- **Machine Learning**: Learn from organizational decision patterns
- **Integration Points**: Connect with ticketing systems, CI/CD pipelines
- **Risk Modeling**: Advanced business risk calculations
- **Compliance Mapping**: Automatic compliance requirement detection

## Getting Started

1. **Basic Usage**: Start with `balanced_security` (default)
2. **Evaluate Context**: Assess your organization's priorities
3. **Choose Strategy**: Select or create strategy matching your needs
4. **Iterate**: Refine based on real-world feedback

```bash
# Start with defaults
sca-scanner .

# List options
sca-scanner --list-strategies

# Try different strategies
sca-scanner . --recommendation-strategy conservative_stability
sca-scanner . --recommendation-strategy aggressive_security

# Create custom strategy for your team
cp strategies/balanced_security.yml my-team.yml
# Edit my-team.yml for your needs
sca-scanner . --custom-strategy my-team.yml
```

This system transforms vulnerability scanning from a data collection exercise into a **strategic decision support tool** aligned with your organization's priorities and constraints.