# SCA Test Suites and Vulnerability Detection Benchmarks

## Overview

This document identifies projects and test suites specifically designed to test Software Composition Analysis (SCA) tools, vulnerability detection capabilities, and remediation recommendations.

## Specialized SCA Testing Projects

### 1. **Vulnerable Node (vulnerable-node)**
- **Repository**: https://github.com/cr0hn/vulnerable-node
- **Purpose**: Intentionally vulnerable Node.js application for testing SCA tools
- **Features**:
  - Known vulnerable versions of popular packages
  - Multiple vulnerability types (XSS, SQLi, RCE via dependencies)
  - Clear documentation of which vulnerabilities should be detected
- **Test Value**: Baseline for detection capabilities

### 2. **OWASP Dependency Track Test Suite**
- **Repository**: https://github.com/DependencyTrack/dependency-track
- **Purpose**: Includes test cases for validating SCA capabilities
- **Features**:
  - Standardized vulnerability test cases
  - Multiple language support
  - CVE mapping validation
- **Test Value**: Industry-standard test cases

### 3. **Snyk Vulnerability Database Test Cases**
- **Repository**: https://github.com/snyk/vulnerabilitydb
- **Purpose**: Public vulnerability test cases from Snyk
- **Features**:
  - Real CVE test cases
  - Proof of concept exploits
  - Fix validation scenarios
- **Test Value**: Commercial-grade test scenarios

### 4. **Damn Vulnerable Dependency (DVD)**
- **Repository**: https://github.com/dependency-check/DependencyCheck
- **Test Files**: Located in `/src/test/resources/`
- **Purpose**: OWASP Dependency-Check test suite
- **Features**:
  - Known vulnerable JARs, NPMs, and Python packages
  - Version-specific vulnerabilities
  - False positive test cases
- **Test Value**: Cross-language vulnerability detection

### 5. **SecurityLab Vulnerability Tests**
- **Repository**: https://github.com/github/securitylab
- **Purpose**: GitHub's security research test cases
- **Features**:
  - CodeQL queries for dependency vulnerabilities
  - Real-world CVE reproductions
  - Automated fix validation
- **Test Value**: Advanced detection patterns

## Purpose-Built Test Repositories

### 6. **Deliberately Vulnerable Dependency Trees**

#### **vulnerable-packages-demo**
```json
{
  "name": "vulnerable-packages-demo",
  "dependencies": {
    "lodash": "4.17.19",        // CVE-2020-28500 (Prototype Pollution)
    "minimist": "0.0.8",         // CVE-2020-7598 (Prototype Pollution)
    "serialize-javascript": "2.1.2", // CVE-2020-7660 (RCE)
    "kind-of": "6.0.2",          // CVE-2019-20149 (Type Confusion)
    "dot-prop": "4.2.0",         // CVE-2020-8116 (Prototype Pollution)
    "yargs-parser": "13.0.0",    // CVE-2020-7608 (Prototype Pollution)
    "ini": "1.3.5",              // CVE-2020-7788 (Prototype Pollution)
    "node-fetch": "2.6.0"        // CVE-2020-15168 (Size Limit Bypass)
  }
}
```

#### **vulnerable-python-requirements**
```txt
Django==2.2.10     # CVE-2020-7471, CVE-2020-9402
Flask==0.12.2      # CVE-2018-1000656, CVE-2019-1010083
requests==2.19.1   # CVE-2018-18074
PyYAML==5.1        # CVE-2020-1747
urllib3==1.24.1    # CVE-2019-11324, CVE-2020-26137
Jinja2==2.10       # CVE-2019-10906
Werkzeug==0.15.2   # CVE-2020-28724
cryptography==2.8  # CVE-2020-36242
```

### 7. **Fix Validation Test Suite**

Create test scenarios that validate both detection AND remediation:

```yaml
test_cases:
  - name: "Simple Direct Upgrade"
    vulnerable: "lodash@4.17.19"
    expected_fix: "lodash@4.17.21"
    breaking_changes: false
    
  - name: "Major Version Required"
    vulnerable: "minimist@0.0.8"
    expected_fix: "minimist@1.2.6"
    breaking_changes: true
    
  - name: "Transitive Dependency"
    parent: "express@4.17.0"
    vulnerable: "qs@6.7.0"
    expected_fix: "Update express to 4.17.3"
    
  - name: "No Fix Available"
    vulnerable: "abandoned-package@1.0.0"
    expected_fix: "No upgrade path - consider alternatives"
    
  - name: "Multiple Vulnerabilities"
    vulnerable: "django@2.2.10"
    cves: ["CVE-2020-7471", "CVE-2020-9402"]
    expected_fix: "django@3.2.18 or django@2.2.28"
```

## Benchmark Test Scenarios

### Scenario 1: Detection Accuracy
```bash
# Test: Can the scanner detect all known vulnerabilities?
git clone https://github.com/our-test/vulnerable-dependencies
cd vulnerable-dependencies

# Expected detections:
- 8 critical vulnerabilities
- 12 high severity
- 15 medium severity
- Specific CVEs: CVE-2020-28500, CVE-2020-7598, etc.
```

### Scenario 2: Fix Recommendations
```bash
# Test: Does the scanner recommend appropriate fixes?
For each vulnerability:
1. Is a fix available?
2. Is the recommended version correct?
3. Are breaking changes identified?
4. Are alternative packages suggested when no fix exists?
```

### Scenario 3: False Positive Rate
```bash
# Test: Does the scanner avoid false positives?
Test packages:
- Development-only dependencies that shouldn't be flagged
- Test frameworks (jest, pytest) - context matters
- Build tools that don't affect runtime
```

### Scenario 4: Transitive Dependency Handling
```bash
# Test: Can the scanner trace vulnerabilities through the dependency tree?
- Direct dependency: express@4.17.0
- Transitive vulnerability: qs@6.7.0 (via body-parser)
- Expected: Identify the path and recommend parent update
```

## Comparative Testing Framework

### Test Matrix

| Test Case | Our Scanner | Snyk | npm audit | Dependabot | GitHub Security |
|-----------|------------|------|-----------|------------|-----------------|
| Direct CVE Detection | ? | ✓ | ✓ | ✓ | ✓ |
| Transitive Detection | ? | ✓ | ✓ | ✓ | ✓ |
| Fix Recommendation | ? | ✓ | ✓ | ✓ | ✓ |
| Breaking Change Warning | ? | ✓ | ✗ | ✓ | ✓ |
| Alternative Suggestions | ? | ✓ | ✗ | ✗ | ✗ |
| Batch Processing | ? | ✗ | ✗ | ✗ | ✗ |
| Context-Aware | ? | Partial | ✗ | ✗ | Partial |

### Performance Metrics

```yaml
metrics:
  detection:
    - true_positives: Count of correctly identified vulnerabilities
    - false_positives: Count of incorrect vulnerability flags
    - false_negatives: Count of missed vulnerabilities
    - accuracy: (TP + TN) / (TP + TN + FP + FN)
    
  performance:
    - scan_time: Time to complete full scan
    - api_calls: Number of external API calls made
    - memory_usage: Peak memory consumption
    - token_usage: For AI-based scanner
    
  recommendations:
    - fix_accuracy: Percentage of correct fix versions
    - breaking_change_detection: Accuracy of breaking change warnings
    - alternative_suggestions: Quality of alternative package suggestions
```

## Implementation Approach

### Phase 1: Controlled Testing
1. Create our own test repository with known vulnerabilities
2. Document expected results for each test case
3. Run our scanner and compare results
4. Calculate accuracy metrics

### Phase 2: Standard Test Suites
1. Run against OWASP test cases
2. Compare with Dependency-Check results
3. Validate against Snyk's public test cases
4. Document any gaps

### Phase 3: Real-World Validation
1. Test on vulnerable-node project
2. Compare results with multiple SCA tools
3. Measure performance differences
4. Document unique capabilities

## Test Repository Structure

```
sca-benchmark-suite/
├── test-projects/
│   ├── javascript/
│   │   ├── direct-vulnerabilities/
│   │   │   ├── package.json
│   │   │   └── expected-results.json
│   │   ├── transitive-vulnerabilities/
│   │   │   ├── package.json
│   │   │   └── expected-results.json
│   │   └── mixed-vulnerabilities/
│   │       ├── package.json
│   │       └── expected-results.json
│   ├── python/
│   │   ├── requirements-vulnerabilities/
│   │   │   ├── requirements.txt
│   │   │   └── expected-results.json
│   │   ├── pyproject-vulnerabilities/
│   │   │   ├── pyproject.toml
│   │   │   └── expected-results.json
│   │   └── poetry-vulnerabilities/
│   │       ├── poetry.lock
│   │       └── expected-results.json
│   └── typescript/
│       └── [similar structure]
├── scripts/
│   ├── run-all-scanners.sh
│   ├── compare-results.py
│   └── generate-report.py
└── results/
    └── [scan results from different tools]
```

## Expected Results Format

```json
{
  "test_case": "direct-vulnerabilities-js",
  "expected": {
    "vulnerabilities": [
      {
        "package": "lodash",
        "version": "4.17.19",
        "cve": "CVE-2020-28500",
        "severity": "high",
        "fix_version": "4.17.21",
        "breaking_change": false
      }
    ],
    "total_count": 8,
    "critical": 2,
    "high": 3,
    "medium": 3
  },
  "scanner_results": {
    "our_scanner": { /* actual results */ },
    "snyk": { /* actual results */ },
    "npm_audit": { /* actual results */ }
  },
  "metrics": {
    "detection_rate": 0.95,
    "false_positive_rate": 0.02,
    "scan_time_ms": 1500
  }
}
```

## Quick Start Test

```bash
# Create a simple test case
mkdir sca-test && cd sca-test

# Create vulnerable package.json
cat > package.json << 'EOF'
{
  "name": "sca-test",
  "dependencies": {
    "lodash": "4.17.19",
    "minimist": "0.0.8"
  }
}
EOF

# Run our scanner
sca-scanner scan --output our-results.json

# Run npm audit for comparison
npm audit --json > npm-results.json

# Compare results
# Both should detect:
# - CVE-2020-28500 in lodash
# - CVE-2020-7598 in minimist
```

## Success Criteria

1. **Detection Parity**: Match or exceed detection rates of established tools
2. **Fix Accuracy**: 95%+ correct fix recommendations
3. **Performance**: 50% faster than sequential scanners on large projects
4. **Unique Value**: Demonstrate batch processing and context-aware advantages
5. **Cost Efficiency**: <$0.01 per 100 packages scanned

---

*This refined benchmark approach focuses on controlled, reproducible tests specifically designed to validate SCA capabilities, ensuring accurate comparison between our AI-powered scanner and traditional tools.*