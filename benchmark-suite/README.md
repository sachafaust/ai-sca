# SCA Scanner Benchmark Suite

## Purpose

This benchmark suite provides controlled test cases specifically designed to validate SCA (Software Composition Analysis) tools. Each test case includes known vulnerabilities with documented expected results.

## Test Projects

### JavaScript Test Cases

#### 1. `js-direct-vulns` - Direct Dependency Vulnerabilities
Tests detection of vulnerabilities in directly declared dependencies.

**Known Vulnerabilities:**
- lodash@4.17.19 → CVE-2020-28500 (Prototype Pollution)
- minimist@0.0.8 → CVE-2020-7598 (Prototype Pollution)
- serialize-javascript@2.1.2 → CVE-2020-7660 (RCE)

**Expected Fixes:**
- lodash → 4.17.21
- minimist → 1.2.6
- serialize-javascript → 3.1.0

#### 2. `js-transitive-vulns` - Transitive Dependency Vulnerabilities
Tests detection through dependency chains.

**Setup:**
- express@4.17.0 (has vulnerable transitive dependencies)
- react-scripts@3.4.0 (complex dependency tree)

#### 3. `js-no-fix-available` - Vulnerabilities Without Direct Fixes
Tests handling of abandoned or unfixable packages.

### Python Test Cases

#### 1. `py-requirements-vulns` - Requirements.txt Vulnerabilities
Standard pip requirements with known issues.

**Known Vulnerabilities:**
- Django==2.2.10 → Multiple CVEs
- requests==2.19.1 → CVE-2018-18074
- PyYAML==5.1 → CVE-2020-1747

#### 2. `py-poetry-vulns` - Poetry/pyproject.toml Vulnerabilities
Modern Python packaging with vulnerabilities.

#### 3. `py-mixed-sources` - Multiple Dependency Sources
Tests handling of different Python package formats together.

## Running the Benchmark

### Quick Test
```bash
cd benchmark-suite
./run-benchmark.sh js-direct-vulns
```

### Full Suite
```bash
./run-benchmark.sh all
```

### Compare with Other Tools
```bash
# Run our scanner
sca-scanner scan js-direct-vulns/ --output results/our-scanner.json

# Run npm audit
cd js-direct-vulns && npm audit --json > ../results/npm-audit.json

# Run Snyk
snyk test --json > ../results/snyk.json

# Generate comparison report
python scripts/compare-results.py
```

## Expected Results Structure

Each test case includes an `expected-results.json` file:

```json
{
  "metadata": {
    "test_name": "js-direct-vulns",
    "description": "Direct dependency vulnerabilities in JavaScript",
    "created": "2024-01-15",
    "language": "javascript"
  },
  "expected_vulnerabilities": [
    {
      "package": "lodash",
      "current_version": "4.17.19",
      "vulnerability": {
        "cve": "CVE-2020-28500",
        "severity": "high",
        "description": "Prototype pollution vulnerability"
      },
      "remediation": {
        "fixed_version": "4.17.21",
        "breaking_changes": false,
        "update_command": "npm install lodash@4.17.21"
      }
    }
  ],
  "statistics": {
    "total_vulnerabilities": 3,
    "critical": 0,
    "high": 2,
    "medium": 1,
    "low": 0
  }
}
```

## Scoring System

### Detection Score (40 points)
- True Positive Rate: 0-20 points
- False Positive Rate: 0-10 points  
- False Negative Rate: 0-10 points

### Remediation Score (30 points)
- Correct Fix Version: 0-15 points
- Breaking Change Detection: 0-10 points
- Alternative Suggestions: 0-5 points

### Performance Score (20 points)
- Scan Speed: 0-10 points
- Resource Usage: 0-5 points
- API Efficiency: 0-5 points

### Unique Features (10 points)
- Batch Processing: 0-5 points
- Context Awareness: 0-5 points

**Total: 100 points**

## Tool Comparison Matrix

| Scanner | Detection | Remediation | Performance | Unique | Total |
|---------|-----------|-------------|-------------|--------|-------|
| Our Scanner | ? | ? | ? | ? | ? |
| Snyk | 38/40 | 28/30 | 15/20 | 5/10 | 86/100 |
| npm audit | 35/40 | 20/30 | 18/20 | 0/10 | 73/100 |
| Dependabot | 37/40 | 25/30 | 12/20 | 3/10 | 77/100 |

## Success Criteria

- **Minimum Viable Score**: 75/100
- **Target Score**: 85/100
- **Stretch Goal**: 90/100

## Notes

- All test cases use specific versions to ensure reproducibility
- CVE data frozen at creation time for consistent comparison
- Performance metrics normalized for hardware differences