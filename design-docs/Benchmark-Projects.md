# Benchmark Projects for SCA Scanner Validation

## Overview

This document identifies open source projects suitable for benchmarking our AI-powered SCA scanner against traditional security tools like Snyk, Dependabot, GitHub Security, Semgrep, and others.

## Selection Criteria

### Ideal Characteristics
- **Known vulnerabilities**: Projects with documented security issues in dependencies
- **Multiple languages**: Mix of Python, JavaScript, and TypeScript
- **Various dependency formats**: Different package managers and lock files
- **Active maintenance**: Regular updates showing real-world usage
- **Reproducible**: Public repositories with clear dependency declarations
- **Different scales**: From small libraries to large applications

## Benchmark Categories

### 1. High-Profile Projects with Known Vulnerabilities

#### **Python Projects**

**Django (Older Versions)**
- Repository: https://github.com/django/django
- Why: Well-documented security history, complex dependencies
- Target: Django 3.0-3.2 branches (known vulnerabilities before patches)
- Dependencies: ~50-100 packages
- Formats: requirements.txt, setup.py

**Flask Ecosystem**
- Repository: https://github.com/pallets/flask
- Why: Popular framework with extension ecosystem
- Dependencies: Core is minimal but extensions add complexity
- Formats: setup.py, requirements.txt

**Ansible (Pre-2.10)**
- Repository: https://github.com/ansible/ansible
- Why: Large dependency tree, known CVEs in older versions
- Dependencies: 100+ packages
- Formats: requirements.txt, setup.py

#### **JavaScript/TypeScript Projects**

**Express.js Applications**
- Repository: https://github.com/expressjs/express
- Why: Most popular Node.js framework
- Known Issues: Older versions have prototype pollution vulnerabilities
- Formats: package.json, package-lock.json

**React (Create React App)**
- Repository: https://github.com/facebook/create-react-app
- Why: Complex dependency tree with frequent security updates
- Dependencies: 1000+ transitive dependencies
- Formats: package.json, yarn.lock

**Ghost CMS**
- Repository: https://github.com/TryGhost/Ghost
- Why: Real-world application with extensive dependencies
- Dependencies: 500+ packages
- Formats: package.json, yarn.lock

**Strapi CMS**
- Repository: https://github.com/strapi/strapi
- Why: Modern full-stack application
- Dependencies: Complex monorepo with multiple package.json files
- Formats: package.json, yarn.lock, lerna.json

### 2. Intentionally Vulnerable Applications

**OWASP NodeGoat**
- Repository: https://github.com/OWASP/NodeGoat
- Why: Designed to have vulnerabilities for testing
- Perfect for: Validation of detection capabilities
- Languages: JavaScript/Node.js

**OWASP Juice Shop**
- Repository: https://github.com/juice-shop/juice-shop
- Why: Modern vulnerable web application
- Dependencies: Intentionally outdated packages
- Languages: TypeScript, JavaScript

**Damn Vulnerable Python Web Application (DVPWA)**
- Repository: https://github.com/anxolerd/dvpwa
- Why: Python-based vulnerable app
- Dependencies: Outdated Flask and related packages

### 3. Large-Scale Real-World Projects

**Kubernetes Dashboard**
- Repository: https://github.com/kubernetes/dashboard
- Why: Enterprise-scale project
- Languages: TypeScript, Go
- Dependencies: Complex multi-language setup

**Jupyter Notebook**
- Repository: https://github.com/jupyter/notebook
- Why: Scientific computing standard
- Languages: Python, JavaScript
- Dependencies: Complex with scientific packages

**Sentry**
- Repository: https://github.com/getsentry/sentry
- Why: Large-scale production application
- Languages: Python, JavaScript, TypeScript
- Dependencies: 1000+ packages across languages

**GitLab CE**
- Repository: https://github.com/gitlabhq/gitlabhq
- Why: Massive application with multiple components
- Languages: Ruby, JavaScript (but good for comparison)
- Dependencies: Very complex dependency tree

### 4. Popular Libraries (Good for Transitive Dependency Testing)

**Requests (Python)**
- Repository: https://github.com/psf/requests
- Why: Most downloaded Python package
- Testing: Transitive vulnerability detection

**Lodash (JavaScript)**
- Repository: https://github.com/lodash/lodash
- Why: Historically had prototype pollution issues
- Testing: Version-specific vulnerability detection

**Moment.js (JavaScript)**
- Repository: https://github.com/moment/moment
- Why: Deprecated but still widely used
- Testing: Detection of deprecated/risky dependencies

## Benchmark Methodology

### Test Scenarios

1. **Fresh Scan Comparison**
   - Run our scanner vs traditional tools on same commit
   - Compare: vulnerabilities found, false positives, false negatives
   - Measure: scan time, API calls, cost

2. **Historical Vulnerability Detection**
   - Check out older versions with known CVEs
   - Verify all tools detect the issues
   - Compare severity assessments

3. **Dependency Update Recommendations**
   - Compare suggested fixes
   - Evaluate practicality of recommendations
   - Check for breaking change awareness

4. **Performance Metrics**
   ```
   For each project measure:
   - Scan time
   - Memory usage
   - API calls made
   - Token usage (for our scanner)
   - Cost (if applicable)
   ```

### Comparison Tools

**Free/Open Source:**
- npm audit (JavaScript)
- pip-audit (Python)
- safety (Python)
- GitHub Dependabot
- OWASP Dependency Check

**Commercial (Free Tiers):**
- Snyk
- Semgrep
- Sonatype Nancy
- WhiteSource Bolt

### Success Metrics

1. **Detection Rate**
   - True positive rate >= 95%
   - False positive rate < 5%
   - Coverage of OWASP Top 10 dependencies

2. **Performance**
   - Scan time < 50% of traditional sequential scanners
   - Cost per scan < $0.50 for projects with <1000 dependencies

3. **Unique Value**
   - Context-aware recommendations
   - Batch processing efficiency
   - AI-powered risk assessment

## Implementation Plan

### Phase 1: Small-Scale Validation (Week 1)
- [ ] Test on 5 small projects (<100 dependencies)
- [ ] Compare with npm audit and pip-audit
- [ ] Document all findings

### Phase 2: Medium-Scale Testing (Week 2)
- [ ] Test on Juice Shop, NodeGoat
- [ ] Compare with Snyk free tier
- [ ] Measure performance differences

### Phase 3: Large-Scale Benchmarking (Week 3-4)
- [ ] Test on Sentry, GitLab, Ghost
- [ ] Full comparison matrix
- [ ] Performance and cost analysis

### Phase 4: Report Generation
- [ ] Create comprehensive benchmark report
- [ ] Include visualizations and metrics
- [ ] Provide recommendations for improvement

## Expected Outcomes

1. **Validation**: Prove AI scanner matches or exceeds traditional tools
2. **Performance Data**: Concrete metrics on speed and efficiency
3. **Gap Analysis**: Identify any detection gaps to address
4. **Unique Strengths**: Highlight advantages of AI approach
5. **Cost Model**: Validate economic benefits

## Notes for Implementation

### Quick Start Commands

```bash
# Clone and scan a test project
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop
git checkout v12.0.0  # Version with known vulnerabilities

# Run our scanner
sca-scanner scan --output benchmark-results.json

# Compare with npm audit
npm audit --json > npm-audit-results.json

# Compare with Snyk
snyk test --json > snyk-results.json
```

### Data Collection Template

```json
{
  "project": "juice-shop",
  "version": "v12.0.0",
  "scan_date": "2024-01-XX",
  "results": {
    "our_scanner": {
      "vulnerabilities_found": 0,
      "scan_time_seconds": 0,
      "api_calls": 0,
      "tokens_used": 0,
      "estimated_cost": 0
    },
    "npm_audit": {
      "vulnerabilities_found": 0,
      "scan_time_seconds": 0
    },
    "snyk": {
      "vulnerabilities_found": 0,
      "scan_time_seconds": 0
    }
  }
}
```

## Repository Links for Quick Reference

### Priority Targets (Start Here)
1. https://github.com/juice-shop/juice-shop (Intentionally vulnerable)
2. https://github.com/OWASP/NodeGoat (Intentionally vulnerable)
3. https://github.com/django/django/tree/3.2 (Real-world, older version)
4. https://github.com/TryGhost/Ghost/tree/4.0.0 (Real-world, specific version)
5. https://github.com/facebook/create-react-app (Complex dependencies)

### Additional Targets
- https://github.com/expressjs/express
- https://github.com/pallets/flask
- https://github.com/jupyter/notebook
- https://github.com/ansible/ansible
- https://github.com/strapi/strapi

---

*This benchmark suite will provide comprehensive validation of our AI-powered SCA scanner against industry-standard tools, demonstrating both parity in detection capabilities and superiority in performance and cost-efficiency.*