# Python Parser Validation - Product Design Requirements (PDR)

## 📖 Table of Contents

- [Overview](#overview)
- [Background](#background)
  - [Python Ecosystem Complexity](#python-ecosystem-complexity)
  - [Validation Targets](#validation-targets)
- [Python-Specific Requirements](#python-specific-requirements)
  - [Functional Requirements](#functional-requirements)
  - [Python-Specific Test Sources](#python-specific-test-sources)
  - [Implementation Plan](#implementation-plan)
  - [Success Criteria](#success-criteria)
  - [Python-Specific Code Structure](#python-specific-code-structure)
  - [Risk Assessment](#risk-assessment)
  - [Dependencies](#dependencies)
- [Implementation Status](#implementation-status)
- [Version History](#version-history)

## Overview

This PDR defines the Python-specific implementation for our parser validation system, focusing on validating our Python dependency parsers against established open source test suites. This document extends the main [Parser-Validation-PDR.md](./Parser-Validation-PDR.md) with Python-specific requirements and implementation details.

## Background

### Python Ecosystem Complexity

Python dependency management has evolved significantly, with multiple formats and tools:
- **requirements.txt** - Traditional pip format with complex syntax
- **pyproject.toml** - Modern standard (PEP 518, 621) with multiple specification formats
- **setup.py** - Legacy format with dynamic dependencies
- **setup.cfg** - Configuration-based format
- **Pipfile** - pipenv format with dependency groups
- **poetry.lock** - Poetry-specific lock file format

### Validation Targets

Our Python parser validation will focus on these established projects:

1. **pip-tools** - Requirements.txt parsing and compilation
2. **poetry** - pyproject.toml parsing and dependency resolution  
3. **setuptools** - setup.py and setup.cfg parsing
4. **pip** - Core requirements parsing logic
5. **pipenv** - Pipfile parsing and virtual environment management

## Python-Specific Requirements

### Functional Requirements

#### File Format Support
1. **requirements.txt Parsing**
   - Basic dependencies (`package==1.0.0`)
   - Complex version specifiers (`package>=1.0,<2.0,!=1.5`)
   - Environment markers (`package; python_version >= "3.8"`)
   - URL dependencies (`git+https://github.com/user/repo.git@branch`)
   - Editable installs (`-e git+https://...`)
   - Include directives (`-r other-requirements.txt`)
   - Index URLs (`-i https://pypi.org/simple/`)
   - Constraint files (`-c constraints.txt`)
   - Hash verification (`package==1.0 --hash=sha256:abc123`)

2. **pyproject.toml Parsing**
   - PEP 621 project metadata
   - Tool-specific dependency specifications (poetry, setuptools, etc.)
   - Optional dependencies (extras)
   - Development dependencies
   - Build system requirements

3. **setup.py Parsing**
   - Static dependency extraction
   - Dynamic dependency detection (limited scope)
   - Entry points and console scripts
   - Package metadata extraction

#### Edge Case Handling
- **Multi-line dependencies** with line continuations
- **Comments and inline comments** preservation/ignoring
- **Whitespace handling** in various formats
- **Case sensitivity** in package names
- **Unicode characters** in dependency specifications
- **Malformed files** graceful error handling

### Python-Specific Test Sources

#### pip-tools Test Suite Analysis

**Repository**: `https://github.com/jazzband/pip-tools`  
**Focus Areas**:
- `tests/test_resolver.py` - Dependency resolution edge cases
- `tests/test_cli_compile.py` - Requirements compilation scenarios
- `tests/test_repository_pypi.py` - PyPI interaction patterns
- `tests/test_data/` - Real-world package fixtures

**Key Test Categories**:
1. **Environment Markers**: `package==1.0; python_version >= "3.8"`
2. **Complex Constraints**: `package>=1.0,<2.0,!=1.5.0`
3. **URL Dependencies**: `git+https://github.com/user/repo.git@v1.0#egg=package`
4. **Editable Installs**: `-e git+https://...`
5. **Recursive Requirements**: `-r other-requirements.txt`
6. **Extras Handling**: `package[extra1,extra2]==1.0`
7. **Hash Verification**: Multi-line hash specifications
8. **Build Dependencies**: `--prefer-binary`, `--no-build-isolation`

#### poetry Test Suite Analysis

**Repository**: `https://github.com/python-poetry/poetry`  
**Focus Areas**:
- `tests/test_factory.py` - pyproject.toml parsing
- `tests/repositories/` - Package resolution tests
- `tests/fixtures/` - Real pyproject.toml files

**Key Test Categories**:
1. **Dependency Groups**: dev, test, docs groups
2. **Version Constraints**: Poetry-specific syntax (`^1.0`, `~1.1`)
3. **Source Dependencies**: Private indexes, git repositories
4. **Platform Dependencies**: OS and architecture specific
5. **Python Version Constraints**: Version range specifications

#### setuptools Test Suite Analysis

**Repository**: `https://github.com/pypa/setuptools`  
**Focus Areas**:
- `tests/test_setup_py.py` - setup.py parsing
- `tests/test_config.py` - setup.cfg parsing
- `tests/fixtures/` - Various setup configurations

**Key Test Categories**:
1. **Dynamic Dependencies**: Runtime dependency discovery
2. **Entry Points**: Console scripts and plugin definitions
3. **Package Data**: Include and exclude patterns
4. **Namespace Packages**: Modern and legacy formats

### Implementation Plan

#### Phase 1: pip-tools Integration (Week 1-2)
1. **Test Extraction**
   - Clone pip-tools repository at stable version (7.4.1)
   - Analyze test structure and identify relevant test cases
   - Extract 50-100 representative test cases covering core scenarios
   - Convert to standardized YAML format

2. **Parser Validation**
   - Implement PythonParserValidator class
   - Run extracted tests against our Python parser
   - Generate compatibility report
   - Document parsing differences and create improvement backlog

#### Phase 2: poetry Integration (Week 3-4)
1. **pyproject.toml Focus**
   - Extract poetry-specific test cases
   - Focus on PEP 621 compliance and poetry extensions
   - Test dependency group handling
   - Validate version constraint parsing

2. **Cross-validation**
   - Compare parsing results between pip-tools and poetry formats
   - Identify format-specific edge cases
   - Document intentional differences vs bugs

#### Phase 3: setuptools Integration (Week 5-6)
1. **Legacy Format Support**
   - Extract setup.py and setup.cfg test cases
   - Focus on static dependency extraction
   - Handle dynamic dependency scenarios
   - Test backward compatibility

#### Phase 4: Comprehensive Testing (Week 7-8)
1. **Integration Testing**
   - Run full test suite against our parser
   - Performance benchmarking
   - Memory usage analysis
   - Error handling validation

2. **Regression Testing**
   - Establish baseline compatibility scores
   - Create CI/CD integration
   - Set up automated regression detection

### Success Criteria

#### Quantitative Metrics
- **pip-tools compatibility**: 95%+ test pass rate
- **poetry compatibility**: 90%+ test pass rate (accounting for format differences)
- **setuptools compatibility**: 85%+ test pass rate (legacy format limitations)
- **Performance**: Parse 1000 dependencies/second
- **Memory**: <100MB peak usage for large dependency files

#### Qualitative Metrics
- **Edge Case Coverage**: Handle all major Python dependency patterns
- **Error Handling**: Graceful failures with actionable error messages
- **Documentation**: Complete catalog of parsing differences and rationale
- **Maintainability**: Clear test organization and update procedures

### Python-Specific Code Structure

```
parser-validation/languages/python/
├── __init__.py
├── sources/                          # Source project integrations
│   ├── pip_tools.py                 # pip-tools test extraction
│   │   ├── TestExtractor
│   │   ├── RequirementsTestExtractor
│   │   └── EdgeCaseExtractor
│   ├── poetry.py                    # poetry test extraction
│   │   ├── PyprojectTestExtractor
│   │   ├── DependencyGroupExtractor
│   │   └── VersionConstraintExtractor
│   ├── setuptools.py                # setuptools test extraction
│   │   ├── SetupPyExtractor
│   │   ├── SetupCfgExtractor
│   │   └── DynamicDepExtractor
│   └── pip_requirements_parser.py   # Alternative parser for comparison
├── extractors/                      # Test case extractors
│   ├── requirements_extractor.py    # requirements.txt parsing
│   ├── pyproject_extractor.py       # pyproject.toml parsing
│   ├── setup_py_extractor.py        # setup.py parsing
│   └── setup_cfg_extractor.py       # setup.cfg parsing
├── test-data/                       # Extracted test fixtures
│   ├── pip-tools/
│   │   ├── basic_parsing/
│   │   ├── environment_markers/
│   │   ├── url_dependencies/
│   │   └── hash_verification/
│   ├── poetry/
│   │   ├── dependency_groups/
│   │   ├── version_constraints/
│   │   └── source_dependencies/
│   ├── poetry-lock/                 # Poetry.lock specific tests
│   │   ├── test_cases.yaml          # Basic poetry.lock parsing
│   │   └── transitive_test_cases.yaml # Transitive dependency tests
│   ├── uv-lock/                     # UV.lock format tests  
│   │   └── test_cases.yaml          # UV.lock parsing tests
│   └── setuptools/
│       ├── setup_py_parsing/
│       ├── setup_cfg_parsing/
│       └── dynamic_dependencies/
├── validators/                      # Python-specific validation
│   ├── python_parser_validator.py   # Main validation logic
│   ├── requirements_validator.py    # requirements.txt validation
│   ├── pyproject_validator.py       # pyproject.toml validation
│   ├── setup_py_validator.py        # setup.py validation
│   └── compatibility_reporter.py    # Python-specific reporting
└── tests/                           # Unit tests for validation system
    ├── test_pip_tools_integration.py
    ├── test_poetry_integration.py
    ├── test_setuptools_integration.py
    └── test_cross_format_validation.py
```

### Risk Assessment

#### High Risk
- **Dynamic Dependencies**: setup.py files with runtime dependency resolution
- **Version Parsing Differences**: Subtle differences in version constraint interpretation
- **Environment Marker Evaluation**: Complex conditional dependency logic

#### Medium Risk  
- **Performance Impact**: Large dependency files causing timeout issues
- **Memory Usage**: Loading extensive test suites into memory
- **External Dependencies**: Test extraction requiring network access

#### Low Risk
- **Basic Parsing**: Well-established requirements.txt format
- **Static Dependencies**: Fixed dependency declarations
- **Format Validation**: Malformed file detection

### Dependencies

#### Internal Dependencies
- Main Parser Validation PDR framework
- Existing Python dependency parser implementation
- Common test format definitions
- Compatibility reporting utilities

#### External Dependencies
- Access to pip-tools, poetry, setuptools repositories
- Python 3.8+ for modern dependency parsing features
- PyYAML for test format conversion
- GitPython for repository cloning

## Implementation Approach

**Phase 1 - Core Validation Framework**:
1. Set up Python-specific validation directory structure with language isolation
2. Implement pip-tools test extractor with intelligent filtering (target: 20+ valid tests)
3. Create comprehensive test suite covering all pip-tools edge cases
4. Target **90%+ compatibility** against pip-tools validation
5. Enhance Python parser with full PEP 508 support:
   - Version constraint preservation (language-native format)
   - Extras parsing `package[extra1,extra2]`
   - Environment markers `package>=1.0; python_version>="3.8"`
   - Editable installs `-e git+https://...`
6. Update all unit tests to align with language-native formats
7. Validate on enterprise codebase: successfully scan 1,000+ packages

**Phase 2 - Semgrep Parity Analysis**:
1. Conduct comprehensive comparison with Semgrep commercial SCA tool
2. Target 95%+ parity rate with Semgrep Python package detection
3. Root cause analysis for any gaps:
   - Missing format support (uv.lock, poetry.lock)
   - Transitive dependency detection issues
   - Package exclusion logic problems
4. Create comprehensive test cases addressing identified gaps:
   - **uv.lock test cases**: Multiple scenarios covering basic parsing, transitive deps, source distributions, real-world examples
   - **Poetry.lock transitive test cases**: Scenarios targeting missing package detection, deep dependency chains, optional dependencies

**Phase 3 - Parser Enhancement**:
1. Update Python parser to support uv.lock format parsing
2. Enhance poetry.lock transitive dependency detection  
3. Refine package exclusion logic to prevent false negatives
4. Run comprehensive validation tests to achieve 100% Semgrep parity

## Target Quality Metrics

**Validation Targets**:
- **Unit Tests**: 100% passing for all parser components
- **pip-tools Validation**: 90%+ compatibility with pip-tools test suite
- **Gap Analysis Tests**: 100% passing for identified format gaps
- **Semgrep Parity**: 100% coverage of Python packages detected by Semgrep SCA
- **Real-World Validation**: Successfully process enterprise-scale codebases (1,000+ packages)

## Enhanced Format Support Requirements

**uv.lock Format Support**:
- Parse TOML-based lockfile from uv package manager (uv 0.4+)
- Support basic package declarations with name/version
- Handle dependency relationships and constraints
- Process source distributions and registry information
- Support real-world complex lock files

**poetry.lock Format Support**:
- Parse TOML-based lockfile from Poetry package manager
- Support package metadata (description, python-versions, files)
- Handle transitive dependency detection
- Process dependency groups and optional dependencies
- Support deprecated packages (e.g., py library)

**Parser Exclusion Logic Requirements**:
- Minimize false negatives for security scanning
- Retain packages with potential security implications
- Use conservative exclusion criteria focused only on pure development tools
- Avoid excluding testing frameworks, build tools, or runtime dependencies that may have vulnerabilities

**Validator Framework Enhancements**:
- Extend test format support for UV_LOCK and POETRY_LOCK file types
- Support new test categories (transitive_dependencies, deprecated_packages, real_world)
- Maintain backward compatibility with existing validation infrastructure

## Version History

| Version | Date | Changes | Author |
|---------|------|---------|---------|
| 1.0 | 2025-07-24 | Initial Python-specific PDR creation | AI Agent |
| 2.0 | 2025-07-25 | Enhanced with uv.lock/poetry.lock support, 100% Semgrep parity achieved | AI Agent |

---

*This PDR extends the main Parser Validation PDR with Python-specific implementation details, following the AI Agent First philosophy for systematic quality improvement.*