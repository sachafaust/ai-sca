"""
Unit tests for dependency parsers.
Tests Python and JavaScript file parsing with error handling.
"""

import pytest
from pathlib import Path

from sca_ai_scanner.parsers.python import PythonParser
from sca_ai_scanner.parsers.javascript import JavaScriptParser
from sca_ai_scanner.core.models import FileType
from sca_ai_scanner.exceptions import ParsingError


class TestPythonParser:
    """Test Python dependency parser."""
    
    @pytest.fixture
    def parser(self, temp_project_dir):
        """Create Python parser instance."""
        return PythonParser(str(temp_project_dir))
    
    def test_parse_requirements_txt(self, parser, temp_project_dir, create_test_files):
        """Test parsing requirements.txt files."""
        # Create test file
        create_test_files(temp_project_dir, {
            "requirements.txt": """
requests==2.25.1
django>=3.2.0,<4.0.0
numpy==1.21.0
# This is a comment
pytest==6.2.4  # inline comment

# Empty lines should be ignored

-r requirements-dev.txt
"""
        })
        
        packages = parser.parse_file(temp_project_dir / "requirements.txt")
        
        # Verify parsed packages
        assert len(packages) == 4  # Excluding pytest (dev package)
        
        # Check specific packages
        package_dict = {pkg.name: pkg for pkg in packages}
        
        assert "requests" in package_dict
        assert package_dict["requests"].version == "==2.25.1"  # Language-native format
        assert package_dict["requests"].source_locations[0].line_number == 2
        
        assert "django" in package_dict
        assert package_dict["django"].version == ">=3.2.0"  # Language-native with first constraint
        
        assert "numpy" in package_dict
        assert package_dict["numpy"].version == "==1.21.0"  # Language-native format
    
    def test_parse_pyproject_toml(self, parser, temp_project_dir, create_test_files):
        """Test parsing pyproject.toml files."""
        create_test_files(temp_project_dir, {
            "pyproject.toml": """
[build-system]
requires = ["setuptools>=61.0", "wheel"]

[project]
name = "test-project"
dependencies = [
    "fastapi>=0.68.0",
    "uvicorn[standard]>=0.15.0",
    "pydantic>=1.8.0"
]

[project.optional-dependencies]
dev = [
    "pytest>=6.0.0",
    "mypy>=0.910"
]

[tool.poetry.dependencies]
python = "^3.9"
click = "^8.0.0"
rich = "^10.0.0"
"""
        })
        
        packages = parser.parse_file(temp_project_dir / "pyproject.toml")
        
        # Should parse project.dependencies and tool.poetry.dependencies
        package_names = {pkg.name for pkg in packages}
        assert "fastapi" in package_names
        assert "uvicorn" in package_names
        assert "pydantic" in package_names
        assert "click" in package_names
        assert "rich" in package_names
        
        # Dev dependencies should be excluded
        assert "pytest" not in package_names
        assert "mypy" not in package_names
    
    def test_parse_setup_py(self, parser, temp_project_dir, create_test_files):
        """Test parsing setup.py files."""
        create_test_files(temp_project_dir, {
            "setup.py": """
from setuptools import setup

setup(
    name="test-project",
    install_requires=[
        "click>=8.0.0",
        "rich>=10.0.0",
        "requests==2.28.0"
    ],
    setup_requires=[
        "wheel"
    ]
)
"""
        })
        
        packages = parser.parse_file(temp_project_dir / "setup.py")
        
        package_names = {pkg.name for pkg in packages}
        assert "click" in package_names
        assert "rich" in package_names
        assert "requests" in package_names
        
        # setup_requires should be excluded (build dependency)
        assert "wheel" not in package_names
    
    def test_parse_invalid_file(self, parser, temp_project_dir, create_test_files):
        """Test parsing invalid/corrupted files."""
        # Test missing file
        with pytest.raises(ParsingError) as exc_info:
            parser.parse_file(temp_project_dir / "nonexistent.txt")
        assert "File not found" in str(exc_info.value)
        
        # Test invalid TOML
        create_test_files(temp_project_dir, {
            "pyproject.toml": """
[invalid toml
missing bracket
"""
        })
        
        with pytest.raises(ParsingError) as exc_info:
            parser.parse_file(temp_project_dir / "pyproject.toml")
        assert "Failed to parse" in str(exc_info.value)
    
    def test_discover_dependency_files(self, parser, temp_project_dir, create_test_files):
        """Test discovering all Python dependency files."""
        # Create multiple files
        create_test_files(temp_project_dir, {
            "requirements.txt": "requests==2.25.1",
            "requirements-dev.txt": "pytest==6.0.0",
            "backend/requirements.txt": "django==3.2.0",
            "frontend/package.json": "{}",  # Should be ignored
            "pyproject.toml": "[project]\nname = 'test'"
        })
        
        files = parser.discover_dependency_files()
        file_names = {f.name for f in files}
        
        assert "requirements.txt" in file_names
        assert "requirements-dev.txt" in file_names
        assert "pyproject.toml" in file_names
        assert "package.json" not in file_names  # Not a Python file
        
        # Should find nested files too
        assert any("backend" in str(f) for f in files)
    
    def test_version_preservation(self, parser, temp_project_dir, create_test_files):
        """Test version constraint preservation (language-native format)."""
        create_test_files(temp_project_dir, {
            "requirements.txt": """
pkg1>=1.0.0
pkg2~=2.0.0
pkg3>3.0.0,<4.0.0
pkg4==4.0.0
pkg5>=5.0.0
"""
        })
        
        packages = parser.parse_file(temp_project_dir / "requirements.txt")
        
        # Version operators should be preserved (language-native format)
        package_dict = {pkg.name: pkg for pkg in packages}
        
        assert package_dict["pkg1"].version == ">=1.0.0"
        assert package_dict["pkg2"].version == "~=2.0.0" 
        assert package_dict["pkg3"].version == ">3.0.0"  # First constraint only
        assert package_dict["pkg4"].version == "==4.0.0"
        assert package_dict["pkg5"].version == ">=5.0.0"


class TestJavaScriptParser:
    """Test JavaScript dependency parser."""
    
    @pytest.fixture
    def parser(self, temp_project_dir):
        """Create JavaScript parser instance."""
        return JavaScriptParser(str(temp_project_dir))
    
    def test_parse_package_json(self, parser, temp_project_dir, create_test_files):
        """Test parsing package.json files."""
        create_test_files(temp_project_dir, {
            "package.json": """{
  "name": "test-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.17.1",
    "lodash": "4.17.20",
    "axios": ">=0.21.0",
    "react": "~17.0.2"
  },
  "devDependencies": {
    "jest": "^27.0.0",
    "webpack": "^5.38.0",
    "@types/node": "^16.0.0"
  },
  "peerDependencies": {
    "react-dom": "^17.0.0"
  }
}"""
        })
        
        packages = parser.parse_file(temp_project_dir / "package.json")
        
        # Check dependencies are parsed
        package_names = {pkg.name for pkg in packages}
        assert "express" in package_names
        assert "lodash" in package_names
        assert "axios" in package_names
        assert "react" in package_names
        assert "react-dom" in package_names
        
        # Dev dependencies should be excluded
        assert "jest" not in package_names
        assert "webpack" not in package_names
        assert "@types/node" not in package_names
        
        # Check version normalization
        package_dict = {pkg.name: pkg for pkg in packages}
        assert package_dict["express"].version == "4.17.1"
        assert package_dict["lodash"].version == "4.17.20"
    
    def test_parse_yarn_lock(self, parser, temp_project_dir, create_test_files):
        """Test parsing yarn.lock files."""
        create_test_files(temp_project_dir, {
            "yarn.lock": """
# yarn lockfile v1

express@^4.17.1:
  version "4.17.1"
  resolved "https://registry.yarnpkg.com/express/-/express-4.17.1.tgz"
  integrity sha512-mHJ9O79RqluphRrcw2X/GTh3k9tVv8YcoyY4Kkh4WDMUYKRZUq0h1o0w2rrrxBqM7VoeUVqgb27xlEMXTnYt4g==
  dependencies:
    accepts "~1.3.7"
    array-flatten "1.1.1"

"@babel/core@^7.12.0":
  version "7.12.9"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.12.9.tgz"
  
lodash@4.17.20, lodash@^4.17.19:
  version "4.17.20"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz"
"""
        })
        
        packages = parser.parse_file(temp_project_dir / "yarn.lock")
        
        package_dict = {pkg.name: pkg for pkg in packages}
        
        assert "express" in package_dict
        assert package_dict["express"].version == "4.17.1"
        
        # @babel/core should be excluded as dev dependency
        assert "@babel/core" not in package_dict
        
        assert "lodash" in package_dict
        assert package_dict["lodash"].version == "4.17.20"
    
    def test_parse_package_lock_json(self, parser, temp_project_dir, create_test_files):
        """Test parsing package-lock.json files."""
        create_test_files(temp_project_dir, {
            "package-lock.json": """{
  "name": "test-app",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "packages": {
    "": {
      "name": "test-app",
      "version": "1.0.0"
    },
    "node_modules/express": {
      "version": "4.17.1",
      "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz"
    },
    "node_modules/@types/node": {
      "version": "16.0.0",
      "dev": true
    }
  },
  "dependencies": {
    "express": {
      "version": "4.17.1",
      "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz"
    }
  }
}"""
        })
        
        packages = parser.parse_file(temp_project_dir / "package-lock.json")
        
        package_names = {pkg.name for pkg in packages}
        assert "express" in package_names
        
        # Dev dependencies should be excluded
        assert "@types/node" not in package_names
    
    def test_npm_version_normalization(self, parser):
        """Test NPM-specific version normalization."""
        test_cases = [
            ("^1.2.3", "1.2.3"),
            ("~1.2.3", "1.2.3"),
            (">=1.2.3", "1.2.3"),
            ("1.2.3 - 2.0.0", "1.2.3"),
            ("1.2.3 || 2.0.0", "1.2.3"),
            ("git+https://github.com/user/repo.git", "git"),
            ("file:../local-package", "local"),
            ("latest", "latest"),
            ("next", "next")
        ]
        
        for input_version, expected in test_cases:
            normalized = parser._normalize_npm_version(input_version)
            assert normalized == expected
    
    def test_scoped_package_parsing(self, parser, temp_project_dir, create_test_files):
        """Test parsing scoped npm packages."""
        create_test_files(temp_project_dir, {
            "package.json": """{
  "dependencies": {
    "@babel/core": "^7.12.0",
    "@types/react": "^17.0.0",
    "@company/private-package": "1.0.0"
  }
}"""
        })
        
        packages = parser.parse_file(temp_project_dir / "package.json")
        
        package_names = {pkg.name for pkg in packages}
        # @babel packages are excluded as dev dependencies
        assert "@babel/core" not in package_names
        assert "@company/private-package" in package_names
        
        # @types packages should be excluded
        assert "@types/react" not in package_names
