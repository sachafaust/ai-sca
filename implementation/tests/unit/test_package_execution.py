"""
Unit tests for package execution and entry points.
Ensures the package can be run as intended by users.
"""

import pytest
import subprocess
import sys
from pathlib import Path


class TestPackageExecution:
    """Test package can be executed properly."""
    
    def test_module_execution(self):
        """Test that package can be run with python -m sca_ai_scanner."""
        # Run the module with --help to test it's executable
        result = subprocess.run(
            [sys.executable, "-m", "sca_ai_scanner", "--help"],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0, f"Failed to run module: {result.stderr}"
        assert "AI-Powered SCA Vulnerability Scanner" in result.stdout
        assert "TARGET_PATH" in result.stdout
    
    def test_main_py_exists(self):
        """Test that __main__.py exists in the package."""
        package_root = Path(__file__).parent.parent.parent / "src" / "sca_ai_scanner"
        main_file = package_root / "__main__.py"
        
        assert main_file.exists(), "__main__.py is required for python -m execution"
        
        # Verify it imports and calls the CLI
        content = main_file.read_text()
        assert "from .cli import main" in content or "from sca_ai_scanner.cli import main" in content
        assert "main()" in content
    
    def test_console_script_entry_point(self):
        """Test that console script is properly configured in pyproject.toml."""
        pyproject_path = Path(__file__).parent.parent.parent / "pyproject.toml"
        content = pyproject_path.read_text()
        
        # Check for console scripts section
        assert "[project.scripts]" in content
        assert "sca-scanner" in content
        assert "sca_ai_scanner.cli:main" in content