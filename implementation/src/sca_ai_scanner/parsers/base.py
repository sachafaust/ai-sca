"""
Base dependency parser with common functionality.
Provides foundation for language-specific parsers.
"""

import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Set, Optional
import logging

from ..core.models import Package, SourceLocation, FileType
from ..exceptions import ParsingError

logger = logging.getLogger(__name__)


class DependencyParser(ABC):
    """
    Abstract base class for dependency parsers.
    Implements common functionality and defines interface for language-specific parsers.
    """
    
    def __init__(self, root_path: str):
        """Initialize parser with project root path."""
        self.root_path = Path(root_path).resolve()
        self.packages: Dict[str, Package] = {}
        self.supported_files: Set[str] = set()
        self.excluded_dirs = {
            '.git', '.svn', '.hg', '__pycache__', 'node_modules', 
            '.venv', 'venv', '.env', 'env', 'dist', 'build',
            '.pytest_cache', '.coverage', '.mypy_cache'
        }
    
    @abstractmethod
    def get_supported_files(self) -> Set[str]:
        """Return set of supported dependency file names."""
        pass
    
    @abstractmethod
    def parse_file(self, file_path: Path) -> List[Package]:
        """Parse a single dependency file and return packages."""
        pass
    
    @abstractmethod
    def get_ecosystem_name(self) -> str:
        """Return the ecosystem name (e.g., 'pypi', 'npm')."""
        pass
    
    def discover_dependency_files(self) -> List[Path]:
        """
        Discover all supported dependency files in the project.
        Implements recursive search with intelligent exclusions.
        """
        dependency_files = []
        supported_files = self.get_supported_files()
        
        logger.info(f"Discovering dependency files in {self.root_path}")
        
        for root, dirs, files in os.walk(self.root_path):
            # Remove excluded directories from search
            dirs[:] = [d for d in dirs if d not in self.excluded_dirs]
            
            root_path = Path(root)
            
            for file_name in files:
                if file_name in supported_files:
                    file_path = root_path / file_name
                    dependency_files.append(file_path)
                    logger.debug(f"Found dependency file: {file_path}")
        
        logger.info(f"Discovered {len(dependency_files)} dependency files")
        return dependency_files
    
    def parse_all_files(self) -> List[Package]:
        """
        Parse all discovered dependency files and return combined package list.
        Merges packages found in multiple files.
        """
        dependency_files = self.discover_dependency_files()
        
        if not dependency_files:
            logger.warning(f"No supported dependency files found in {self.root_path}")
            return []
        
        all_packages = {}
        
        for file_path in dependency_files:
            try:
                file_packages = self.parse_file(file_path)
                logger.info(f"Parsed {len(file_packages)} packages from {file_path}")
                
                # Merge packages, combining source locations
                for package in file_packages:
                    package_key = f"{package.name}:{package.version}"
                    
                    if package_key in all_packages:
                        # Merge source locations
                        existing_package = all_packages[package_key]
                        existing_package.source_locations.extend(package.source_locations)
                    else:
                        all_packages[package_key] = package
                        
            except Exception as e:
                logger.error(f"Failed to parse {file_path}: {e}")
                # Continue with other files
                continue
        
        unique_packages = list(all_packages.values())
        logger.info(f"Total unique packages: {len(unique_packages)}")
        
        return unique_packages
    
    def create_source_location(
        self, 
        file_path: Path, 
        line_number: int, 
        declaration: str,
        file_type: FileType
    ) -> SourceLocation:
        """Create a source location object with ABSOLUTE path for unambiguous file identification."""
        # Always use absolute path for clear identification by AI agents and users
        absolute_path = file_path.resolve()
        
        return SourceLocation(
            file_path=str(absolute_path),
            line_number=line_number,
            declaration=declaration.strip(),
            file_type=file_type
        )
    
    def validate_package_name(self, name: str) -> bool:
        """Validate package name format."""
        if not name or not name.strip():
            return False
        
        # Basic validation - can be extended per ecosystem
        return len(name.strip()) > 0
    
    def validate_version(self, version: str) -> bool:
        """Validate version format."""
        if not version or not version.strip():
            return False
        
        # Basic validation - can be extended per ecosystem
        return len(version.strip()) > 0
    
    def normalize_package_name(self, name: str) -> str:
        """Normalize package name for consistent comparison."""
        return name.strip().lower()
    
    def normalize_version(self, version: str) -> str:
        """Normalize version string."""
        # Remove common prefixes and clean up
        version = version.strip()
        
        # Remove version operators
        for prefix in ['>=', '<=', '==', '!=', '~=', '>', '<', '^', '~']:
            if version.startswith(prefix):
                version = version[len(prefix):].strip()
        
        # Remove any environment markers or conditions after semicolon
        if ';' in version:
            version = version.split(';')[0].strip()
        
        # Remove any remaining quotes
        version = version.strip('"\'')
        
        return version
    
    def should_include_package(self, name: str, version: str) -> bool:
        """
        Determine if package should be included in analysis.
        Override in subclasses for ecosystem-specific exclusions.
        """
        # Basic filters
        if not self.validate_package_name(name):
            return False
        
        if not self.validate_version(version):
            return False
        
        # Exclude development/test packages by default
        dev_indicators = [
            'test', 'dev', 'debug', 'mock', 'stub', 
            'example', 'sample', 'demo'
        ]
        
        name_lower = name.lower()
        if any(indicator in name_lower for indicator in dev_indicators):
            logger.debug(f"Excluding development package: {name}")
            return False
        
        return True
    
    def read_file_lines(self, file_path: Path) -> List[str]:
        """
        Read file lines with proper encoding handling.
        Returns empty list if file cannot be read.
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.readlines()
        except UnicodeDecodeError:
            # Try with fallback encoding
            try:
                with open(file_path, 'r', encoding='latin-1') as f:
                    return f.readlines()
            except Exception as e:
                logger.warning(f"Could not read {file_path} with latin-1 encoding: {e}")
                return []
        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")
            return []
    
    def extract_comment(self, line: str, comment_chars: List[str] = ['#']) -> Optional[str]:
        """Extract comment from line if present."""
        for comment_char in comment_chars:
            if comment_char in line:
                comment_start = line.find(comment_char)
                comment = line[comment_start + len(comment_char):].strip()
                return comment if comment else None
        return None
    
    def is_commented_line(self, line: str, comment_chars: List[str] = ['#']) -> bool:
        """Check if line is commented out."""
        stripped = line.strip()
        return any(stripped.startswith(char) for char in comment_chars)
    
    def get_parser_metadata(self) -> Dict[str, any]:
        """Get metadata about this parser for telemetry."""
        return {
            "parser_type": self.__class__.__name__,
            "ecosystem": self.get_ecosystem_name(),
            "supported_files": list(self.get_supported_files()),
            "root_path": str(self.root_path),
            "excluded_dirs": list(self.excluded_dirs)
        }