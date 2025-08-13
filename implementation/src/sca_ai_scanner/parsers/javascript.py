"""
JavaScript/Node.js dependency parser for package.json, yarn.lock, and package-lock.json files.
Supports modern JavaScript package management formats.
"""

import json
from pathlib import Path
from typing import List, Set, Dict, Any, Optional
import logging

from .base import DependencyParser
from ..core.models import Package, SourceLocation, FileType
from ..exceptions import ParsingError

logger = logging.getLogger(__name__)


class JavaScriptParser(DependencyParser):
    """
    JavaScript/Node.js dependency parser supporting multiple package managers.
    Handles package.json, yarn.lock, package-lock.json, and pnpm-lock.yaml.
    """
    
    def get_supported_files(self) -> Set[str]:
        """Return set of supported JavaScript dependency files."""
        return {
            'package.json', 'yarn.lock', 'package-lock.json',
            'pnpm-lock.yaml', 'npm-shrinkwrap.json'
        }
    
    def get_ecosystem_name(self) -> str:
        """Return ecosystem name for JavaScript packages."""
        return "npm"
    
    def parse_file(self, file_path: Path) -> List[Package]:
        """Parse a JavaScript dependency file and extract packages."""
        if not file_path.exists():
            raise ParsingError(f"File not found: {file_path}", str(file_path))
        
        file_name = file_path.name
        
        if file_name == 'package.json':
            return self._parse_package_json(file_path)
        elif file_name == 'yarn.lock':
            return self._parse_yarn_lock(file_path)
        elif file_name in ['package-lock.json', 'npm-shrinkwrap.json']:
            return self._parse_npm_lock(file_path)
        elif file_name == 'pnpm-lock.yaml':
            return self._parse_pnpm_lock(file_path)
        else:
            logger.warning(f"Unsupported JavaScript file type: {file_name}")
            return []
    
    def _parse_package_json(self, file_path: Path) -> List[Package]:
        """Parse package.json files."""
        packages = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Parse different dependency sections
            dependency_sections = [
                'dependencies',
                'devDependencies', 
                'peerDependencies',
                'optionalDependencies'
            ]
            
            for section in dependency_sections:
                if section in data and isinstance(data[section], dict):
                    section_packages = self._parse_package_json_dependencies(
                        data[section], file_path, section
                    )
                    packages.extend(section_packages)
            
        except json.JSONDecodeError as e:
            raise ParsingError(f"Invalid JSON in package.json: {e}", str(file_path))
        except Exception as e:
            raise ParsingError(f"Failed to parse package.json: {e}", str(file_path))
        
        return packages
    
    def _parse_package_json_dependencies(
        self, 
        dependencies: Dict[str, str], 
        file_path: Path, 
        section: str
    ) -> List[Package]:
        """Parse dependencies section from package.json."""
        packages = []
        
        for name, version_spec in dependencies.items():
            if self.should_include_package(name, version_spec):
                # Normalize version specification
                normalized_version = self._normalize_npm_version(version_spec)
                
                source_location = self.create_source_location(
                    file_path, 1, f'"{name}": "{version_spec}"', FileType.PACKAGE_JSON
                )
                
                package = Package(
                    name=self.normalize_package_name(name),
                    version=normalized_version,
                    source_locations=[source_location],
                    ecosystem=self.get_ecosystem_name()
                )
                
                packages.append(package)
        
        return packages
    
    def _normalize_npm_version(self, version_spec: str) -> str:
        """Normalize npm version specification."""
        version = version_spec.strip()
        
        # Handle common npm version prefixes
        prefixes_to_remove = ['^', '~', '>=', '<=', '>', '<', '=']
        
        for prefix in prefixes_to_remove:
            if version.startswith(prefix):
                version = version[len(prefix):].strip()
                break
        
        # Handle version ranges (take first version)
        if ' - ' in version:
            version = version.split(' - ')[0].strip()
        elif '||' in version:
            version = version.split('||')[0].strip()
        
        # Handle git/url specifications
        if version.startswith(('git+', 'http:', 'https:', 'git:')):
            return "git"
        
        # Handle file: specifications
        if version.startswith('file:'):
            return "local"
        
        # Handle npm tag specifications
        if version in ['latest', 'next', 'beta', 'alpha', 'canary']:
            return version
        
        return version
    
    def _parse_yarn_lock(self, file_path: Path) -> List[Package]:
        """Parse yarn.lock files."""
        packages = []
        lines = self.read_file_lines(file_path)
        
        current_package = None
        current_version = None
        line_num = 0
        
        for line_num, line in enumerate(lines, 1):
            original_line = line
            line_stripped = line.strip()
            
            # Skip empty lines and comments
            if not line_stripped or line_stripped.startswith('#'):
                continue
            
            # Debug line processing
            logger.debug(f"Processing line {line_num}: '{repr(line)}'")
            logger.debug(f"  stripped: '{line_stripped}'")
            
            # Parse package entry (starts without indentation and ends with colon)
            if (not line.startswith(' ') and '@' in line_stripped and line_stripped.endswith(':') and 
                not line_stripped.startswith('resolved') and not line_stripped.startswith('integrity')):
                # Parse package name and version specification
                package_spec = line_stripped.split(':')[0].strip()
                # Remove quotes from package spec (yarn adds quotes around some entries)
                package_spec = package_spec.strip('"')
                current_package, current_version = self._parse_yarn_package_spec(package_spec)
                logger.debug(f"Found yarn package spec: {current_package}")
                continue
            
            # Parse resolved version (indented line with "version")
            if line.startswith('  version '):
                version_line = line.replace('  version ', '').strip(' "')
                logger.debug(f"Found version line: {version_line}, current_package: {current_package}")
                
                if current_package and self.should_include_package(current_package, version_line):
                    source_location = self.create_source_location(
                        file_path, line_num, original_line.strip(), FileType.YARN_LOCK
                    )
                    
                    package = Package(
                        name=self.normalize_package_name(current_package),
                        version=self.normalize_version(version_line),
                        source_locations=[source_location],
                        ecosystem=self.get_ecosystem_name()
                    )
                    
                    packages.append(package)
                    logger.debug(f"Added package: {current_package} -> {version_line}")
                else:
                    logger.debug(f"Excluded package: {current_package}")
                
                current_package = None
                current_version = None
        
        return packages
    
    def _parse_yarn_package_spec(self, package_spec: str) -> tuple[Optional[str], Optional[str]]:
        """Parse yarn package specification, handling multiple constraints."""
        
        # Handle multiple constraints: "react@^17.0.0, react@^17.0.1" -> extract "react"
        if ',' in package_spec:
            # Take the first constraint to extract the package name
            first_constraint = package_spec.split(',')[0].strip()
            package_spec = first_constraint
        
        # Handle scoped packages: @scope/package@version
        if package_spec.startswith('@'):
            # Find the second @ which indicates version
            at_positions = [i for i, char in enumerate(package_spec) if char == '@']
            if len(at_positions) >= 2:
                package_name = package_spec[:at_positions[1]]
                version_spec = package_spec[at_positions[1]+1:]
                return package_name, version_spec
            else:
                return package_spec, None
        else:
            # Regular package: package@version
            if '@' in package_spec:
                parts = package_spec.rsplit('@', 1)
                return parts[0], parts[1]
            else:
                return package_spec, None
    
    def _parse_npm_lock(self, file_path: Path) -> List[Package]:
        """Parse package-lock.json and npm-shrinkwrap.json files."""
        packages = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Parse dependencies from lock file
            if 'dependencies' in data:
                packages.extend(self._parse_lock_dependencies(
                    data['dependencies'], file_path, []
                ))
            
            # Handle lockfileVersion 2 and 3 format
            if 'packages' in data:
                packages.extend(self._parse_lock_packages(
                    data['packages'], file_path
                ))
            
        except json.JSONDecodeError as e:
            raise ParsingError(f"Invalid JSON in lock file: {e}", str(file_path))
        except Exception as e:
            raise ParsingError(f"Failed to parse lock file: {e}", str(file_path))
        
        return packages
    
    def _parse_lock_dependencies(
        self, 
        dependencies: Dict[str, Any], 
        file_path: Path, 
        path: List[str]
    ) -> List[Package]:
        """Parse dependencies from npm lock file (recursive)."""
        packages = []
        
        for name, dep_info in dependencies.items():
            if isinstance(dep_info, dict):
                version = dep_info.get('version', '')
                
                if version and self.should_include_package(name, version):
                    source_location = self.create_source_location(
                        file_path, 1, f"{'/'.join(path + [name])}: {version}", FileType.PACKAGE_JSON
                    )
                    
                    package = Package(
                        name=self.normalize_package_name(name),
                        version=self.normalize_version(version),
                        source_locations=[source_location],
                        ecosystem=self.get_ecosystem_name()
                    )
                    
                    packages.append(package)
                
                # Recursively parse nested dependencies
                if 'dependencies' in dep_info:
                    packages.extend(self._parse_lock_dependencies(
                        dep_info['dependencies'], file_path, path + [name]
                    ))
        
        return packages
    
    def _parse_lock_packages(self, packages_data: Dict[str, Any], file_path: Path) -> List[Package]:
        """Parse packages from npm lock file v2/v3 format."""
        packages = []
        
        for package_path, package_info in packages_data.items():
            if package_path == "":
                # Skip root package
                continue
            
            # Extract package name from path
            if package_path.startswith('node_modules/'):
                name = package_path.replace('node_modules/', '')
                # Handle nested dependencies
                if 'node_modules/' in name:
                    name = name.split('node_modules/')[-1]
            else:
                name = package_path
            
            version = package_info.get('version', '')
            
            if version and self.should_include_package(name, version):
                source_location = self.create_source_location(
                    file_path, 1, f"{package_path}: {version}", FileType.PACKAGE_JSON
                )
                
                package = Package(
                    name=self.normalize_package_name(name),
                    version=self.normalize_version(version),
                    source_locations=[source_location],
                    ecosystem=self.get_ecosystem_name()
                )
                
                packages.append(package)
        
        return packages
    
    def _parse_pnpm_lock(self, file_path: Path) -> List[Package]:
        """Parse pnpm-lock.yaml files."""
        packages = []
        
        try:
            import yaml
            
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            # Parse different sections
            if 'dependencies' in data:
                packages.extend(self._parse_pnpm_dependencies(
                    data['dependencies'], file_path, 'dependencies'
                ))
            
            if 'devDependencies' in data:
                packages.extend(self._parse_pnpm_dependencies(
                    data['devDependencies'], file_path, 'devDependencies'
                ))
            
            # Parse packages section for resolved versions
            if 'packages' in data:
                packages.extend(self._parse_pnpm_packages(
                    data['packages'], file_path
                ))
            
        except ImportError:
            logger.warning(f"PyYAML not available, skipping {file_path}")
        except Exception as e:
            raise ParsingError(f"Failed to parse pnpm-lock.yaml: {e}", str(file_path))
        
        return packages
    
    def _parse_pnpm_dependencies(
        self, 
        dependencies: Dict[str, str], 
        file_path: Path, 
        section: str
    ) -> List[Package]:
        """Parse dependencies from pnpm lock file."""
        packages = []
        
        for name, version_spec in dependencies.items():
            if self.should_include_package(name, version_spec):
                normalized_version = self._normalize_npm_version(version_spec)
                
                source_location = self.create_source_location(
                    file_path, 1, f"{section}.{name}: {version_spec}", FileType.YARN_LOCK
                )
                
                package = Package(
                    name=self.normalize_package_name(name),
                    version=normalized_version,
                    source_locations=[source_location],
                    ecosystem=self.get_ecosystem_name()
                )
                
                packages.append(package)
        
        return packages
    
    def _parse_pnpm_packages(self, packages_data: Dict[str, Any], file_path: Path) -> List[Package]:
        """Parse packages section from pnpm lock file."""
        packages = []
        
        for package_spec, package_info in packages_data.items():
            # Parse package specification: /@babel/core/7.12.9
            if package_spec.startswith('/'):
                spec_parts = package_spec[1:].split('/')
                if len(spec_parts) >= 2:
                    if spec_parts[0].startswith('@'):
                        # Scoped package
                        name = f"{spec_parts[0]}/{spec_parts[1]}"
                        version = spec_parts[2] if len(spec_parts) > 2 else ''
                    else:
                        # Regular package
                        name = spec_parts[0]
                        version = spec_parts[1] if len(spec_parts) > 1 else ''
                    
                    if version and self.should_include_package(name, version):
                        source_location = self.create_source_location(
                            file_path, 1, f"packages.{package_spec}", FileType.YARN_LOCK
                        )
                        
                        package = Package(
                            name=self.normalize_package_name(name),
                            version=self.normalize_version(version),
                            source_locations=[source_location],
                            ecosystem=self.get_ecosystem_name()
                        )
                        
                        packages.append(package)
        
        return packages
    
    def should_include_package(self, name: str, version: str) -> bool:
        """Override with JavaScript-specific exclusions."""
        if not super().should_include_package(name, version):
            return False
        
        # JavaScript-specific exclusions
        js_dev_packages = {
            'webpack', 'babel', 'eslint', 'prettier', 'jest', 'mocha',
            'chai', 'sinon', 'karma', 'jasmine', 'typescript', 'ts-node',
            'nodemon', 'concurrently', 'cross-env', 'rimraf', 'husky',
            'lint-staged', '@types/', 'parcel', 'rollup', 'vite'
        }
        
        name_lower = name.lower()
        
        # Check exact matches
        if name_lower in js_dev_packages:
            logger.debug(f"Excluding JavaScript development package: {name}")
            return False
        
        # Check for TypeScript type packages
        if name_lower.startswith('@types/'):
            logger.debug(f"Excluding TypeScript types package: {name}")
            return False
        
        # Check for common dev package patterns - but be more specific with @babel
        dev_patterns = ['webpack-', 'babel-', 'eslint-', '@webpack/']  # Removed @babel/ - too broad
        if any(pattern in name_lower for pattern in dev_patterns):
            logger.debug(f"Excluding development package: {name}")
            return False
        
        # More specific @babel exclusions (only dev-specific babel packages)
        babel_dev_packages = {
            '@babel/core', '@babel/cli', '@babel/node', '@babel/preset-env', '@babel/preset-react',
            '@babel/preset-typescript', '@babel/plugin-transform-runtime'
        }
        if name_lower in babel_dev_packages:
            logger.debug(f"Excluding Babel development package: {name}")
            return False
        
        return True