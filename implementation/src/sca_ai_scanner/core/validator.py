"""
Hybrid validation pipeline for AI vulnerability findings.
Cross-validates critical findings against authoritative databases.
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
import logging
import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential

from .models import (
    CVEFinding, PackageAnalysis, VulnerabilityResults, 
    Severity, Package
)
from ..exceptions import ValidationError

logger = logging.getLogger(__name__)


class ValidationPipeline:
    """
    Hybrid validation system for AI vulnerability findings.
    Validates critical findings against traditional vulnerability databases.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize validation pipeline with configuration."""
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Validation thresholds
        self.validate_critical = config.get('validate_critical', True)
        self.validate_high = config.get('validate_high', True)
        self.spot_check_medium = config.get('spot_check_medium', True)
        self.spot_check_ratio = config.get('spot_check_ratio', 0.2)  # 20% of medium findings
        
        # Database endpoints
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.osv_base_url = "https://api.osv.dev/v1"
        self.github_base_url = "https://api.github.com/advisories"
        
        # Rate limiting
        self.request_delay = config.get('request_delay', 1.0)  # Seconds between requests
        self.max_concurrent = config.get('max_concurrent_validations', 5)
        
        # Cache for validation results
        self.validation_cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl = timedelta(hours=6)  # Cache for 6 hours
        
        logger.info("Initialized validation pipeline")
    
    async def __aenter__(self):
        """Async context manager entry."""
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session and hasattr(self.session, 'close'):
            try:
                await self.session.close()
            except TypeError:
                # Handle mock objects in tests that don't have proper async close
                pass
    
    async def validate_findings(self, results: VulnerabilityResults) -> VulnerabilityResults:
        """
        Validate AI findings against authoritative vulnerability databases.
        Updates confidence scores and adds validation metadata.
        """
        if not self.session:
            raise ValidationError("Validation session not initialized")
        
        logger.info(f"Starting validation of {len(results.vulnerability_analysis)} packages")
        
        # Collect findings that need validation
        findings_to_validate = self._collect_findings_for_validation(results)
        
        if not findings_to_validate:
            logger.info("No findings require validation")
            return results
        
        logger.info(f"Validating {len(findings_to_validate)} findings")
        
        # Create semaphore for concurrent request limiting
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        # Validate findings concurrently
        validation_tasks = []
        for pkg_id, cve_finding in findings_to_validate:
            task = self._validate_single_finding(semaphore, pkg_id, cve_finding)
            validation_tasks.append(task)
        
        # Execute validations
        validation_results = await asyncio.gather(*validation_tasks, return_exceptions=True)
        
        # Process validation results
        validated_count = 0
        for i, result in enumerate(validation_results):
            if isinstance(result, Exception):
                logger.warning(f"Validation failed for finding {i}: {result}")
                continue
            
            pkg_id, cve_id, validation_data = result
            if validation_data:
                self._update_finding_with_validation(results, pkg_id, cve_id, validation_data)
                validated_count += 1
        
        logger.info(f"Successfully validated {validated_count} findings")
        
        # Update results metadata
        results.scan_metadata['validation'] = {
            'validated_findings': validated_count,
            'total_findings': len(findings_to_validate),
            'validation_timestamp': datetime.utcnow().isoformat()
        }
        
        return results
    
    def _collect_findings_for_validation(
        self, 
        results: VulnerabilityResults
    ) -> List[tuple[str, CVEFinding]]:
        """Collect findings that need validation based on severity and sampling."""
        findings_to_validate = []
        
        for pkg_id, analysis in results.vulnerability_analysis.items():
            for cve in analysis.cves:
                should_validate = False
                
                # Always validate critical and high severity
                if cve.severity in [Severity.CRITICAL, Severity.HIGH]:
                    if (cve.severity == Severity.CRITICAL and self.validate_critical) or \
                       (cve.severity == Severity.HIGH and self.validate_high):
                        should_validate = True
                
                # Spot check medium severity findings
                elif cve.severity == Severity.MEDIUM and self.spot_check_medium:
                    import random
                    if random.random() < self.spot_check_ratio:
                        should_validate = True
                
                # Always validate findings with low confidence
                elif analysis.confidence < 0.8:
                    should_validate = True
                
                if should_validate:
                    findings_to_validate.append((pkg_id, cve))
        
        return findings_to_validate
    
    async def _validate_single_finding(
        self, 
        semaphore: asyncio.Semaphore, 
        pkg_id: str, 
        cve_finding: CVEFinding
    ) -> tuple[str, str, Optional[Dict[str, Any]]]:
        """Validate a single CVE finding against multiple databases."""
        async with semaphore:
            try:
                # Check cache first
                cache_key = f"{pkg_id}:{cve_finding.id}"
                cached_result = self._get_cached_validation(cache_key)
                if cached_result:
                    return pkg_id, cve_finding.id, cached_result
                
                # Validate against multiple sources
                validation_data = await self._cross_validate_cve(pkg_id, cve_finding)
                
                # Cache result
                if validation_data:
                    self._cache_validation_result(cache_key, validation_data)
                
                # Add delay to respect rate limits
                await asyncio.sleep(self.request_delay)
                
                return pkg_id, cve_finding.id, validation_data
                
            except Exception as e:
                logger.error(f"Failed to validate {cve_finding.id} for {pkg_id}: {e}")
                return pkg_id, cve_finding.id, None
    
    async def _cross_validate_cve(
        self, 
        pkg_id: str, 
        cve_finding: CVEFinding
    ) -> Optional[Dict[str, Any]]:
        """Cross-validate CVE against multiple authoritative sources."""
        validation_sources = []
        
        # Try NVD first (most authoritative)
        nvd_data = await self._validate_against_nvd(cve_finding.id)
        if nvd_data:
            validation_sources.append(('nvd', nvd_data))
        
        # Try OSV.dev
        package_name = pkg_id.split(':')[0]
        osv_data = await self._validate_against_osv(package_name, cve_finding.id)
        if osv_data:
            validation_sources.append(('osv', osv_data))
        
        # Try GitHub Security Advisories
        github_data = await self._validate_against_github(cve_finding.id)
        if github_data:
            validation_sources.append(('github', github_data))
        
        if not validation_sources:
            return None
        
        # Merge validation data from multiple sources
        return self._merge_validation_sources(validation_sources, cve_finding)
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    async def _validate_against_nvd(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Validate CVE against NIST NVD database."""
        try:
            url = f"{self.nvd_base_url}?cveId={cve_id}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if data.get('totalResults', 0) > 0:
                        cve_data = data['vulnerabilities'][0]['cve']
                        
                        return {
                            'source': 'nvd',
                            'cve_id': cve_id,
                            'description': self._extract_nvd_description(cve_data),
                            'cvss_score': self._extract_nvd_cvss_score(cve_data),
                            'severity': self._extract_nvd_severity(cve_data),
                            'published_date': cve_data.get('published'),
                            'last_modified': cve_data.get('lastModified'),
                            'references': self._extract_nvd_references(cve_data),
                            'validated': True
                        }
                
                elif response.status == 404:
                    logger.debug(f"CVE {cve_id} not found in NVD")
                    return None
                else:
                    logger.warning(f"NVD validation failed for {cve_id}: HTTP {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error validating {cve_id} against NVD: {e}")
            return None
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    async def _validate_against_osv(
        self, 
        package_name: str, 
        cve_id: str
    ) -> Optional[Dict[str, Any]]:
        """Validate CVE against OSV.dev database."""
        try:
            # First try to query by CVE ID
            url = f"{self.osv_base_url}/vulns/{cve_id}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    return {
                        'source': 'osv',
                        'vulnerability_id': data.get('id'),
                        'summary': data.get('summary'),
                        'severity': self._extract_osv_severity(data),
                        'affected_packages': self._extract_osv_affected_packages(data),
                        'references': data.get('references', []),
                        'validated': True
                    }
                
                elif response.status == 404:
                    # Try querying by package name
                    return await self._query_osv_by_package(package_name, cve_id)
                
        except Exception as e:
            logger.error(f"Error validating {cve_id} against OSV: {e}")
            return None
    
    async def _query_osv_by_package(
        self, 
        package_name: str, 
        cve_id: str
    ) -> Optional[Dict[str, Any]]:
        """Query OSV by package name to find CVE."""
        try:
            url = f"{self.osv_base_url}/query"
            payload = {
                "package": {
                    "name": package_name,
                    "ecosystem": "PyPI"  # Could be made dynamic based on package
                }
            }
            
            async with self.session.post(url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # Look for the specific CVE in results
                    for vuln in data.get('vulns', []):
                        aliases = vuln.get('aliases', [])
                        if cve_id in aliases or vuln.get('id') == cve_id:
                            return {
                                'source': 'osv',
                                'vulnerability_id': vuln.get('id'),
                                'summary': vuln.get('summary'),
                                'severity': self._extract_osv_severity(vuln),
                                'affected_packages': self._extract_osv_affected_packages(vuln),
                                'references': vuln.get('references', []),
                                'validated': True
                            }
            
            return None
            
        except Exception as e:
            logger.error(f"Error querying OSV by package {package_name}: {e}")
            return None
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    async def _validate_against_github(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Validate CVE against GitHub Security Advisories."""
        try:
            # GitHub API requires user agent
            headers = {
                'User-Agent': 'SCA-AI-Scanner/3.0',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            # Search for the CVE
            url = f"{self.github_base_url}?cve_id={cve_id}"
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if len(data) > 0:
                        advisory = data[0]  # Take first result
                        
                        return {
                            'source': 'github',
                            'ghsa_id': advisory.get('ghsa_id'),
                            'summary': advisory.get('summary'),
                            'description': advisory.get('description'),
                            'severity': advisory.get('severity'),
                            'cvss_score': self._extract_github_cvss_score(advisory),
                            'published_at': advisory.get('published_at'),
                            'updated_at': advisory.get('updated_at'),
                            'vulnerabilities': advisory.get('vulnerabilities', []),
                            'validated': True
                        }
                
                elif response.status == 404:
                    logger.debug(f"CVE {cve_id} not found in GitHub advisories")
                    return None
                    
        except Exception as e:
            logger.error(f"Error validating {cve_id} against GitHub: {e}")
            return None
    
    def _merge_validation_sources(
        self, 
        validation_sources: List[tuple[str, Dict[str, Any]]], 
        original_finding: CVEFinding
    ) -> Dict[str, Any]:
        """Merge validation data from multiple sources."""
        merged_data = {
            'validated': True,
            'validation_sources': [source[0] for source in validation_sources],
            'validation_confidence': self._calculate_validation_confidence(validation_sources),
            'original_finding': {
                'severity': original_finding.severity.value,
                'description': original_finding.description,
                'cvss_score': original_finding.cvss_score
            }
        }
        
        # Merge data from sources (prioritize NVD > OSV > GitHub)
        for source_name, source_data in validation_sources:
            if source_name == 'nvd':
                merged_data.update({
                    'authoritative_description': source_data.get('description'),
                    'authoritative_cvss_score': source_data.get('cvss_score'),
                    'authoritative_severity': source_data.get('severity'),
                    'published_date': source_data.get('published_date'),
                    'nvd_references': source_data.get('references')
                })
                break  # NVD is most authoritative
        
        # Add additional context from other sources
        for source_name, source_data in validation_sources:
            if source_name == 'osv':
                merged_data['osv_affected_packages'] = source_data.get('affected_packages')
            elif source_name == 'github':
                merged_data['github_advisory'] = source_data.get('ghsa_id')
        
        return merged_data
    
    def _calculate_validation_confidence(
        self, 
        validation_sources: List[tuple[str, Dict[str, Any]]]
    ) -> float:
        """Calculate confidence score based on validation sources."""
        source_weights = {'nvd': 1.0, 'osv': 0.8, 'github': 0.7}
        
        total_weight = 0.0
        for source_name, _ in validation_sources:
            total_weight += source_weights.get(source_name, 0.5)
        
        # Normalize to 0.0-1.0 range
        return min(total_weight / 1.5, 1.0)  # Max confidence with multiple sources
    
    def _update_finding_with_validation(
        self, 
        results: VulnerabilityResults, 
        pkg_id: str, 
        cve_id: str, 
        validation_data: Dict[str, Any]
    ) -> None:
        """Update finding with validation results."""
        if pkg_id in results.vulnerability_analysis:
            analysis = results.vulnerability_analysis[pkg_id]
            
            # Find the CVE to update
            for cve in analysis.cves:
                if cve.id == cve_id:
                    # Update with validated information
                    if 'authoritative_cvss_score' in validation_data:
                        cve.cvss_score = validation_data['authoritative_cvss_score']
                    
                    if 'authoritative_description' in validation_data:
                        cve.description = validation_data['authoritative_description']
                    
                    if 'published_date' in validation_data:
                        try:
                            cve.publish_date = datetime.fromisoformat(
                                validation_data['published_date'].replace('Z', '+00:00')
                            )
                        except (ValueError, AttributeError):
                            pass
                    
                    # Update data source to indicate validation
                    cve.data_source = "validated"
                    
                    # Increase confidence for validated findings
                    analysis.confidence = min(analysis.confidence + 0.1, 1.0)
                    
                    break
    
    def _get_cached_validation(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached validation result if still valid."""
        if cache_key in self.validation_cache:
            cached_data = self.validation_cache[cache_key]
            cached_time = datetime.fromisoformat(cached_data['timestamp'])
            
            if datetime.utcnow() - cached_time < self.cache_ttl:
                return cached_data['data']
            else:
                # Remove expired cache entry
                del self.validation_cache[cache_key]
        
        return None
    
    def _cache_validation_result(self, cache_key: str, validation_data: Dict[str, Any]) -> None:
        """Cache validation result."""
        self.validation_cache[cache_key] = {
            'timestamp': datetime.utcnow().isoformat(),
            'data': validation_data
        }
    
    # Helper methods for extracting data from different sources
    
    def _extract_nvd_description(self, cve_data: Dict[str, Any]) -> str:
        """Extract description from NVD CVE data."""
        descriptions = cve_data.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                return desc.get('value', '')
        return ''
    
    def _extract_nvd_cvss_score(self, cve_data: Dict[str, Any]) -> Optional[float]:
        """Extract CVSS score from NVD CVE data."""
        metrics = cve_data.get('metrics', {})
        
        # Try CVSS v3.1 first, then v3.0, then v2.0
        for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            if version in metrics and len(metrics[version]) > 0:
                cvss_data = metrics[version][0]
                return cvss_data.get('cvssData', {}).get('baseScore')
        
        return None
    
    def _extract_nvd_severity(self, cve_data: Dict[str, Any]) -> Optional[str]:
        """Extract severity from NVD CVE data."""
        metrics = cve_data.get('metrics', {})
        
        for version in ['cvssMetricV31', 'cvssMetricV30']:
            if version in metrics and len(metrics[version]) > 0:
                cvss_data = metrics[version][0]
                return cvss_data.get('cvssData', {}).get('baseSeverity')
        
        return None
    
    def _extract_nvd_references(self, cve_data: Dict[str, Any]) -> List[str]:
        """Extract references from NVD CVE data."""
        references = cve_data.get('references', [])
        return [ref.get('url') for ref in references if ref.get('url')]
    
    def _extract_osv_severity(self, vuln_data: Dict[str, Any]) -> Optional[str]:
        """Extract severity from OSV vulnerability data."""
        severity = vuln_data.get('severity')
        if isinstance(severity, list) and len(severity) > 0:
            return severity[0].get('score')
        return None
    
    def _extract_osv_affected_packages(self, vuln_data: Dict[str, Any]) -> List[str]:
        """Extract affected packages from OSV vulnerability data."""
        affected = vuln_data.get('affected', [])
        packages = []
        
        for item in affected:
            package = item.get('package', {})
            if package.get('name'):
                packages.append(f"{package['name']}@{package.get('ecosystem', 'unknown')}")
        
        return packages
    
    def _extract_github_cvss_score(self, advisory_data: Dict[str, Any]) -> Optional[float]:
        """Extract CVSS score from GitHub advisory data."""
        cvss = advisory_data.get('cvss')
        if cvss:
            return cvss.get('score')
        return None
    
    def get_validation_stats(self) -> Dict[str, Any]:
        """Get validation pipeline statistics."""
        return {
            'cache_size': len(self.validation_cache),
            'cache_ttl_hours': self.cache_ttl.total_seconds() / 3600,
            'validation_settings': {
                'validate_critical': self.validate_critical,
                'validate_high': self.validate_high,
                'spot_check_medium': self.spot_check_medium,
                'spot_check_ratio': self.spot_check_ratio
            },
            'rate_limiting': {
                'request_delay': self.request_delay,
                'max_concurrent': self.max_concurrent
            }
        }