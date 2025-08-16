"""
DSPy Structured CVE Extraction with typed predictors.
Provides accurate vulnerability data extraction with type enforcement.
"""

import dspy
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass
import json
import re
import logging
from datetime import datetime
from functools import lru_cache

from ..core.models import CVEFinding, Severity

logger = logging.getLogger(__name__)


class CVEExtractionSignature(dspy.Signature):
    """Typed signature for CVE data extraction."""
    
    # Input fields
    raw_text = dspy.InputField(desc="Raw text containing CVE information")
    package_name = dspy.InputField(desc="Package name for context")
    package_version = dspy.InputField(desc="Package version for context")
    data_source = dspy.InputField(desc="Source of the data (nvd, github, etc.)")
    
    # Typed output fields
    cve_id = dspy.OutputField(desc="CVE identifier (e.g., CVE-2020-8203)")
    severity = dspy.OutputField(
        desc="Severity level",
        enum_constraint=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    )
    cvss_score = dspy.OutputField(
        desc="CVSS score (0.0-10.0)",
        type_constraint=float
    )
    description = dspy.OutputField(desc="Vulnerability description")
    published_date = dspy.OutputField(desc="Publication date (YYYY-MM-DD)")
    affected_versions = dspy.OutputField(desc="Affected version range")
    fixed_versions = dspy.OutputField(desc="Fixed version range")
    references = dspy.OutputField(desc="List of reference URLs")
    
    def validate(self, data: Dict[str, Any]) -> None:
        """Validate extracted CVE data."""
        # Validate CVE ID format
        if 'cve_id' in data:
            cve_id = data['cve_id']
            if not re.match(r'^CVE-\d{4}-\d+$', cve_id):
                raise ValueError(f"Invalid CVE ID format: {cve_id}")
        
        # Validate CVSS score
        if 'cvss_score' in data:
            score = data['cvss_score']
            if not isinstance(score, (int, float)) or score < 0 or score > 10:
                raise ValueError(f"CVSS score must be 0-10, got {score}")
        
        # Validate severity
        if 'severity' in data:
            severity = data['severity']
            valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            if severity not in valid_severities:
                raise ValueError(f"Invalid severity: {severity}")


class CVEDataValidator:
    """Validator for CVE data integrity."""
    
    @staticmethod
    def validate_cve_id(cve_id: str) -> bool:
        """Validate CVE ID format.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            True if valid
        """
        pattern = r'^CVE-\d{4}-\d+$'
        return bool(re.match(pattern, cve_id))
    
    @staticmethod
    def validate_cvss_score(score: Any) -> bool:
        """Validate CVSS score.
        
        Args:
            score: CVSS score
            
        Returns:
            True if valid
        """
        if score is None:
            return False
        try:
            score_float = float(score)
            return 0.0 <= score_float <= 10.0
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def validate_severity(severity: str) -> bool:
        """Validate severity level.
        
        Args:
            severity: Severity level
            
        Returns:
            True if valid
        """
        valid_severities = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}
        return severity in valid_severities
    
    @staticmethod
    def validate_version_range(version_range: str) -> bool:
        """Validate version range format.
        
        Args:
            version_range: Version range string
            
        Returns:
            True if valid
        """
        if not version_range:
            return False
        
        # Common version range patterns
        patterns = [
            r'^<\d+\.\d+\.\d+',        # <1.2.3
            r'^>\d+\.\d+\.\d+',        # >1.2.3
            r'^>=\d+\.\d+\.\d+',       # >=1.2.3
            r'^<=\d+\.\d+\.\d+',       # <=1.2.3
            r'^==\d+\.\d+\.\d+',       # ==1.2.3
            r'^\^\d+\.\d+\.\d+',       # ^1.2.3
            r'^~\d+\.\d+\.\d+',        # ~1.2.3
            r'^>=\d+\.\d+\.\d+\s*<\d+\.\d+\.\d+'  # >=1.0.0 <2.0.0
        ]
        
        return any(re.match(pattern, version_range) for pattern in patterns)


class TypedCVEPredictor(dspy.Module):
    """Typed predictor for CVE extraction with type enforcement."""
    
    def __init__(self):
        """Initialize typed CVE predictor."""
        super().__init__()
        
        self.signature = CVEExtractionSignature
        self.predictor = dspy.TypedPredictor(self.signature)
        self.validator = CVEDataValidator()
        self.type_enforcer = TypeEnforcer()
        self.assertions = []
    
    def extract(
        self,
        raw_text: str,
        package_name: str,
        package_version: str,
        data_source: str = 'unknown'
    ) -> Dict[str, Any]:
        """Extract CVE data with type enforcement.
        
        Args:
            raw_text: Text containing CVE information
            package_name: Package name
            package_version: Package version
            data_source: Data source
            
        Returns:
            Extracted and typed CVE data
        """
        try:
            # Run typed prediction
            result = self.predictor(
                raw_text=raw_text,
                package_name=package_name,
                package_version=package_version,
                data_source=data_source
            )
            
            # Parse and enforce types
            cve_data = self._parse_and_enforce_types(result)
            
            # Validate
            self._validate_cve_data(cve_data)
            
            # Apply assertions
            for assertion_fn, msg in self.assertions:
                if not assertion_fn(cve_data):
                    raise AssertionError(msg)
            
            return cve_data
            
        except Exception as e:
            logger.error(f"Failed to extract CVE data: {e}")
            raise
    
    def _parse_and_enforce_types(self, result) -> Dict[str, Any]:
        """Parse result and enforce types."""
        cve_data = {}
        
        # CVE ID (string)
        cve_data['cve_id'] = str(getattr(result, 'cve_id', ''))
        
        # Severity (enum)
        severity = str(getattr(result, 'severity', 'MEDIUM')).upper()
        cve_data['severity'] = severity if self.validator.validate_severity(severity) else 'MEDIUM'
        
        # CVSS Score (float)
        cvss = getattr(result, 'cvss_score', 5.0)
        cve_data['cvss_score'] = self.type_enforcer.enforce_float(cvss, min_val=0.0, max_val=10.0)
        
        # Description (string)
        cve_data['description'] = str(getattr(result, 'description', ''))
        
        # Published date (string)
        cve_data['published_date'] = str(getattr(result, 'published_date', ''))
        
        # Version ranges (string)
        cve_data['affected_versions'] = str(getattr(result, 'affected_versions', ''))
        cve_data['fixed_versions'] = str(getattr(result, 'fixed_versions', ''))
        
        # References (list)
        refs = getattr(result, 'references', [])
        if isinstance(refs, str):
            try:
                refs = json.loads(refs)
            except:
                refs = [refs] if refs else []
        cve_data['references'] = refs if isinstance(refs, list) else []
        
        return cve_data
    
    def _validate_cve_data(self, cve_data: Dict[str, Any]) -> None:
        """Validate extracted CVE data."""
        if not self.validator.validate_cve_id(cve_data['cve_id']):
            raise ValueError(f"Invalid CVE ID: {cve_data['cve_id']}")
        
        if not self.validator.validate_cvss_score(cve_data['cvss_score']):
            raise ValueError(f"Invalid CVSS score: {cve_data['cvss_score']}")
    
    def add_assertion(self, assertion_fn, message: str):
        """Add quality assertion.
        
        Args:
            assertion_fn: Function that returns True if assertion passes
            message: Error message if assertion fails
        """
        self.assertions.append((assertion_fn, message))
    
    def raw_predict(self, *args, **kwargs):
        """Raw prediction for testing."""
        return self.predictor(*args, **kwargs)


class TypeEnforcer:
    """Enforce types for extracted data."""
    
    @staticmethod
    def enforce_float(value: Any, min_val: float = None, max_val: float = None) -> float:
        """Enforce float type with optional bounds.
        
        Args:
            value: Value to convert
            min_val: Minimum value
            max_val: Maximum value
            
        Returns:
            Float value
        """
        try:
            if isinstance(value, str):
                # Extract number from string
                match = re.search(r'\d+\.?\d*', value)
                if match:
                    value = match.group()
            
            result = float(value)
            
            if min_val is not None:
                result = max(min_val, result)
            if max_val is not None:
                result = min(max_val, result)
            
            return result
            
        except (ValueError, TypeError):
            return 5.0  # Default middle value
    
    @staticmethod
    def enforce_string(value: Any) -> str:
        """Enforce string type.
        
        Args:
            value: Value to convert
            
        Returns:
            String value
        """
        return str(value) if value is not None else ''
    
    @staticmethod
    def enforce_list(value: Any) -> list:
        """Enforce list type.
        
        Args:
            value: Value to convert
            
        Returns:
            List value
        """
        if isinstance(value, list):
            return value
        elif isinstance(value, str):
            try:
                return json.loads(value)
            except:
                return [value] if value else []
        else:
            return []


class StructuredCVEExtractor:
    """Complete structured CVE extractor with caching."""
    
    def __init__(self):
        """Initialize CVE extractor."""
        self.predictor = TypedCVEPredictor()
        self.validator = CVEDataValidator()
        self.cache = {}
    
    def extract_cves_from_text(
        self,
        text: str,
        package_name: str,
        package_version: str
    ) -> List[Dict[str, Any]]:
        """Extract CVEs from unstructured text.
        
        Args:
            text: Text containing CVE information
            package_name: Package name
            package_version: Package version
            
        Returns:
            List of extracted CVEs
        """
        # Check cache
        cache_key = f"{package_name}:{package_version}:{hash(text)}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        # Find CVE mentions in text
        cve_pattern = r'CVE-\d{4}-\d+'
        cve_ids = re.findall(cve_pattern, text)
        
        extracted_cves = []
        for cve_id in cve_ids:
            # Extract context around CVE ID
            context = self._extract_context(text, cve_id)
            
            try:
                cve_data = self.predictor.extract(
                    raw_text=context,
                    package_name=package_name,
                    package_version=package_version,
                    data_source='text'
                )
                extracted_cves.append(cve_data)
            except Exception as e:
                logger.warning(f"Failed to extract {cve_id}: {e}")
        
        # Cache result
        self.cache[cache_key] = extracted_cves
        
        return extracted_cves
    
    def extract_cves_from_json(
        self,
        json_data: Dict[str, Any],
        package_name: str,
        package_version: str
    ) -> List[CVEFinding]:
        """Extract CVEs from JSON data.
        
        Args:
            json_data: JSON vulnerability data
            package_name: Package name
            package_version: Package version
            
        Returns:
            List of CVE findings
        """
        vulnerabilities = json_data.get('vulnerabilities', [])
        findings = []
        
        for vuln in vulnerabilities:
            try:
                finding = self._parse_json_vulnerability(vuln)
                findings.append(finding)
            except Exception as e:
                logger.warning(f"Failed to parse vulnerability: {e}")
        
        return findings
    
    def _extract_context(self, text: str, cve_id: str, context_size: int = 200) -> str:
        """Extract context around CVE ID.
        
        Args:
            text: Full text
            cve_id: CVE ID to find
            context_size: Characters of context
            
        Returns:
            Context string
        """
        idx = text.find(cve_id)
        if idx == -1:
            return text[:context_size * 2]
        
        start = max(0, idx - context_size)
        end = min(len(text), idx + len(cve_id) + context_size)
        
        return text[start:end]
    
    def _parse_json_vulnerability(self, vuln: Dict[str, Any]) -> CVEFinding:
        """Parse JSON vulnerability to CVEFinding.
        
        Args:
            vuln: Vulnerability data
            
        Returns:
            CVE finding
        """
        # Map severity strings
        severity_map = {
            'critical': Severity.CRITICAL,
            'high': Severity.HIGH,
            'medium': Severity.MEDIUM,
            'low': Severity.LOW,
            'info': Severity.INFO
        }
        
        severity_str = vuln.get('severity', 'medium').lower()
        severity = severity_map.get(severity_str, Severity.MEDIUM)
        
        # Extract CVSS score
        cvss = vuln.get('cvss', {})
        if isinstance(cvss, dict):
            cvss_score = cvss.get('score', 5.0)
        else:
            cvss_score = 5.0
        
        return CVEFinding(
            id=vuln.get('id', 'UNKNOWN'),
            severity=severity,
            description=vuln.get('description', ''),
            cvss_score=cvss_score,
            publish_date=self._parse_date(vuln.get('published_date'))
        )
    
    def _parse_date(self, date_str: Any) -> Optional[datetime]:
        """Parse date string to datetime.
        
        Args:
            date_str: Date string
            
        Returns:
            Datetime or None
        """
        if not date_str:
            return None
        
        try:
            if isinstance(date_str, datetime):
                return date_str
            
            # Try common date formats
            formats = [
                '%Y-%m-%d',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y/%m/%d'
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(str(date_str), fmt)
                except:
                    continue
            
            return None
            
        except Exception:
            return None
    
    def extract_from_structured(self, data: Dict[str, Any]) -> List[CVEFinding]:
        """Extract from structured data.
        
        Args:
            data: Structured vulnerability data
            
        Returns:
            List of CVE findings
        """
        return self.extract_cves_from_json(data, '', '')
    
    def extract_from_source(self, source: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract from a data source.
        
        Args:
            source: Data source with type and content
            
        Returns:
            Extracted CVEs
        """
        source_type = source.get('type', 'text')
        content = source.get('content', '')
        
        if source_type == 'json':
            return self.extract_cves_from_json(content, '', '')
        else:
            return self.extract_cves_from_text(content, '', '')


class CVEEnrichmentPipeline:
    """Pipeline for enriching CVE data."""
    
    def __init__(self):
        """Initialize enrichment pipeline."""
        self.extractor = StructuredCVEExtractor()
        self.enricher = CVEEnricher()
        self.deduplicator = CVEDeduplicator()
    
    def enrich(self, basic_cve: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich basic CVE data.
        
        Args:
            basic_cve: Basic CVE data
            
        Returns:
            Enriched CVE data
        """
        return self.enricher.enrich(basic_cve)
    
    def deduplicate(self, cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate CVE list.
        
        Args:
            cves: List of CVEs
            
        Returns:
            Deduplicated list
        """
        return self.deduplicator.deduplicate(cves)
    
    def batch_extract(
        self,
        sources: List[Dict[str, Any]],
        package_name: str,
        package_version: str
    ) -> List[Dict[str, Any]]:
        """Extract from multiple sources.
        
        Args:
            sources: List of data sources
            package_name: Package name
            package_version: Package version
            
        Returns:
            All extracted CVEs
        """
        all_cves = []
        
        for source in sources:
            try:
                cves = self.extractor.extract_from_source(source)
                all_cves.extend(cves)
            except Exception as e:
                logger.warning(f"Failed to extract from source: {e}")
        
        # Deduplicate
        return self.deduplicate(all_cves)


class CVEEnricher:
    """Enrich CVE data with additional context."""
    
    def enrich(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich CVE data.
        
        Args:
            cve_data: Basic CVE data
            
        Returns:
            Enriched data
        """
        enriched = cve_data.copy()
        
        # Add exploit availability (mock)
        enriched['exploit_available'] = self._check_exploit_availability(cve_data['cve_id'])
        
        # Add patch availability
        enriched['patch_available'] = bool(cve_data.get('fixed_versions'))
        
        # Add CWE IDs
        enriched['cwe_ids'] = self._extract_cwe_ids(cve_data.get('description', ''))
        
        # Add attack vector
        enriched['attack_vector'] = self._determine_attack_vector(cve_data)
        
        return enriched
    
    def _check_exploit_availability(self, cve_id: str) -> bool:
        """Check if exploit is available (mock).
        
        Args:
            cve_id: CVE ID
            
        Returns:
            True if exploit exists
        """
        # In real implementation, would check exploit databases
        return 'critical' in cve_id.lower() or '2020' in cve_id
    
    def _extract_cwe_ids(self, description: str) -> List[str]:
        """Extract CWE IDs from description.
        
        Args:
            description: CVE description
            
        Returns:
            List of CWE IDs
        """
        pattern = r'CWE-\d+'
        return re.findall(pattern, description)
    
    def _determine_attack_vector(self, cve_data: Dict[str, Any]) -> str:
        """Determine attack vector.
        
        Args:
            cve_data: CVE data
            
        Returns:
            Attack vector
        """
        description = cve_data.get('description', '').lower()
        
        if 'remote' in description or 'network' in description:
            return 'NETWORK'
        elif 'local' in description:
            return 'LOCAL'
        elif 'adjacent' in description:
            return 'ADJACENT'
        else:
            return 'UNKNOWN'


class CVEDeduplicator:
    """Deduplicate CVE findings."""
    
    def deduplicate(self, cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate CVE list.
        
        Args:
            cves: List of CVEs
            
        Returns:
            Deduplicated list
        """
        seen = {}
        
        for cve in cves:
            cve_id = cve.get('cve_id', '')
            
            if cve_id not in seen:
                seen[cve_id] = cve
            else:
                # Keep the one with higher severity
                existing = seen[cve_id]
                if self._compare_severity(cve, existing) > 0:
                    seen[cve_id] = cve
        
        return list(seen.values())
    
    def _compare_severity(self, cve1: Dict[str, Any], cve2: Dict[str, Any]) -> int:
        """Compare severity of two CVEs.
        
        Args:
            cve1: First CVE
            cve2: Second CVE
            
        Returns:
            1 if cve1 is more severe, -1 if cve2 is more severe, 0 if equal
        """
        severity_order = {
            'CRITICAL': 5,
            'HIGH': 4,
            'MEDIUM': 3,
            'LOW': 2,
            'INFO': 1
        }
        
        s1 = severity_order.get(cve1.get('severity', 'LOW'), 2)
        s2 = severity_order.get(cve2.get('severity', 'LOW'), 2)
        
        if s1 > s2:
            return 1
        elif s1 < s2:
            return -1
        else:
            return 0


def calculate_extraction_accuracy(predicted: Dict[str, Any], expected: Dict[str, Any]) -> float:
    """Calculate extraction accuracy.
    
    Args:
        predicted: Predicted CVE data
        expected: Expected CVE data
        
    Returns:
        Accuracy score between 0 and 1
    """
    score = 0.0
    total_fields = 0
    
    # Critical fields with higher weight
    critical_fields = ['cve_id', 'severity']
    for field in critical_fields:
        if field in expected:
            total_fields += 2  # Double weight
            if predicted.get(field) == expected[field]:
                score += 2
    
    # Regular fields
    regular_fields = ['cvss_score', 'description']
    for field in regular_fields:
        if field in expected:
            total_fields += 1
            if field == 'cvss_score':
                # Allow small difference for scores
                pred_score = predicted.get(field, 0)
                exp_score = expected[field]
                if abs(pred_score - exp_score) < 0.5:
                    score += 1
            elif predicted.get(field) == expected[field]:
                score += 1
    
    return score / total_fields if total_fields > 0 else 0.0


def create_optimized_extractor(
    training_data: List[Dict[str, Any]],
    metric_fn: Optional[callable] = None
) -> StructuredCVEExtractor:
    """Create optimized CVE extractor.
    
    Args:
        training_data: Training examples
        metric_fn: Metric function
        
    Returns:
        Optimized extractor
    """
    # Create base extractor
    extractor = StructuredCVEExtractor()
    
    # Prepare training examples
    trainset = []
    for item in training_data:
        example = dspy.Example(
            text=item['text'],
            expected=item['expected']
        )
        trainset.append(example)
    
    # Use default metric if not provided
    if metric_fn is None:
        metric_fn = lambda pred, example: calculate_extraction_accuracy(
            pred.dict() if hasattr(pred, 'dict') else pred,
            example.expected
        )
    
    # Setup optimizer
    optimizer = dspy.MIPROv2(
        metric=metric_fn,
        max_bootstrapped_demos=5,
        max_labeled_demos=5,
        num_iterations=5
    )
    
    # Optimize
    optimized = optimizer.compile(
        extractor.predictor,
        trainset=trainset,
        requires_permission_to_run=False
    )
    
    # Update extractor with optimized predictor
    extractor.predictor = optimized
    
    logger.info(f"Optimized CVE extractor with {len(trainset)} examples")
    
    return extractor