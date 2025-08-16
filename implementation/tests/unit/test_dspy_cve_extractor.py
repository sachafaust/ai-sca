"""
Unit tests for DSPy Structured CVE Extraction.
Tests typed predictors for accurate vulnerability data extraction.
"""

import pytest
import dspy
from unittest.mock import Mock, patch, MagicMock
from typing import List, Dict, Any
from datetime import datetime

from sca_ai_scanner.dspy_modules.cve_extractor import (
    CVEExtractionSignature,
    StructuredCVEExtractor,
    CVEDataValidator,
    TypedCVEPredictor,
    CVEEnrichmentPipeline,
    create_optimized_extractor
)
from sca_ai_scanner.core.models import CVEFinding, Severity


class TestCVEExtractionSignature:
    """Test the CVE extraction signature."""
    
    def test_signature_structure(self):
        """Test CVEExtractionSignature has correct fields."""
        sig = CVEExtractionSignature()
        
        # Input fields
        assert hasattr(sig, 'raw_text')
        assert hasattr(sig, 'package_name')
        assert hasattr(sig, 'package_version')
        assert hasattr(sig, 'data_source')
        
        # Output fields (typed)
        assert hasattr(sig, 'cve_id')
        assert hasattr(sig, 'severity')
        assert hasattr(sig, 'cvss_score')
        assert hasattr(sig, 'description')
        assert hasattr(sig, 'published_date')
        assert hasattr(sig, 'affected_versions')
        assert hasattr(sig, 'fixed_versions')
        assert hasattr(sig, 'references')
    
    def test_signature_typing(self):
        """Test that signature has proper type annotations."""
        sig = CVEExtractionSignature()
        
        # Check type annotations exist
        assert sig.cve_id.__class__.__name__ == 'OutputField'
        assert sig.severity.__class__.__name__ == 'OutputField'
        assert sig.cvss_score.__class__.__name__ == 'OutputField'
        
        # Verify type constraints
        assert hasattr(sig.cvss_score, 'type_constraint')
        assert sig.cvss_score.type_constraint == float
        
        assert hasattr(sig.severity, 'enum_constraint')
        assert 'CRITICAL' in sig.severity.enum_constraint
    
    def test_signature_validation(self):
        """Test validation of extracted CVE data."""
        sig = CVEExtractionSignature()
        
        valid_data = {
            'raw_text': 'CVE-2020-8203 affects lodash < 4.17.20',
            'package_name': 'lodash',
            'package_version': '4.17.19',
            'data_source': 'nvd',
            'cve_id': 'CVE-2020-8203',
            'severity': 'HIGH',
            'cvss_score': 7.4,
            'description': 'Prototype pollution vulnerability',
            'published_date': '2020-07-15',
            'affected_versions': '<4.17.20',
            'fixed_versions': '>=4.17.20',
            'references': ['https://nvd.nist.gov/vuln/detail/CVE-2020-8203']
        }
        
        sig.validate(valid_data)
        
        # Test invalid CVSS score
        invalid_data = valid_data.copy()
        invalid_data['cvss_score'] = 11.0  # Out of range
        
        with pytest.raises(ValueError):
            sig.validate(invalid_data)


class TestCVEDataValidator:
    """Test CVE data validation."""
    
    def test_cve_id_validation(self):
        """Test CVE ID format validation."""
        validator = CVEDataValidator()
        
        # Valid CVE IDs
        assert validator.validate_cve_id('CVE-2020-8203')
        assert validator.validate_cve_id('CVE-2021-12345')
        assert validator.validate_cve_id('CVE-2019-1')
        
        # Invalid CVE IDs
        assert not validator.validate_cve_id('CVE-20-8203')  # Year too short
        assert not validator.validate_cve_id('CVE-2020-ABC')  # Non-numeric sequence
        assert not validator.validate_cve_id('2020-8203')     # Missing CVE prefix
        assert not validator.validate_cve_id('CVE20208203')   # Missing hyphens
    
    def test_cvss_score_validation(self):
        """Test CVSS score validation."""
        validator = CVEDataValidator()
        
        # Valid scores
        assert validator.validate_cvss_score(0.0)
        assert validator.validate_cvss_score(5.5)
        assert validator.validate_cvss_score(10.0)
        
        # Invalid scores
        assert not validator.validate_cvss_score(-1.0)
        assert not validator.validate_cvss_score(10.1)
        assert not validator.validate_cvss_score(None)
    
    def test_severity_validation(self):
        """Test severity level validation."""
        validator = CVEDataValidator()
        
        # Valid severities
        assert validator.validate_severity('CRITICAL')
        assert validator.validate_severity('HIGH')
        assert validator.validate_severity('MEDIUM')
        assert validator.validate_severity('LOW')
        assert validator.validate_severity('INFO')
        
        # Invalid severities
        assert not validator.validate_severity('VERY_HIGH')
        assert not validator.validate_severity('critical')  # Case sensitive
        assert not validator.validate_severity('')
    
    def test_version_range_validation(self):
        """Test version range validation."""
        validator = CVEDataValidator()
        
        # Valid version ranges
        assert validator.validate_version_range('<4.17.20')
        assert validator.validate_version_range('>=2.0.0 <3.0.0')
        assert validator.validate_version_range('==1.2.3')
        assert validator.validate_version_range('~1.2.0')
        assert validator.validate_version_range('^2.0.0')
        
        # Invalid version ranges
        assert not validator.validate_version_range('invalid')
        assert not validator.validate_version_range('')


class TestTypedCVEPredictor:
    """Test the typed CVE predictor."""
    
    @pytest.fixture
    def mock_lm(self):
        """Mock language model for testing."""
        mock = MagicMock()
        mock.request.return_value = {
            'cve_id': 'CVE-2020-8203',
            'severity': 'HIGH',
            'cvss_score': 7.4,
            'description': 'Prototype pollution vulnerability',
            'published_date': '2020-07-15',
            'affected_versions': '<4.17.20',
            'fixed_versions': '>=4.17.20',
            'references': ['https://nvd.nist.gov/vuln/detail/CVE-2020-8203']
        }
        return mock
    
    @pytest.fixture
    def predictor(self, mock_lm):
        """Create predictor with mocked LM."""
        with patch('dspy.settings.lm', mock_lm):
            return TypedCVEPredictor()
    
    def test_predictor_initialization(self, predictor):
        """Test predictor initializes correctly."""
        assert predictor is not None
        assert hasattr(predictor, 'signature')
        assert hasattr(predictor, 'validator')
        assert hasattr(predictor, 'type_enforcer')
    
    def test_single_cve_extraction(self, predictor):
        """Test extracting a single CVE."""
        raw_text = """
        Security Advisory: lodash vulnerability
        CVE-2020-8203 - High severity
        CVSS Score: 7.4
        Prototype pollution in lodash versions before 4.17.20
        """
        
        result = predictor.extract(
            raw_text=raw_text,
            package_name='lodash',
            package_version='4.17.19'
        )
        
        assert result is not None
        assert result['cve_id'] == 'CVE-2020-8203'
        assert result['severity'] == 'HIGH'
        assert result['cvss_score'] == 7.4
        assert isinstance(result['cvss_score'], float)
    
    def test_type_enforcement(self, predictor):
        """Test that types are enforced correctly."""
        with patch.object(predictor, 'raw_predict') as mock_predict:
            # Return string instead of float for CVSS score
            mock_predict.return_value = {
                'cve_id': 'CVE-2020-8203',
                'severity': 'HIGH',
                'cvss_score': '7.4',  # String instead of float
                'description': 'Test',
                'published_date': '2020-07-15',
                'affected_versions': '<4.17.20',
                'fixed_versions': '>=4.17.20',
                'references': []
            }
            
            result = predictor.extract(
                raw_text='test',
                package_name='lodash',
                package_version='4.17.19'
            )
            
            # Type enforcer should convert to float
            assert isinstance(result['cvss_score'], float)
            assert result['cvss_score'] == 7.4
    
    def test_validation_assertions(self, predictor):
        """Test that validation assertions work."""
        predictor.add_assertion(
            lambda result: result['cvss_score'] >= 7.0,
            "Only extract high/critical vulnerabilities"
        )
        
        with patch.object(predictor, 'raw_predict') as mock_predict:
            # Low severity CVE
            mock_predict.return_value = {
                'cve_id': 'CVE-2020-1234',
                'severity': 'LOW',
                'cvss_score': 3.5,
                'description': 'Minor issue',
                'published_date': '2020-01-01',
                'affected_versions': '<1.0.0',
                'fixed_versions': '>=1.0.0',
                'references': []
            }
            
            with pytest.raises(AssertionError):
                predictor.extract(
                    raw_text='test',
                    package_name='test',
                    package_version='0.9.0'
                )


class TestStructuredCVEExtractor:
    """Test the complete structured CVE extractor."""
    
    @pytest.fixture
    def extractor(self):
        """Create extractor."""
        with patch('dspy.settings.lm', MagicMock()):
            return StructuredCVEExtractor()
    
    def test_extractor_initialization(self, extractor):
        """Test extractor initializes with all components."""
        assert extractor is not None
        assert hasattr(extractor, 'predictor')
        assert hasattr(extractor, 'validator')
        assert hasattr(extractor, 'cache')
    
    def test_extract_from_text(self, extractor):
        """Test extracting CVEs from unstructured text."""
        text = """
        Multiple vulnerabilities found:
        1. CVE-2020-8203 (HIGH, CVSS 7.4): Prototype pollution in lodash < 4.17.20
        2. CVE-2020-28500 (MEDIUM, CVSS 5.3): ReDOS vulnerability in lodash < 4.17.21
        """
        
        with patch.object(extractor.predictor, 'extract') as mock_extract:
            mock_extract.side_effect = [
                {
                    'cve_id': 'CVE-2020-8203',
                    'severity': 'HIGH',
                    'cvss_score': 7.4,
                    'description': 'Prototype pollution',
                    'affected_versions': '<4.17.20'
                },
                {
                    'cve_id': 'CVE-2020-28500',
                    'severity': 'MEDIUM',
                    'cvss_score': 5.3,
                    'description': 'ReDOS vulnerability',
                    'affected_versions': '<4.17.21'
                }
            ]
            
            cves = extractor.extract_cves_from_text(
                text=text,
                package_name='lodash',
                package_version='4.17.19'
            )
            
            assert len(cves) == 2
            assert cves[0]['cve_id'] == 'CVE-2020-8203'
            assert cves[1]['cve_id'] == 'CVE-2020-28500'
    
    def test_extract_from_json(self, extractor):
        """Test extracting CVEs from JSON data."""
        json_data = {
            'vulnerabilities': [
                {
                    'id': 'CVE-2020-8203',
                    'severity': 'High',
                    'cvss': {'score': 7.4},
                    'description': 'Prototype pollution vulnerability'
                }
            ]
        }
        
        with patch.object(extractor, 'extract_from_structured') as mock_extract:
            mock_extract.return_value = [
                CVEFinding(
                    id='CVE-2020-8203',
                    severity=Severity.HIGH,
                    description='Prototype pollution vulnerability',
                    cvss_score=7.4
                )
            ]
            
            cves = extractor.extract_cves_from_json(
                json_data=json_data,
                package_name='lodash',
                package_version='4.17.19'
            )
            
            assert len(cves) == 1
            assert cves[0].id == 'CVE-2020-8203'
    
    def test_caching(self, extractor):
        """Test that extractor caches results."""
        text = "CVE-2020-8203: High severity vulnerability"
        
        with patch.object(extractor.predictor, 'extract') as mock_extract:
            mock_extract.return_value = {
                'cve_id': 'CVE-2020-8203',
                'severity': 'HIGH',
                'cvss_score': 7.4,
                'description': 'Test'
            }
            
            # First call
            result1 = extractor.extract_cves_from_text(
                text=text,
                package_name='lodash',
                package_version='4.17.19'
            )
            
            # Second call with same inputs
            result2 = extractor.extract_cves_from_text(
                text=text,
                package_name='lodash',
                package_version='4.17.19'
            )
            
            # Should only call predictor once due to caching
            assert mock_extract.call_count == 1
            assert result1 == result2


class TestCVEEnrichmentPipeline:
    """Test the CVE enrichment pipeline."""
    
    @pytest.fixture
    def pipeline(self):
        """Create enrichment pipeline."""
        with patch('dspy.settings.lm', MagicMock()):
            return CVEEnrichmentPipeline()
    
    def test_pipeline_initialization(self, pipeline):
        """Test pipeline initializes correctly."""
        assert pipeline is not None
        assert hasattr(pipeline, 'extractor')
        assert hasattr(pipeline, 'enricher')
        assert hasattr(pipeline, 'deduplicator')
    
    def test_enrich_cve_data(self, pipeline):
        """Test enriching CVE data with additional context."""
        basic_cve = {
            'cve_id': 'CVE-2020-8203',
            'severity': 'HIGH',
            'cvss_score': 7.4
        }
        
        with patch.object(pipeline.enricher, 'enrich') as mock_enrich:
            mock_enrich.return_value = {
                'cve_id': 'CVE-2020-8203',
                'severity': 'HIGH',
                'cvss_score': 7.4,
                'description': 'Prototype pollution in lodash',
                'exploit_available': True,
                'patch_available': True,
                'references': ['https://nvd.nist.gov/vuln/detail/CVE-2020-8203'],
                'cwe_ids': ['CWE-1321'],
                'attack_vector': 'NETWORK'
            }
            
            enriched = pipeline.enrich(basic_cve)
            
            assert enriched['exploit_available'] == True
            assert enriched['patch_available'] == True
            assert len(enriched['references']) > 0
    
    def test_deduplicate_cves(self, pipeline):
        """Test deduplication of CVE findings."""
        cves = [
            {'cve_id': 'CVE-2020-8203', 'severity': 'HIGH'},
            {'cve_id': 'CVE-2020-8203', 'severity': 'HIGH'},  # Duplicate
            {'cve_id': 'CVE-2020-28500', 'severity': 'MEDIUM'},
            {'cve_id': 'CVE-2020-8203', 'severity': 'CRITICAL'}  # Same CVE, different severity
        ]
        
        deduplicated = pipeline.deduplicate(cves)
        
        # Should keep unique CVEs and prefer higher severity
        assert len(deduplicated) == 2
        cve_8203 = next(c for c in deduplicated if c['cve_id'] == 'CVE-2020-8203')
        assert cve_8203['severity'] == 'CRITICAL'  # Should keep highest severity
    
    def test_batch_extraction(self, pipeline):
        """Test batch extraction from multiple sources."""
        sources = [
            {'type': 'text', 'content': 'CVE-2020-8203 found'},
            {'type': 'json', 'content': {'vulnerabilities': []}},
            {'type': 'api', 'content': 'CVE-2020-28500 detected'}
        ]
        
        with patch.object(pipeline, 'extract_from_source') as mock_extract:
            mock_extract.side_effect = [
                [{'cve_id': 'CVE-2020-8203'}],
                [],
                [{'cve_id': 'CVE-2020-28500'}]
            ]
            
            all_cves = pipeline.batch_extract(
                sources=sources,
                package_name='lodash',
                package_version='4.17.19'
            )
            
            assert len(all_cves) == 2
            assert mock_extract.call_count == 3


class TestOptimizedExtractor:
    """Test optimized extractor creation."""
    
    def test_create_optimized_extractor(self):
        """Test creating an optimized CVE extractor."""
        training_data = [
            {
                'text': 'CVE-2020-8203 (HIGH, 7.4): Prototype pollution',
                'expected': {
                    'cve_id': 'CVE-2020-8203',
                    'severity': 'HIGH',
                    'cvss_score': 7.4
                }
            }
        ]
        
        with patch('dspy.MIPROv2') as mock_optimizer:
            mock_optimizer.return_value.compile.return_value = Mock()
            
            extractor = create_optimized_extractor(
                training_data=training_data,
                metric_fn=lambda pred, expected: 0.9
            )
            
            assert extractor is not None
            mock_optimizer.return_value.compile.assert_called_once()
    
    def test_extraction_accuracy_metric(self):
        """Test the accuracy metric for extraction."""
        from sca_ai_scanner.dspy_modules.cve_extractor import calculate_extraction_accuracy
        
        predicted = {
            'cve_id': 'CVE-2020-8203',
            'severity': 'HIGH',
            'cvss_score': 7.4,
            'description': 'Prototype pollution'
        }
        
        expected = {
            'cve_id': 'CVE-2020-8203',
            'severity': 'HIGH',
            'cvss_score': 7.5,  # Slightly different
            'description': 'Prototype pollution vulnerability'
        }
        
        accuracy = calculate_extraction_accuracy(predicted, expected)
        
        # Should have high accuracy (CVE ID and severity match)
        assert accuracy > 0.8
        assert accuracy < 1.0  # Not perfect due to CVSS difference


@pytest.mark.integration
class TestCVEExtractionIntegration:
    """Integration tests for CVE extraction."""
    
    def test_end_to_end_extraction(self):
        """Test complete CVE extraction flow."""
        with patch('dspy.OpenAI') as mock_openai:
            mock_openai.return_value.request.return_value = {
                'cve_id': 'CVE-2020-8203',
                'severity': 'HIGH',
                'cvss_score': 7.4,
                'description': 'Prototype pollution vulnerability',
                'published_date': '2020-07-15',
                'affected_versions': '<4.17.20',
                'fixed_versions': '>=4.17.20',
                'references': ['https://nvd.nist.gov/vuln/detail/CVE-2020-8203']
            }
            
            # Configure DSPy
            dspy.settings.configure(lm=mock_openai())
            
            # Create and use extractor
            extractor = StructuredCVEExtractor()
            
            text = "CVE-2020-8203: High severity prototype pollution in lodash"
            
            cves = extractor.extract_cves_from_text(
                text=text,
                package_name='lodash',
                package_version='4.17.19'
            )
            
            assert len(cves) > 0
            assert cves[0]['cve_id'] == 'CVE-2020-8203'
            assert cves[0]['severity'] == 'HIGH'
            assert isinstance(cves[0]['cvss_score'], float)