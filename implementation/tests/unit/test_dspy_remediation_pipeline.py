"""
Unit tests for DSPy ChainOfThought Remediation Pipeline.
Tests multi-stage reasoning for remediation recommendations.
"""

import pytest
import dspy
from unittest.mock import Mock, patch, MagicMock
from typing import List, Dict, Any

from sca_ai_scanner.dspy_modules.remediation_pipeline import (
    RiskAssessmentSignature,
    VersionAnalysisSignature,
    BreakingChangeSignature,
    RemediationSignature,
    ChainOfThoughtRemediation,
    RemediationPipeline
)
from sca_ai_scanner.core.models import Package, CVEFinding, Severity


class TestRiskAssessmentSignature:
    """Test the risk assessment signature."""
    
    def test_risk_assessment_structure(self):
        """Test RiskAssessmentSignature has correct fields."""
        sig = RiskAssessmentSignature()
        
        # Input fields
        assert hasattr(sig, 'package_name')
        assert hasattr(sig, 'current_version')
        assert hasattr(sig, 'cve_list')
        assert hasattr(sig, 'severity_scores')
        
        # Output fields
        assert hasattr(sig, 'risk_score')
        assert hasattr(sig, 'business_impact')
        assert hasattr(sig, 'exploitability')
        assert hasattr(sig, 'urgency_level')
    
    def test_risk_assessment_validation(self):
        """Test validation of risk assessment data."""
        sig = RiskAssessmentSignature()
        
        valid_data = {
            'package_name': 'django',
            'current_version': '2.2.10',
            'cve_list': ['CVE-2020-7471', 'CVE-2020-9402'],
            'severity_scores': [7.5, 5.3],
            'risk_score': 8.5,
            'business_impact': 'HIGH',
            'exploitability': 'MEDIUM',
            'urgency_level': 'CRITICAL'
        }
        
        sig.validate(valid_data)


class TestVersionAnalysisSignature:
    """Test the version analysis signature."""
    
    def test_version_analysis_structure(self):
        """Test VersionAnalysisSignature has correct fields."""
        sig = VersionAnalysisSignature()
        
        # Input fields
        assert hasattr(sig, 'package_name')
        assert hasattr(sig, 'current_version')
        assert hasattr(sig, 'available_versions')
        assert hasattr(sig, 'cve_fixed_versions')
        
        # Output fields
        assert hasattr(sig, 'recommended_version')
        assert hasattr(sig, 'version_jump_type')
        assert hasattr(sig, 'alternatives')
        assert hasattr(sig, 'analysis_reasoning')


class TestBreakingChangeSignature:
    """Test the breaking change detection signature."""
    
    def test_breaking_change_structure(self):
        """Test BreakingChangeSignature has correct fields."""
        sig = BreakingChangeSignature()
        
        # Input fields
        assert hasattr(sig, 'package_name')
        assert hasattr(sig, 'current_version')
        assert hasattr(sig, 'target_version')
        assert hasattr(sig, 'ecosystem')
        
        # Output fields
        assert hasattr(sig, 'has_breaking_changes')
        assert hasattr(sig, 'breaking_change_list')
        assert hasattr(sig, 'migration_effort')
        assert hasattr(sig, 'compatibility_notes')


class TestChainOfThoughtRemediation:
    """Test the complete Chain of Thought remediation module."""
    
    @pytest.fixture
    def mock_lm(self):
        """Mock language model for testing."""
        mock = MagicMock()
        return mock
    
    @pytest.fixture
    def remediation_module(self, mock_lm):
        """Create remediation module with mocked LM."""
        with patch('dspy.settings.lm', mock_lm):
            return ChainOfThoughtRemediation()
    
    def test_module_initialization(self, remediation_module):
        """Test module initializes with all stages."""
        assert remediation_module is not None
        assert hasattr(remediation_module, 'risk_assessor')
        assert hasattr(remediation_module, 'version_analyzer')
        assert hasattr(remediation_module, 'breaking_change_detector')
        assert hasattr(remediation_module, 'final_recommender')
    
    def test_full_pipeline_execution(self, remediation_module):
        """Test complete pipeline execution."""
        with patch.object(remediation_module.risk_assessor, 'forward') as mock_risk:
            with patch.object(remediation_module.version_analyzer, 'forward') as mock_version:
                with patch.object(remediation_module.breaking_change_detector, 'forward') as mock_breaking:
                    with patch.object(remediation_module.final_recommender, 'forward') as mock_final:
                        
                        # Setup mock returns
                        mock_risk.return_value = Mock(
                            risk_score=8.5,
                            business_impact='HIGH',
                            exploitability='MEDIUM',
                            urgency_level='CRITICAL'
                        )
                        
                        mock_version.return_value = Mock(
                            recommended_version='2.2.28',
                            version_jump_type='PATCH',
                            alternatives=['3.2.18'],
                            analysis_reasoning='Security patch available'
                        )
                        
                        mock_breaking.return_value = Mock(
                            has_breaking_changes=False,
                            breaking_change_list=[],
                            migration_effort='LOW',
                            compatibility_notes='Drop-in replacement'
                        )
                        
                        mock_final.return_value = Mock(
                            action='UPGRADE',
                            target_version='2.2.28',
                            urgency='IMMEDIATE',
                            estimated_effort='LOW',
                            confidence=0.95
                        )
                        
                        # Execute pipeline
                        result = remediation_module.forward(
                            package_name='django',
                            current_version='2.2.10',
                            cve_list=['CVE-2020-7471', 'CVE-2020-9402'],
                            severity_scores=[7.5, 5.3]
                        )
                        
                        assert result.action == 'UPGRADE'
                        assert result.target_version == '2.2.28'
                        assert result.urgency == 'IMMEDIATE'
                        assert result.confidence == 0.95
    
    def test_pipeline_with_breaking_changes(self, remediation_module):
        """Test pipeline handles breaking changes correctly."""
        with patch.object(remediation_module, 'risk_assessor') as mock_risk:
            with patch.object(remediation_module, 'version_analyzer') as mock_version:
                with patch.object(remediation_module, 'breaking_change_detector') as mock_breaking:
                    with patch.object(remediation_module, 'final_recommender') as mock_final:
                        
                        # Setup scenario with breaking changes
                        mock_risk.forward.return_value = Mock(
                            risk_score=9.0,
                            urgency_level='CRITICAL'
                        )
                        
                        mock_version.forward.return_value = Mock(
                            recommended_version='3.0.0',
                            version_jump_type='MAJOR'
                        )
                        
                        mock_breaking.forward.return_value = Mock(
                            has_breaking_changes=True,
                            breaking_change_list=['API changes', 'Config format'],
                            migration_effort='HIGH'
                        )
                        
                        mock_final.forward.return_value = Mock(
                            action='UPGRADE_WITH_CAUTION',
                            target_version='3.0.0',
                            urgency='HIGH',
                            estimated_effort='HIGH'
                        )
                        
                        result = remediation_module.forward(
                            package_name='flask',
                            current_version='0.12.2',
                            cve_list=['CVE-2018-1000656'],
                            severity_scores=[7.5]
                        )
                        
                        assert result.action == 'UPGRADE_WITH_CAUTION'
                        assert result.estimated_effort == 'HIGH'


class TestRemediationPipeline:
    """Test the complete remediation pipeline with optimization."""
    
    def test_pipeline_initialization(self):
        """Test pipeline initializes correctly."""
        pipeline = RemediationPipeline()
        
        assert pipeline is not None
        assert hasattr(pipeline, 'chain_of_thought')
        assert hasattr(pipeline, 'strategy_selector')
        assert hasattr(pipeline, 'cache')
    
    def test_pipeline_process_single_package(self):
        """Test processing a single package through the pipeline."""
        pipeline = RemediationPipeline()
        
        package = Package(
            name='django',
            version='2.2.10',
            ecosystem='pypi',
            source_locations=[]
        )
        
        vulnerabilities = [
            CVEFinding(
                id='CVE-2020-7471',
                severity=Severity.HIGH,
                description='SQL injection',
                cvss_score=7.5
            )
        ]
        
        with patch.object(pipeline.chain_of_thought, 'forward') as mock_cot:
            mock_cot.return_value = Mock(
                action='UPGRADE',
                target_version='2.2.28',
                urgency='IMMEDIATE',
                estimated_effort='LOW',
                confidence=0.95
            )
            
            recommendation = pipeline.generate_recommendation(
                package=package,
                vulnerabilities=vulnerabilities,
                strategy='balanced_security'
            )
            
            assert recommendation is not None
            assert recommendation['action'] == 'UPGRADE'
            assert recommendation['target_version'] == '2.2.28'
    
    def test_pipeline_batch_processing(self):
        """Test batch processing of multiple packages."""
        pipeline = RemediationPipeline()
        
        packages_with_vulns = [
            {
                'package': Package(name='django', version='2.2.10', ecosystem='pypi', source_locations=[]),
                'vulnerabilities': [CVEFinding(id='CVE-2020-7471', severity=Severity.HIGH, description='SQL', cvss_score=7.5)]
            },
            {
                'package': Package(name='flask', version='0.12.2', ecosystem='pypi', source_locations=[]),
                'vulnerabilities': [CVEFinding(id='CVE-2018-1000656', severity=Severity.HIGH, description='DoS', cvss_score=7.5)]
            }
        ]
        
        with patch.object(pipeline, 'generate_recommendation') as mock_gen:
            mock_gen.return_value = {
                'action': 'UPGRADE',
                'target_version': '2.2.28',
                'urgency': 'IMMEDIATE'
            }
            
            recommendations = pipeline.batch_process(
                packages_with_vulns,
                strategy='balanced_security'
            )
            
            assert len(recommendations) == 2
            assert mock_gen.call_count == 2
    
    def test_pipeline_caching(self):
        """Test that pipeline caches results appropriately."""
        pipeline = RemediationPipeline()
        
        package = Package(
            name='django',
            version='2.2.10',
            ecosystem='pypi',
            source_locations=[]
        )
        
        vulnerabilities = [
            CVEFinding(
                id='CVE-2020-7471',
                severity=Severity.HIGH,
                description='SQL injection',
                cvss_score=7.5
            )
        ]
        
        with patch.object(pipeline.chain_of_thought, 'forward') as mock_cot:
            mock_cot.return_value = Mock(
                action='UPGRADE',
                target_version='2.2.28',
                urgency='IMMEDIATE',
                estimated_effort='LOW',
                confidence=0.95
            )
            
            # First call
            rec1 = pipeline.generate_recommendation(
                package=package,
                vulnerabilities=vulnerabilities,
                strategy='balanced_security'
            )
            
            # Second call with same inputs
            rec2 = pipeline.generate_recommendation(
                package=package,
                vulnerabilities=vulnerabilities,
                strategy='balanced_security'
            )
            
            # Should only call chain_of_thought once due to caching
            assert mock_cot.call_count == 1
            assert rec1 == rec2
    
    def test_pipeline_strategy_selection(self):
        """Test different strategies produce different recommendations."""
        pipeline = RemediationPipeline()
        
        package = Package(
            name='django',
            version='2.2.10',
            ecosystem='pypi',
            source_locations=[]
        )
        
        vulnerabilities = [
            CVEFinding(
                id='CVE-2020-7471',
                severity=Severity.HIGH,
                description='SQL injection',
                cvss_score=7.5
            )
        ]
        
        # Test conservative strategy
        with patch.object(pipeline, 'strategy_selector') as mock_selector:
            mock_selector.return_value = 'conservative'
            
            with patch.object(pipeline.chain_of_thought, 'forward') as mock_cot:
                mock_cot.return_value = Mock(
                    action='DEFER',
                    target_version='2.2.10',
                    urgency='LOW',
                    estimated_effort='NONE',
                    confidence=0.85
                )
                
                rec_conservative = pipeline.generate_recommendation(
                    package=package,
                    vulnerabilities=vulnerabilities,
                    strategy='conservative_stability'
                )
                
                assert rec_conservative['urgency'] == 'LOW'
        
        # Test aggressive strategy
        with patch.object(pipeline, 'strategy_selector') as mock_selector:
            mock_selector.return_value = 'aggressive'
            
            with patch.object(pipeline.chain_of_thought, 'forward') as mock_cot:
                mock_cot.return_value = Mock(
                    action='UPGRADE',
                    target_version='3.2.18',
                    urgency='IMMEDIATE',
                    estimated_effort='HIGH',
                    confidence=0.95
                )
                
                rec_aggressive = pipeline.generate_recommendation(
                    package=package,
                    vulnerabilities=vulnerabilities,
                    strategy='aggressive_security'
                )
                
                assert rec_aggressive['urgency'] == 'IMMEDIATE'
                assert rec_aggressive['target_version'] != rec_conservative.get('target_version')


@pytest.mark.integration
class TestRemediationIntegration:
    """Integration tests for the remediation pipeline."""
    
    def test_end_to_end_remediation_flow(self):
        """Test complete remediation flow with DSPy."""
        with patch('dspy.OpenAI') as mock_openai:
            # Configure mock responses for each stage
            mock_openai.return_value.request.side_effect = [
                # Risk assessment response
                {
                    'risk_score': 8.5,
                    'business_impact': 'HIGH',
                    'exploitability': 'MEDIUM',
                    'urgency_level': 'CRITICAL'
                },
                # Version analysis response
                {
                    'recommended_version': '2.2.28',
                    'version_jump_type': 'PATCH',
                    'alternatives': ['3.2.18'],
                    'analysis_reasoning': 'Security patch available'
                },
                # Breaking change response
                {
                    'has_breaking_changes': False,
                    'breaking_change_list': [],
                    'migration_effort': 'LOW',
                    'compatibility_notes': 'Drop-in replacement'
                },
                # Final recommendation response
                {
                    'action': 'UPGRADE',
                    'target_version': '2.2.28',
                    'urgency': 'IMMEDIATE',
                    'estimated_effort': 'LOW',
                    'confidence': 0.95
                }
            ]
            
            # Configure DSPy
            dspy.settings.configure(lm=mock_openai())
            
            # Create and use pipeline
            pipeline = RemediationPipeline()
            
            package = Package(
                name='django',
                version='2.2.10',
                ecosystem='pypi',
                source_locations=[]
            )
            
            vulnerabilities = [
                CVEFinding(
                    id='CVE-2020-7471',
                    severity=Severity.HIGH,
                    description='SQL injection',
                    cvss_score=7.5
                )
            ]
            
            recommendation = pipeline.generate_recommendation(
                package=package,
                vulnerabilities=vulnerabilities,
                strategy='balanced_security'
            )
            
            assert recommendation is not None
            assert recommendation['action'] == 'UPGRADE'
            assert recommendation['target_version'] == '2.2.28'
            assert recommendation['urgency'] == 'IMMEDIATE'