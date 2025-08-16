"""
DSPy-optimized modules for AI-powered SCA vulnerability scanning.
Provides structured, optimizable components for vulnerability detection and remediation.
"""

from .vulnerability_detector import (
    VulnerabilityDetector,
    VulnerabilitySignature,
    create_optimized_detector
)

from .remediation_pipeline import (
    ChainOfThoughtRemediation,
    RemediationPipeline,
    RiskAssessmentSignature,
    VersionAnalysisSignature,
    BreakingChangeSignature,
    RemediationSignature
)

from .batch_optimizer import (
    AdaptiveBatchOptimizer,
    BatchStrategy,
    ModelCapabilities,
    create_optimized_batch_processor
)

from .cve_extractor import (
    StructuredCVEExtractor,
    TypedCVEPredictor,
    CVEEnrichmentPipeline,
    create_optimized_extractor
)

__all__ = [
    # Vulnerability Detection
    'VulnerabilityDetector',
    'VulnerabilitySignature',
    'create_optimized_detector',
    
    # Remediation Pipeline
    'ChainOfThoughtRemediation',
    'RemediationPipeline',
    'RiskAssessmentSignature',
    'VersionAnalysisSignature',
    'BreakingChangeSignature',
    'RemediationSignature',
    
    # Batch Optimization
    'AdaptiveBatchOptimizer',
    'BatchStrategy',
    'ModelCapabilities',
    'create_optimized_batch_processor',
    
    # CVE Extraction
    'StructuredCVEExtractor',
    'TypedCVEPredictor',
    'CVEEnrichmentPipeline',
    'create_optimized_extractor'
]