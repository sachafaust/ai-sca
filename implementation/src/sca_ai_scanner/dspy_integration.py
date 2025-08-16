"""
DSPy-powered core AI processing for SCA scanner.
All AI operations use DSPy structured approaches with intelligent fallbacks.
"""

import logging
import os
from typing import Optional, List, Dict, Any

from .core.models import Package, VulnerabilityResults
from .core.client import ScanConfig

logger = logging.getLogger(__name__)

# DSPy availability flag
DSPY_AVAILABLE = False
try:
    import dspy
    from .dspy_modules.simple_vulnerability_detector import SimpleVulnerabilityDetector
    from .dspy_modules.remediation_pipeline import RemediationPipeline
    from .dspy_modules.batch_optimizer import AdaptiveBatchOptimizer
    from .dspy_modules.cve_extractor import StructuredCVEExtractor
    DSPY_AVAILABLE = True
    logger.info("DSPy modules available for enhanced processing")
except ImportError as e:
    logger.debug(f"DSPy not available: {e}")


class DSPyEnhancedScanner:
    """Scanner with optional DSPy enhancements."""
    
    def __init__(self, config: ScanConfig):
        """Initialize DSPy-enhanced scanner.
        
        Args:
            config: Scan configuration
        """
        self.config = config
        self.dspy_enabled = False
        
        if DSPY_AVAILABLE:
            self.dspy_enabled = self._configure_dspy()
            if self.dspy_enabled:
                self._initialize_dspy_modules()
    
    def _configure_dspy(self) -> bool:
        """Configure DSPy with available LM.
        
        Returns:
            True if DSPy configured successfully
        """
        try:
            # Detect which API key is available
            if os.getenv('OPENAI_API_KEY'):
                dspy.configure(lm=dspy.LM('openai/gpt-4o-mini'))
                logger.info("DSPy configured with OpenAI")
                return True
            elif os.getenv('ANTHROPIC_API_KEY'):
                dspy.configure(lm=dspy.LM('anthropic/claude-3-haiku-20240307'))
                logger.info("DSPy configured with Anthropic")
                return True
            elif os.getenv('GOOGLE_AI_API_KEY'):
                dspy.configure(lm=dspy.LM('google/gemini-1.5-flash'))
                logger.info("DSPy configured with Google")
                return True
            else:
                logger.info("No API keys found for DSPy configuration")
                return False
                
        except Exception as e:
            logger.warning(f"Failed to configure DSPy: {e}")
            return False
    
    def _initialize_dspy_modules(self):
        """Initialize DSPy modules."""
        try:
            self.vulnerability_detector = SimpleVulnerabilityDetector()
            self.remediation_pipeline = RemediationPipeline()
            self.batch_optimizer = AdaptiveBatchOptimizer(self.config.model)
            self.cve_extractor = StructuredCVEExtractor()
            logger.info("DSPy modules initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize DSPy modules: {e}")
            self.dspy_enabled = False
    
    def is_dspy_available(self) -> bool:
        """Check if DSPy enhancements are available.
        
        Returns:
            True if DSPy is configured and ready
        """
        return self.dspy_enabled
    
    def detect_vulnerabilities_enhanced(self, packages: List[Package]) -> Dict[str, Any]:
        """Enhanced vulnerability detection using DSPy.
        
        Args:
            packages: Packages to analyze
            
        Returns:
            Enhanced detection results
        """
        if not self.dspy_enabled:
            raise RuntimeError("DSPy not available for enhanced detection")
        
        try:
            # Use batch optimizer to determine optimal strategy
            optimal_strategy = self.batch_optimizer.optimize_for_packages(packages)
            logger.info(f"Using optimized batch strategy: {optimal_strategy.batch_size} per batch")
            
            # Detect vulnerabilities with structured output
            results = []
            for package in packages:
                result = self.vulnerability_detector.detect(package)
                results.append({
                    'package': f"{package.name}:{package.version}",
                    'detection': result
                })
            
            return {
                'results': results,
                'strategy_used': optimal_strategy.__dict__,
                'total_packages': len(packages),
                'enhanced': True
            }
            
        except Exception as e:
            logger.error(f"Enhanced detection failed: {e}")
            raise
    
    def generate_enhanced_remediation(
        self, 
        packages_with_vulns: List[Dict[str, Any]], 
        strategy: str = "balanced_security"
    ) -> List[Dict[str, Any]]:
        """Generate enhanced remediation recommendations.
        
        Args:
            packages_with_vulns: Packages with vulnerabilities
            strategy: Remediation strategy
            
        Returns:
            Enhanced remediation recommendations
        """
        if not self.dspy_enabled:
            raise RuntimeError("DSPy not available for enhanced remediation")
        
        try:
            recommendations = self.remediation_pipeline.batch_process(
                packages_with_vulns, 
                strategy=strategy
            )
            
            logger.info(f"Generated {len(recommendations)} enhanced recommendations")
            return recommendations
            
        except Exception as e:
            logger.error(f"Enhanced remediation failed: {e}")
            raise
    
    def extract_structured_cves(self, raw_text: str, package_name: str, package_version: str) -> List[Dict[str, Any]]:
        """Extract CVEs with structured output.
        
        Args:
            raw_text: Raw vulnerability text
            package_name: Package name
            package_version: Package version
            
        Returns:
            Structured CVE data
        """
        if not self.dspy_enabled:
            raise RuntimeError("DSPy not available for structured extraction")
        
        try:
            cves = self.cve_extractor.extract_cves_from_text(
                text=raw_text,
                package_name=package_name,
                package_version=package_version
            )
            
            logger.info(f"Extracted {len(cves)} CVEs with structured data")
            return cves
            
        except Exception as e:
            logger.error(f"Structured extraction failed: {e}")
            raise
    
    def get_enhancement_status(self) -> Dict[str, Any]:
        """Get status of DSPy enhancements.
        
        Returns:
            Enhancement status information
        """
        status = {
            'dspy_available': DSPY_AVAILABLE,
            'dspy_enabled': self.dspy_enabled,
            'modules_ready': False,
            'features': []
        }
        
        if self.dspy_enabled:
            try:
                status['modules_ready'] = all([
                    hasattr(self, 'vulnerability_detector'),
                    hasattr(self, 'remediation_pipeline'),
                    hasattr(self, 'batch_optimizer'),
                    hasattr(self, 'cve_extractor')
                ])
                
                if status['modules_ready']:
                    status['features'] = [
                        'Enhanced vulnerability detection',
                        'Chain-of-thought remediation',
                        'Adaptive batch optimization',
                        'Structured CVE extraction'
                    ]
            except Exception as e:
                logger.warning(f"Error checking module status: {e}")
        
        return status


def create_enhanced_scanner(config: ScanConfig) -> DSPyEnhancedScanner:
    """Create DSPy-enhanced scanner.
    
    Args:
        config: Scan configuration
        
    Returns:
        Enhanced scanner instance
    """
    return DSPyEnhancedScanner(config)


def is_dspy_enhancement_available() -> bool:
    """Check if DSPy enhancements are available.
    
    Returns:
        True if DSPy can be used
    """
    return DSPY_AVAILABLE and (
        os.getenv('OPENAI_API_KEY') or 
        os.getenv('ANTHROPIC_API_KEY') or 
        os.getenv('GOOGLE_AI_API_KEY')
    )