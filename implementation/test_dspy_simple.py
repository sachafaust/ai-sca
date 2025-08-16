#!/usr/bin/env python3
"""
Simple test for DSPy integration.
"""

import sys
import os
sys.path.insert(0, 'src')

import dspy
from sca_ai_scanner.dspy_modules.simple_vulnerability_detector import SimpleVulnerabilityDetector
from sca_ai_scanner.core.models import Package

def test_simple_detector():
    """Test simple detector without external dependencies."""
    
    # Mock response
    class MockLM:
        def __call__(self, *args, **kwargs):
            return type('MockResponse', (), {
                'vulnerabilities': '[]',
                'confidence': 0.9,
                'reasoning': 'No vulnerabilities found'
            })()
    
    # Configure DSPy with mock
    dspy.configure(lm=MockLM())
    
    # Create detector
    detector = SimpleVulnerabilityDetector()
    
    # Test package
    package = Package(
        name='test-package',
        version='1.0.0',
        ecosystem='npm',
        source_locations=[]
    )
    
    # Run detection
    result = detector.detect(package)
    
    print("✅ DSPy Simple Detector Test Passed!")
    print(f"   Result: {result}")
    print(f"   Confidence: {result['confidence']}")
    print(f"   Vulnerabilities: {len(result['vulnerabilities'])}")
    
    return result

if __name__ == '__main__':
    test_simple_detector()