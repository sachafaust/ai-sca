"""
AI-Powered SCA Vulnerability Scanner

Fast, accurate vulnerability scanning powered by AI agents for multi-language codebases.
Optimized for AI Agent First operation with balanced token efficiency.
"""

__version__ = "3.0.0"
__author__ = "SCA Scanner Team"
__email__ = "security@company.com"

from .core.client import AIVulnerabilityClient
from .core.models import Package, VulnerabilityResults, CVEFinding
from .core.optimizer import TokenOptimizer
# ValidationPipeline removed - using AI-only approach
from .parsers.base import DependencyParser
from .formatters.json_output import JSONOutputFormatter

__all__ = [
    "AIVulnerabilityClient",
    "TokenOptimizer", 
    "DependencyParser",
    "JSONOutputFormatter",
    "Package",
    "VulnerabilityResults",
    "CVEFinding",
]