"""
Output formatters for AI agent consumption.
Provides structured data exports optimized for downstream AI processing.
"""

from .json_output import JSONOutputFormatter

__all__ = [
    "JSONOutputFormatter"
]