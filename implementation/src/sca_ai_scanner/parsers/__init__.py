"""
Dependency parsers for multi-language support.
Extracts package information from various dependency files.
"""

from .base import DependencyParser
from .python import PythonParser
from .javascript import JavaScriptParser

__all__ = [
    "DependencyParser",
    "PythonParser", 
    "JavaScriptParser"
]