"""
Exception classes for the AI-powered SCA scanner.
Provides clear, actionable error messages for autonomous AI agent troubleshooting.
"""


class SCAError(Exception):
    """Base exception class for SCA scanner errors."""
    pass


class AIClientError(SCAError):
    """Base exception for AI client errors."""
    pass


class AuthenticationError(AIClientError):
    """Raised when API key authentication fails."""
    
    def __init__(self, message: str, provider: str = None):
        self.provider = provider
        super().__init__(message)


class RateLimitError(AIClientError):
    """Raised when AI provider rate limits are exceeded."""
    
    def __init__(self, message: str, retry_after: int = None):
        self.retry_after = retry_after
        super().__init__(message)


class BudgetExceededError(AIClientError):
    """Raised when daily or monthly budget limits are exceeded."""
    
    def __init__(self, message: str, current_cost: float = None, limit: float = None):
        self.current_cost = current_cost
        self.limit = limit
        super().__init__(message)


class UnsupportedModelError(AIClientError):
    """Raised when an unsupported AI model is specified."""
    
    def __init__(self, message: str, model: str = None):
        self.model = model
        super().__init__(message)


class ParsingError(SCAError):
    """Raised when dependency file parsing fails."""
    
    def __init__(self, message: str, file_path: str = None, line_number: int = None):
        self.file_path = file_path
        self.line_number = line_number
        super().__init__(message)


class ValidationError(SCAError):
    """Raised when vulnerability validation fails."""
    
    def __init__(self, message: str, package: str = None, cve_id: str = None):
        self.package = package
        self.cve_id = cve_id
        super().__init__(message)


class ConfigurationError(SCAError):
    """Raised when configuration is invalid or missing."""
    
    def __init__(self, message: str, config_field: str = None):
        self.config_field = config_field
        super().__init__(message)


class TelemetryError(SCAError):
    """Raised when telemetry operations fail."""
    pass


class OutputFormattingError(SCAError):
    """Raised when output formatting fails."""
    
    def __init__(self, message: str, format_type: str = None):
        self.format_type = format_type
        super().__init__(message)