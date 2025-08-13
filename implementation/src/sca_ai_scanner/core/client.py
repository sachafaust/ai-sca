"""
Core AI vulnerability client with multi-provider support.
Implements the AI Agent First design with balanced token efficiency.
"""

import asyncio
import os
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
import json
import logging

import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential

from .models import (
    Package, VulnerabilityResults, PackageAnalysis, CVEFinding, 
    ScanConfig, Severity, AIAgentMetadata, VulnerabilitySummary
)
from .optimizer import TokenOptimizer
from ..exceptions import (
    AIClientError, AuthenticationError, RateLimitError, 
    BudgetExceededError, UnsupportedModelError
)

logger = logging.getLogger(__name__)


class AIVulnerabilityClient:
    """
    AI-powered vulnerability client with multi-provider support.
    Optimized for AI Agent First operation with context window efficiency.
    """
    
    # Model capabilities mapping
    LIVE_SEARCH_MODELS = {
        "gpt-4o-with-search", "gpt-4o-mini-with-search",
        "claude-3.5-sonnet-tools", "claude-3.5-haiku-tools", 
        "gemini-2.5-pro-search", "gemini-2.0-flash-search",
        "grok-3-web", "grok-3-mini-web"
    }
    
    # Comprehensive provider mapping for all current AI models (2025)
    PROVIDER_MAPPING = {
        # OpenAI Models
        "gpt-": "openai",          # GPT series (gpt-4o, gpt-4.1, etc.)
        "o1": "openai",            # o1 (exact match)
        "o1-": "openai",           # o1 series (o1-mini, o1-preview)
        "o2": "openai",            # o2 (exact match)
        "o2-": "openai",           # o2 series
        "o3": "openai",            # o3 (exact match)  
        "o3-": "openai",           # o3 series (o3-pro)
        "o4": "openai",            # o4 (exact match)
        "o4-": "openai",           # o4 series (o4-mini)
        
        # Anthropic Claude Models
        "claude-": "anthropic",    # All Claude series (claude-3.5, claude-4, etc.)
        
        # Google Gemini Models  
        "gemini-": "google",       # All Gemini series (gemini-2.0, gemini-2.5, etc.)
        
        # X.AI Grok Models
        "grok-": "xai",           # All Grok series (grok-3, grok-4, etc.)
        "grok": "xai",            # grok (exact match)
        
        # Additional model patterns that may emerge
        "chat-": "openai",         # Potential future OpenAI naming
        "text-": "openai",         # Legacy/future OpenAI text models
    }
    
    def __init__(self, config: ScanConfig):
        """Initialize AI vulnerability client with configuration."""
        self.config = config
        self.session_id = str(uuid.uuid4())
        self.token_optimizer = TokenOptimizer(config)
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Determine provider and capabilities
        self.provider = self._detect_provider(config.model)
        self.supports_live_search = self._check_live_search_support(config.model)
        self.is_reasoning_model = self._is_reasoning_model(config.model)
        
        # Configure API authentication
        self.api_keys = self._load_api_keys()
        self._validate_authentication()
        
        # Initialize provider-specific clients
        self._setup_provider_client()
        
        # Cost tracking
        self.total_cost = 0.0
        self.daily_cost = 0.0
        
        logger.info(
            f"Initialized AI client: model={config.model}, provider={self.provider}, "
            f"live_search={self.supports_live_search}, reasoning={self.is_reasoning_model}"
        )
    
    def _detect_provider(self, model: str) -> str:
        """Auto-detect AI provider from model name."""
        # Check for exact matches first (like 'o1')
        if model in self.PROVIDER_MAPPING:
            return self.PROVIDER_MAPPING[model]
        
        # Then check prefix matches
        for prefix, provider in self.PROVIDER_MAPPING.items():
            if model.startswith(prefix):
                return provider
        raise UnsupportedModelError(f"Unknown model provider for: {model}")
    
    def _check_live_search_support(self, model: str) -> bool:
        """Check if model supports live web search capabilities."""
        return any(live_model in model for live_model in self.LIVE_SEARCH_MODELS)
    
    def _is_reasoning_model(self, model: str) -> bool:
        """Check if model is a reasoning model that uses max_completion_tokens."""
        # OpenAI reasoning models (o-series) require max_completion_tokens instead of max_tokens
        reasoning_models = ['o1', 'o2', 'o3', 'o4']
        return any(model.startswith(prefix) or model == prefix for prefix in reasoning_models)
    
    def _load_api_keys(self) -> Dict[str, Optional[str]]:
        """Load API keys from environment variables only (security requirement)."""
        return {
            'openai': os.getenv('OPENAI_API_KEY'),
            'anthropic': os.getenv('ANTHROPIC_API_KEY'),
            'google': os.getenv('GOOGLE_AI_API_KEY'),
            'xai': os.getenv('XAI_API_KEY')
        }
    
    def _validate_authentication(self) -> None:
        """Validate that required API key is available."""
        api_key = self.api_keys.get(self.provider)
        if not api_key:
            raise AuthenticationError(
                f"API key not found for {self.provider}. "
                f"Set environment variable: {self.provider.upper()}_API_KEY"
            )
    
    def _setup_provider_client(self) -> None:
        """Setup provider-specific client configuration."""
        if self.provider == "openai":
            self._setup_openai_client()
        elif self.provider == "anthropic":
            self._setup_anthropic_client()
        elif self.provider == "google":
            self._setup_google_client()
        elif self.provider == "xai":
            self._setup_xai_client()
        else:
            raise UnsupportedModelError(f"Provider not implemented: {self.provider}")
    
    def _setup_openai_client(self) -> None:
        """Setup OpenAI client configuration."""
        self.base_url = "https://api.openai.com/v1"
        self.headers = {
            "Authorization": f"Bearer {self.api_keys['openai']}",
            "Content-Type": "application/json"
        }
        # Token costs per 1K tokens (input, output)
        self.token_costs = {
            "gpt-4o-mini": (0.00015, 0.0006),
            "gpt-4o": (0.005, 0.015),
            "gpt-4": (0.03, 0.06),
            "o1-mini": (0.003, 0.012),
            "o1": (0.015, 0.06)
        }
    
    def _setup_anthropic_client(self) -> None:
        """Setup Anthropic client configuration."""
        self.base_url = "https://api.anthropic.com/v1"
        self.headers = {
            "x-api-key": self.api_keys['anthropic'],
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01"
        }
        # Token costs per 1K tokens (input, output)
        self.token_costs = {
            "claude-3.5-sonnet": (0.003, 0.015),
            "claude-3.5-haiku": (0.00025, 0.00125),
            "claude-3-opus": (0.015, 0.075)
        }
    
    def _setup_google_client(self) -> None:
        """Setup Google AI client configuration."""
        self.base_url = "https://generativelanguage.googleapis.com/v1beta"
        self.headers = {
            "Content-Type": "application/json"
        }
        # Google AI pricing (per 1K tokens)
        self.token_costs = {
            "gemini-2.5-pro": (0.00125, 0.005),
            "gemini-2.0-flash": (0.000075, 0.0003),
            "gemini-pro": (0.0005, 0.0015)
        }
    
    def _setup_xai_client(self) -> None:
        """Setup X AI client configuration."""
        self.base_url = "https://api.x.ai/v1"
        self.headers = {
            "Authorization": f"Bearer {self.api_keys['xai']}",
            "Content-Type": "application/json"
        }
        # X AI pricing estimates
        self.token_costs = {
            "grok-3": (0.005, 0.015),
            "grok-3-mini": (0.001, 0.003)
        }
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def bulk_analyze(self, packages: List[Package]) -> VulnerabilityResults:
        """
        Analyze packages with AI-powered bulk vulnerability detection.
        Implements intelligent batching and context window optimization.
        """
        if not packages:
            return self._create_empty_results()
        
        logger.info(f"Starting bulk analysis of {len(packages)} packages")
        
        # Check budget before processing
        await self._check_budget_limits()
        
        # Create batches for optimal context window utilization
        batches = self._create_batches(packages)
        logger.info(f"Created {len(batches)} batches (size: {self.config.batch_size})")
        
        # Process batches with AI analysis
        batch_results = []
        for i, batch in enumerate(batches):
            logger.info(f"Processing batch {i+1}/{len(batches)} ({len(batch)} packages)")
            
            try:
                if self.config.enable_live_search and self.supports_live_search:
                    batch_result = await self._analyze_with_live_search(batch)
                else:
                    batch_result = await self._analyze_knowledge_only(batch)
                
                batch_results.append(batch_result)
                
                # Update cost tracking
                batch_cost = batch_result.get('cost', 0.0)
                self._update_cost_tracking(batch_cost)
                
                # Check budget after accumulating costs
                await self._check_budget_limits()
                
            except BudgetExceededError:
                # Re-raise budget errors immediately
                raise
            except Exception as e:
                logger.error(f"Batch {i+1} failed: {e}")
                # Continue with other batches, mark failed packages
                batch_results.append(self._create_failed_batch_result(batch, str(e)))
        
        # Merge batch results into final vulnerability analysis
        return self._merge_batch_results(batch_results, packages)
    
    def _create_batches(self, packages: List[Package]) -> List[List[Package]]:
        """Create optimized batches for context window utilization."""
        # Use context optimization if enabled and no explicit batch size
        if self.config.context_optimization and self.config.batch_size is None:
            optimal_batch_size = self._calculate_optimal_batch_size()
            logger.info(f"Using context-optimized batch size: {optimal_batch_size}")
        else:
            optimal_batch_size = self.config.batch_size or 75  # Fallback for legacy
            logger.info(f"Using configured batch size: {optimal_batch_size}")
        
        batches = []
        current_batch = []
        
        for package in packages:
            current_batch.append(package)
            
            if len(current_batch) >= optimal_batch_size:
                batches.append(current_batch)
                current_batch = []
        
        # Add remaining packages
        if current_batch:
            batches.append(current_batch)
        
        return batches
    
    def _calculate_optimal_batch_size(self) -> int:
        """Calculate optimal batch size based on model's context window."""
        # Model context window sizes (approximate)
        context_windows = {
            "gpt-4o": 128000,
            "gpt-4o-mini": 128000,
            "o1": 200000,
            "o1-mini": 128000,
            "claude-3.5-sonnet": 200000,
            "claude-3.5-haiku": 200000,
            "gemini-2.5-pro": 2000000,  # 2M context window
            "gemini-2.0-flash": 1000000,  # 1M context window
            "gemini-1.5-pro": 2000000,
            "grok-3": 128000,
            "grok-3-mini": 128000
        }
        
        # Get base model name
        base_model = self.config.model.replace("-with-search", "").replace("-tools", "").replace("-web", "").replace("-search", "")
        
        # Find matching context window
        context_size = None
        for model_prefix in context_windows:
            if base_model.startswith(model_prefix):
                context_size = context_windows[model_prefix]
                break
        
        if not context_size:
            logger.warning(f"Unknown context window for {base_model}, using default")
            return 75  # Conservative default
        
        # Estimate tokens per package (package name + version + analysis prompt overhead)
        # Conservative estimate: ~100 tokens per package for metadata + 200 tokens for analysis
        estimated_tokens_per_package = 300
        
        # Reserve 20% of context for response and system prompts
        usable_context = int(context_size * 0.8)
        
        theoretical_batch = max(1, min(300, usable_context // estimated_tokens_per_package))
        
        # Use theoretical batch size based on context window optimization
        # Previous 30-package limit was for debugging - now using full context
        optimal_batch = theoretical_batch
        
        logger.info(f"Model {base_model}: {context_size} context → {optimal_batch} packages per batch (limited to tested safe range, theoretical: {theoretical_batch})")
        return optimal_batch
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry_error_callback=lambda retry_state: logger.warning(
            f"Retrying AI request (attempt {retry_state.attempt_number})"
        )
    )
    async def _analyze_with_live_search(self, packages: List[Package]) -> Dict[str, Any]:
        """Analyze packages with live web search for current vulnerability data."""
        prompt = self.token_optimizer.create_prompt_with_live_search(packages)
        
        if self.provider == "openai":
            return await self._call_openai_with_search(prompt)
        elif self.provider == "anthropic":
            return await self._call_anthropic_with_tools(prompt)
        elif self.provider == "google":
            return await self._call_google_with_search(prompt)
        elif self.provider == "xai":
            return await self._call_xai_with_web(prompt)
        else:
            raise UnsupportedModelError(f"Live search not supported for {self.provider}")
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10)
    )
    async def _analyze_knowledge_only(self, packages: List[Package]) -> Dict[str, Any]:
        """Analyze packages using model's training knowledge only."""
        prompt = self.token_optimizer.create_prompt(packages)
        
        if self.provider == "openai":
            return await self._call_openai_standard(prompt)
        elif self.provider == "anthropic":
            return await self._call_anthropic_standard(prompt)
        elif self.provider == "google":
            return await self._call_google_standard(prompt)
        elif self.provider == "xai":
            return await self._call_xai_standard(prompt)
        else:
            raise UnsupportedModelError(f"Provider not implemented: {self.provider}")
    
    async def _call_openai_with_search(self, prompt: str) -> Dict[str, Any]:
        """Call OpenAI API with web search capabilities."""
        # Use max_completion_tokens for reasoning models (o1, o2, o3, o4), max_tokens for others
        token_param = "max_completion_tokens" if self.is_reasoning_model else "max_tokens"
        
        payload = {
            "model": self.config.model,
            "messages": [{"role": "user", "content": prompt}],
            token_param: 2048,
        }
        
        # Only add temperature for non-reasoning models
        if not self.is_reasoning_model:
            payload["temperature"] = 0.1
        
        # Add tools for search-enabled models
        if "with-search" in self.config.model:
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": "web_search",
                        "description": "Search web for current vulnerability information",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "query": {"type": "string", "description": "Search query"}
                            },
                            "required": ["query"]
                        }
                    }
                }
            ]
        
        return await self._make_api_request(f"{self.base_url}/chat/completions", payload)
    
    async def _call_openai_standard(self, prompt: str) -> Dict[str, Any]:
        """Call OpenAI API without web search."""
        # Use max_completion_tokens for reasoning models (o1, o2, o3, o4), max_tokens for others
        token_param = "max_completion_tokens" if self.is_reasoning_model else "max_tokens"
        
        payload = {
            "model": self.config.model,
            "messages": [{"role": "user", "content": prompt}],
            token_param: 2048
        }
        
        # Only add temperature for non-reasoning models
        if not self.is_reasoning_model:
            payload["temperature"] = 0.1
        
        return await self._make_api_request(f"{self.base_url}/chat/completions", payload)
    
    async def _call_anthropic_with_tools(self, prompt: str) -> Dict[str, Any]:
        """Call Anthropic API with tool use for live CVE lookup."""
        payload = {
            "model": self.config.model,
            "max_tokens": 4096,
            "temperature": 0.0,
            "messages": [{"role": "user", "content": prompt}],
            "tools": [
                {
                    "name": "web_search",
                    "description": "Search web for current CVE information",
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string", "description": "CVE search query"}
                        },
                        "required": ["query"]
                    }
                }
            ] if "tools" in self.config.model else None
        }
        
        return await self._make_api_request(f"{self.base_url}/messages", payload)
    
    async def _call_anthropic_standard(self, prompt: str) -> Dict[str, Any]:
        """Call Anthropic API without tools."""
        payload = {
            "model": self.config.model,
            "max_tokens": 4096,
            "temperature": 0.0,
            "messages": [{"role": "user", "content": prompt}]
        }
        
        return await self._make_api_request(f"{self.base_url}/messages", payload)
    
    async def _call_google_with_search(self, prompt: str) -> Dict[str, Any]:
        """Call Google AI API with search capabilities."""
        # Fix model naming for Google API
        model_name = self._normalize_google_model_name(self.config.model)
        url = f"{self.base_url}/models/{model_name}:generateContent"
        
        logger.debug(f"Using Google model: {model_name} (from config: {self.config.model})")
        
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.1,
                "maxOutputTokens": 8192  # Increased for better context usage
            },
            "tools": [
                {
                    "googleSearchRetrieval": {
                        "dynamicRetrievalConfig": {
                            "mode": "MODE_DYNAMIC",
                            "dynamicThreshold": 0.7
                        }
                    }
                }
            ] if "search" in self.config.model else None
        }
        
        return await self._make_api_request(f"{url}?key={self.api_keys['google']}", payload)
    
    async def _call_google_standard(self, prompt: str) -> Dict[str, Any]:
        """Call Google AI API without search."""
        model_name = self._normalize_google_model_name(self.config.model)
        url = f"{self.base_url}/models/{model_name}:generateContent"
        
        logger.debug(f"Using Google model: {model_name} (from config: {self.config.model})")
        
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.1,
                "maxOutputTokens": 8192  # Increased for better context usage
            }
        }
        
        return await self._make_api_request(f"{url}?key={self.api_keys['google']}", payload)
    
    def _normalize_google_model_name(self, model: str) -> str:
        """Normalize model name for Google AI API."""
        # Map our model names to Google's actual API model names
        model_mapping = {
            "gemini-2.5-pro": "gemini-2.0-flash-exp",  # Gemini 2.5 Pro is experimental
            "gemini-2.5-pro-search": "gemini-2.0-flash-exp",
            "gemini-2.0-flash": "gemini-2.0-flash-exp",
            "gemini-2.0-flash-search": "gemini-2.0-flash-exp",
            "gemini-pro": "gemini-1.5-pro",
            "gemini-pro-search": "gemini-1.5-pro"
        }
        
        # Remove search suffix for lookup
        base_model = model.replace("-search", "")
        normalized = model_mapping.get(base_model, base_model)
        
        logger.debug(f"Model name mapping: {model} -> {base_model} -> {normalized}")
        return normalized
    
    async def _call_xai_with_web(self, prompt: str) -> Dict[str, Any]:
        """Call X AI API with web access."""
        payload = {
            "model": self.config.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "max_tokens": 2048,
            "stream": False
        }
        
        return await self._make_api_request(f"{self.base_url}/chat/completions", payload)
    
    async def _call_xai_standard(self, prompt: str) -> Dict[str, Any]:
        """Call X AI API without web access."""
        model_name = self.config.model.replace("-web", "")
        payload = {
            "model": model_name,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "max_tokens": 2048,
            "stream": False
        }
        
        return await self._make_api_request(f"{self.base_url}/chat/completions", payload)
    
    async def _make_api_request(self, url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Make HTTP request to AI provider API with error handling."""
        if not self.session:
            raise AIClientError("Client session not initialized")
        
        # Log request details for debugging
        logger.debug(f"Making API request to {self.provider}")
        logger.debug(f"URL: {url}")
        logger.debug(f"Headers: {dict(self.headers)}")
        logger.debug(f"Payload keys: {list(payload.keys())}")
        
        # DETAILED PROMPT LOGGING - Log the exact prompt sent to LLM
        if "contents" in payload and payload["contents"]:
            prompt_text = payload["contents"][0]["parts"][0]["text"]
            logger.info(f"🎯 PROMPT SENT TO {self.provider.upper()}:")
            logger.info(f"📝 {'-'*60}")
            logger.info(f"{prompt_text}")
            logger.info(f"📝 {'-'*60}")
        elif "messages" in payload:
            prompt_text = payload["messages"][-1]["content"]
            logger.info(f"🎯 PROMPT SENT TO {self.provider.upper()}:")
            logger.info(f"📝 {'-'*60}")
            logger.info(f"{prompt_text}")
            logger.info(f"📝 {'-'*60}")
        
        try:
            async with self.session.post(url, json=payload, headers=self.headers) as response:
                # Log response details
                logger.debug(f"Response status: {response.status}")
                logger.debug(f"Response headers: {dict(response.headers)}")
                
                if response.status == 401:
                    raise AuthenticationError(f"Invalid API key for {self.provider}")
                elif response.status == 429:
                    raise RateLimitError(f"Rate limit exceeded for {self.provider}")
                elif response.status >= 400:
                    error_text = await response.text()
                    logger.error(f"API error response: {error_text}")
                    raise AIClientError(f"API error ({response.status}): {error_text}")
                
                result = await response.json()
                
                # Log raw response for debugging (truncated for security)
                logger.debug(f"Raw API response keys: {list(result.keys()) if isinstance(result, dict) else type(result)}")
                if isinstance(result, dict) and len(str(result)) < 1000:
                    logger.debug(f"Raw API response: {result}")
                else:
                    logger.debug("Raw API response too large to log safely")
                
                # DETAILED RESPONSE LOGGING - Log the exact response from LLM
                if isinstance(result, dict) and "candidates" in result:
                    logger.info(f"🎯 RESPONSE FROM {self.provider.upper()}:")
                    logger.info(f"📤 {'-'*60}")
                    if result['candidates'] and 'content' in result['candidates'][0]:
                        content = result['candidates'][0]['content']
                        if 'parts' in content and content['parts']:
                            response_text = content['parts'][0].get('text', str(content['parts'][0]))
                            logger.info(f"{response_text}")
                        else:
                            logger.info(f"Content structure: {content}")
                    else:
                        logger.info(f"No content found in candidates: {result['candidates']}")
                    logger.info(f"📤 {'-'*60}")
                    
                    # Also log usage metadata
                    if 'usageMetadata' in result:
                        usage = result['usageMetadata']
                        logger.info(f"💰 TOKEN USAGE: Input: {usage.get('promptTokenCount', 0)}, Output: {usage.get('candidatesTokenCount', 0)}")
                else:
                    logger.info(f"🎯 RESPONSE FROM {self.provider.upper()}:")
                    logger.info(f"📤 {'-'*60}")
                    logger.info(f"{str(result)[:1000]}...")
                    logger.info(f"📤 {'-'*60}")
                
                # Parse response and calculate costs
                parsed_result = self._parse_api_response(result)
                logger.debug(f"Parsed result keys: {list(parsed_result.keys())}")
                return parsed_result
                
        except aiohttp.ClientError as e:
            logger.error(f"Network error for {self.provider}: {e}")
            raise AIClientError(f"Network error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during API request to {self.provider}: {e}")
            raise
    
    def _parse_api_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Parse AI provider response into standardized format with robust error handling."""
        try:
            if self.provider == "openai":
                return self._parse_openai_response(response)
            elif self.provider == "anthropic":
                return self._parse_anthropic_response(response)
            elif self.provider == "google":
                return self._parse_google_response(response)
            elif self.provider == "xai":
                return self._parse_xai_response(response)
            else:
                raise UnsupportedModelError(f"Response parser not implemented: {self.provider}")
        except Exception as e:
            logger.error(f"Critical error parsing {self.provider} response: {e}")
            # Return graceful fallback to prevent complete failure
            return {
                "vulnerability_data": {
                    "critical_parsing_error": True,
                    "error_message": str(e),
                    "provider": self.provider,
                    "raw_response_type": type(response).__name__
                },
                "cost": 0.0,
                "tokens": {"input": 0, "output": 0},
                "provider": self.provider,
                "error": f"Critical parsing failure: {e}"
            }
    
    def _parse_openai_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Parse OpenAI API response with robust error handling."""
        try:
            logger.debug(f"Parsing OpenAI response with keys: {list(response.keys())}")
            
            # Extract content with fallbacks
            content = None
            if "choices" in response and response["choices"]:
                choice = response["choices"][0]
                if "message" in choice and "content" in choice["message"]:
                    content = choice["message"]["content"]
                elif "text" in choice:  # Completion API format
                    content = choice["text"]
                else:
                    logger.warning(f"Unexpected OpenAI choice format: {list(choice.keys())}")
                    content = str(choice)
            
            if not content:
                logger.error(f"Could not extract content from OpenAI response: {response}")
                return {
                    "vulnerability_data": {"parsing_error": True, "raw_response": str(response)},
                    "cost": 0.0,
                    "tokens": {"input": 0, "output": 0},
                    "provider": "openai",
                    "error": "Failed to extract content from response"
                }
            
            usage = response.get("usage", {})
            input_tokens = usage.get("prompt_tokens", 0)
            output_tokens = usage.get("completion_tokens", 0)
            cost = self._calculate_openai_cost(input_tokens, output_tokens)
            
            vulnerability_data = self._extract_vulnerability_json(content)
            
            return {
                "vulnerability_data": vulnerability_data,
                "cost": cost,
                "tokens": {"input": input_tokens, "output": output_tokens},
                "provider": "openai"
            }
            
        except Exception as e:
            logger.error(f"Failed to parse OpenAI response: {e}")
            return {
                "vulnerability_data": {
                    "parsing_error": True,
                    "error_message": str(e),
                    "raw_response": str(response)[:500] + "..." if len(str(response)) > 500 else str(response)
                },
                "cost": 0.0,
                "tokens": {"input": 0, "output": 0},
                "provider": "openai",
                "error": f"Response parsing failed: {e}"
            }
    
    def _parse_anthropic_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Anthropic API response with robust error handling."""
        try:
            logger.debug(f"Parsing Anthropic response with keys: {list(response.keys())}")
            
            # Extract content with fallbacks
            content = None
            if "content" in response and response["content"]:
                if isinstance(response["content"], list) and response["content"]:
                    first_content = response["content"][0]
                    if isinstance(first_content, dict) and "text" in first_content:
                        content = first_content["text"]
                    else:
                        content = str(first_content)
                elif isinstance(response["content"], str):
                    content = response["content"]
            
            if not content:
                logger.error(f"Could not extract content from Anthropic response: {response}")
                return {
                    "vulnerability_data": {"parsing_error": True, "raw_response": str(response)},
                    "cost": 0.0,
                    "tokens": {"input": 0, "output": 0},
                    "provider": "anthropic",
                    "error": "Failed to extract content from response"
                }
            
            usage = response.get("usage", {})
            input_tokens = usage.get("input_tokens", 0)
            output_tokens = usage.get("output_tokens", 0)
            cost = self._calculate_anthropic_cost(input_tokens, output_tokens)
            
            vulnerability_data = self._extract_vulnerability_json(content)
            
            return {
                "vulnerability_data": vulnerability_data,
                "cost": cost,
                "tokens": {"input": input_tokens, "output": output_tokens},
                "provider": "anthropic"
            }
            
        except Exception as e:
            logger.error(f"Failed to parse Anthropic response: {e}")
            return {
                "vulnerability_data": {
                    "parsing_error": True,
                    "error_message": str(e),
                    "raw_response": str(response)[:500] + "..." if len(str(response)) > 500 else str(response)
                },
                "cost": 0.0,
                "tokens": {"input": 0, "output": 0},
                "provider": "anthropic",
                "error": f"Response parsing failed: {e}"
            }
    
    def _parse_google_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Google AI API response with robust error handling."""
        try:
            logger.debug(f"Parsing Google response with keys: {list(response.keys())}")
            
            # Handle different response formats
            content = None
            if "candidates" in response and response["candidates"]:
                candidate = response["candidates"][0]
                logger.debug(f"First candidate keys: {list(candidate.keys())}")
                
                if "content" in candidate and candidate["content"]:
                    if "parts" in candidate["content"] and candidate["content"]["parts"]:
                        if "text" in candidate["content"]["parts"][0]:
                            content = candidate["content"]["parts"][0]["text"]
                        else:
                            logger.warning("No 'text' in first part, checking alternative formats")
                            # Try other potential formats
                            part = candidate["content"]["parts"][0]
                            content = part.get("text") or part.get("content") or str(part)
                    else:
                        logger.warning("No 'parts' in content, trying direct text access")
                        content = candidate["content"].get("text") or str(candidate["content"])
                else:
                    logger.warning("No 'content' in candidate, trying alternative structures")
                    # Try alternative response structures
                    content = candidate.get("text") or candidate.get("message") or str(candidate)
            else:
                logger.error("No 'candidates' found in Google response")
                # Try other potential response formats
                content = response.get("text") or response.get("content") or response.get("message")
            
            if not content:
                logger.error(f"Could not extract content from Google response: {response}")
                # Return minimal viable response instead of failing
                return {
                    "vulnerability_data": {"parsing_error": True, "raw_response": str(response)},
                    "cost": 0.0,
                    "tokens": {"input": 0, "output": 0},
                    "provider": "google",
                    "error": "Failed to extract content from response"
                }
            
            # Extract usage data with fallbacks
            usage = response.get("usageMetadata", {})
            input_tokens = usage.get("promptTokenCount", 0)
            output_tokens = usage.get("candidatesTokenCount", usage.get("outputTokenCount", 0))
            
            # Alternative usage field names
            if input_tokens == 0 and output_tokens == 0:
                usage_alt = response.get("usage", {})
                input_tokens = usage_alt.get("prompt_tokens", usage_alt.get("input_tokens", 0))
                output_tokens = usage_alt.get("completion_tokens", usage_alt.get("output_tokens", 0))
            
            cost = self._calculate_google_cost(input_tokens, output_tokens)
            vulnerability_data = self._extract_vulnerability_json(content)
            
            logger.debug(f"Successfully parsed Google response: {len(str(vulnerability_data))} chars of vulnerability data")
            logger.info(f"Extracted vulnerability data: {json.dumps(vulnerability_data, indent=2)[:500]}...")
            
            return {
                "vulnerability_data": vulnerability_data,
                "cost": cost,
                "tokens": {"input": input_tokens, "output": output_tokens},
                "provider": "google"
            }
            
        except Exception as e:
            logger.error(f"Failed to parse Google response: {e}")
            logger.error(f"Response structure: {response}")
            
            # Return graceful fallback instead of crashing
            return {
                "vulnerability_data": {
                    "parsing_error": True, 
                    "error_message": str(e),
                    "raw_response": str(response)[:500] + "..." if len(str(response)) > 500 else str(response)
                },
                "cost": 0.0,
                "tokens": {"input": 0, "output": 0},
                "provider": "google",
                "error": f"Response parsing failed: {e}"
            }
    
    def _parse_xai_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Parse X AI API response."""
        try:
            content = response["choices"][0]["message"]["content"]
            usage = response.get("usage", {})
            
            input_tokens = usage.get("prompt_tokens", 0)
            output_tokens = usage.get("completion_tokens", 0)
            cost = self._calculate_xai_cost(input_tokens, output_tokens)
            
            vulnerability_data = self._extract_vulnerability_json(content)
            
            return {
                "vulnerability_data": vulnerability_data,
                "cost": cost,
                "tokens": {"input": input_tokens, "output": output_tokens},
                "provider": "xai"
            }
            
        except (KeyError, IndexError, json.JSONDecodeError) as e:
            raise AIClientError(f"Failed to parse X AI response: {e}")
    
    def _extract_vulnerability_json(self, content: str) -> Dict[str, Any]:
        """Extract JSON vulnerability data from AI response content."""
        try:
            # First, try to extract from markdown code blocks
            if '```json' in content:
                start_idx = content.find('```json') + 7
                end_idx = content.find('```', start_idx)
                if start_idx > 6 and end_idx > start_idx:
                    json_str = content[start_idx:end_idx].strip()
                    raw_data = json.loads(json_str)
                    return self._normalize_package_keys(raw_data)
            
            # Try to find JSON in the response
            start_idx = content.find('{')
            end_idx = content.rfind('}') + 1
            
            if start_idx == -1 or end_idx == 0:
                # No JSON found, create structured response from text
                return self._parse_text_response(content)
            
            json_str = content[start_idx:end_idx]
            raw_data = json.loads(json_str)
            return self._normalize_package_keys(raw_data)
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            # Fallback to text parsing
            return self._parse_text_response(content)
    
    def _normalize_package_keys(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize package keys to consistent package:version format."""
        if not isinstance(data, dict):
            return data
            
        normalized = {}
        for key, value in data.items():
            # Extract package name and version from various formats
            if '==' in key:
                # Handle format like "aiohttp==3.12.13; python_full_version:'3.11.5'"
                parts = key.split('==', 1)
                name = parts[0].strip()
                version_part = parts[1]
                # Remove any conditions after semicolon
                if ';' in version_part:
                    version = version_part.split(';')[0].strip()
                else:
                    version = version_part.strip()
                normalized_key = f"{name}:{version}"
            elif ':' in key and ';' not in key:
                # Already in correct format
                normalized_key = key
            else:
                # Unknown format, keep as is
                normalized_key = key
                logger.warning(f"Unable to normalize package key: {key}")
            
            normalized[normalized_key] = value
            if normalized_key != key:
                logger.debug(f"Normalized package key: {key} -> {normalized_key}")
        
        return normalized
    
    def _parse_text_response(self, content: str) -> Dict[str, Any]:
        """Parse text response when JSON extraction fails."""
        # This is a fallback - in production, we'd want more sophisticated parsing
        logger.warning("Failed to extract JSON, using text parsing fallback")
        return {"raw_response": content, "parsing_failed": True}
    
    def _calculate_openai_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Calculate cost for OpenAI API usage."""
        model_base = self.config.model.split("-")[0:2]
        model_key = "-".join(model_base)
        
        if model_key in self.token_costs:
            input_cost, output_cost = self.token_costs[model_key]
            return (input_tokens * input_cost / 1000) + (output_tokens * output_cost / 1000)
        
        # Default cost estimate
        return (input_tokens * 0.001 / 1000) + (output_tokens * 0.003 / 1000)
    
    def _calculate_anthropic_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Calculate cost for Anthropic API usage."""
        model_base = "-".join(self.config.model.split("-")[0:3])
        
        if model_base in self.token_costs:
            input_cost, output_cost = self.token_costs[model_base]
            return (input_tokens * input_cost / 1000) + (output_tokens * output_cost / 1000)
        
        # Default cost estimate
        return (input_tokens * 0.003 / 1000) + (output_tokens * 0.015 / 1000)
    
    def _calculate_google_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Calculate cost for Google AI API usage."""
        model_base = self.config.model.replace("-search", "")
        
        if model_base in self.token_costs:
            input_cost, output_cost = self.token_costs[model_base]
            return (input_tokens * input_cost / 1000) + (output_tokens * output_cost / 1000)
        
        # Default cost estimate
        return (input_tokens * 0.0005 / 1000) + (output_tokens * 0.0015 / 1000)
    
    def _calculate_xai_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Calculate cost for X AI API usage."""
        model_base = self.config.model.replace("-web", "")
        
        if model_base in self.token_costs:
            input_cost, output_cost = self.token_costs[model_base]
            return (input_tokens * input_cost / 1000) + (output_tokens * output_cost / 1000)
        
        # Default cost estimate
        return (input_tokens * 0.002 / 1000) + (output_tokens * 0.006 / 1000)
    
    def _update_cost_tracking(self, batch_cost: float) -> None:
        """Update cost tracking with batch results."""
        self.total_cost += batch_cost
        self.daily_cost += batch_cost
        
        logger.info(f"Batch cost: ${batch_cost:.4f}, Total: ${self.total_cost:.4f}")
    
    async def _check_budget_limits(self) -> None:
        """Check if budget limits would be exceeded (only if budget enabled)."""
        # Only check budget if explicitly enabled
        if not self.config.budget_enabled:
            return
            
        if self.daily_cost >= self.config.daily_budget_limit:
            raise BudgetExceededError(
                f"Daily budget limit reached: ${self.daily_cost:.2f} >= ${self.config.daily_budget_limit:.2f}"
            )
    
    def _create_empty_results(self) -> VulnerabilityResults:
        """Create empty vulnerability results for edge cases."""
        return VulnerabilityResults(
            ai_agent_metadata=AIAgentMetadata(
                workflow_stage="completed",
                confidence_level="high",
                autonomous_action_recommended=True
            ),
            vulnerability_analysis={},
            vulnerability_summary=VulnerabilitySummary(
                total_packages_analyzed=0,
                vulnerable_packages=0,
                severity_breakdown={},
                recommended_next_steps=["No packages to analyze"]
            ),
            scan_metadata={
                "session_id": self.session_id,
                "model": self.config.model,
                "total_cost": 0.0
            }
        )
    
    def _create_failed_batch_result(self, packages: List[Package], error: str) -> Dict[str, Any]:
        """Create result for failed batch processing."""
        return {
            "vulnerability_data": {
                f"{pkg.name}:{pkg.version}": {
                    "error": error,
                    "confidence": 0.0
                } for pkg in packages
            },
            "cost": 0.0,
            "tokens": {"input": 0, "output": 0},
            "provider": self.provider,
            "failed": True
        }
    
    def _merge_batch_results(
        self, 
        batch_results: List[Dict[str, Any]], 
        original_packages: List[Package]
    ) -> VulnerabilityResults:
        """Merge batch results into final vulnerability analysis."""
        # This would contain the complex logic to merge all batch results
        # into a comprehensive VulnerabilityResults object
        
        merged_analysis = {}
        total_cost = 0.0
        vulnerable_count = 0
        severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        # Create mapping of package ID to source locations
        source_locations_map = {}
        for package in original_packages:
            pkg_id = f"{package.name}:{package.version}"
            source_locations_map[pkg_id] = package.source_locations
            logger.debug(f"Source location mapping: {pkg_id} -> {len(package.source_locations)} locations")
        
        for i, batch_result in enumerate(batch_results):
            vuln_data = batch_result.get("vulnerability_data", {})
            total_cost += batch_result.get("cost", 0.0)
            
            logger.info(f"Processing batch result {i+1}/{len(batch_results)} with {len(vuln_data)} packages")
            logger.debug(f"Package IDs in result: {list(vuln_data.keys())[:5]}...")
            
            # Check for parsing errors
            if isinstance(vuln_data, dict) and vuln_data.get("parsing_error"):
                logger.error(f"Batch {i+1} had parsing error: {vuln_data.get('error_message', 'Unknown error')}")
                continue
            
            batch_vulnerable_count = 0
            batch_converted_count = 0
            
            for pkg_id, analysis in vuln_data.items():
                if isinstance(analysis, dict) and "error" not in analysis:
                    # Process successful analysis
                    try:
                        converted = self._convert_to_package_analysis(analysis, pkg_id)
                        merged_analysis[pkg_id] = converted
                        batch_converted_count += 1
                        logger.debug(f"Successfully converted analysis for {pkg_id}")
                        
                        # Count vulnerabilities
                        if analysis.get("cves"):
                            vulnerable_count += 1
                            batch_vulnerable_count += 1
                            for cve in analysis.get("cves", []):
                                severity = cve.get("severity", "LOW")
                                if severity in severity_breakdown:
                                    severity_breakdown[severity] += 1
                    except Exception as e:
                        logger.error(f"Failed to convert analysis for {pkg_id}: {e}")
                        logger.error(f"Analysis data: {str(analysis)[:200]}...")
                else:
                    logger.warning(f"Skipping invalid analysis for {pkg_id}: {str(analysis)[:100]}...")
            
            logger.info(f"Batch {i+1} summary: {batch_converted_count} converted, {batch_vulnerable_count} vulnerable")
        
        # Log any AI-returned packages without source locations
        for pkg_id in merged_analysis:
            if pkg_id not in source_locations_map:
                logger.warning(f"No source locations found for AI-returned package: {pkg_id}")
                # Try to find by package name only (ignoring version mismatch)
                pkg_name = pkg_id.split(':')[0]
                for mapped_id in source_locations_map:
                    if mapped_id.startswith(f"{pkg_name}:"):
                        logger.info(f"Found potential match: {mapped_id} for {pkg_id}")
                        source_locations_map[pkg_id] = source_locations_map[mapped_id]
                        break
        
        # Create final results
        return VulnerabilityResults(
            ai_agent_metadata=AIAgentMetadata(
                workflow_stage="remediation_ready",
                confidence_level="high" if vulnerable_count > 0 else "medium",
                autonomous_action_recommended=True,
                optimization_opportunities=[]
            ),
            vulnerability_analysis=merged_analysis,
            vulnerability_summary=VulnerabilitySummary(
                total_packages_analyzed=len(original_packages),
                vulnerable_packages=vulnerable_count,
                severity_breakdown=severity_breakdown,
                recommended_next_steps=[
                    "Forward vulnerability data to remediation AI agent",
                    "Prioritize critical and high severity fixes first",
                    "Re-scan after remediation to verify fixes"
                ]
            ),
            scan_metadata={
                "session_id": self.session_id,
                "model": self.config.model,
                "provider": self.provider,
                "total_cost": total_cost,
                "live_search_enabled": self.config.enable_live_search,
                "scan_timestamp": datetime.utcnow().isoformat()
            },
            source_locations=source_locations_map
        )
    
    def _convert_to_package_analysis(self, raw_analysis: Dict[str, Any], pkg_id: str) -> PackageAnalysis:
        """Convert raw AI analysis to structured PackageAnalysis model."""
        # Convert CVEs
        cves = []
        for cve_data in raw_analysis.get("cves", []):
            cve = CVEFinding(
                id=cve_data.get("id", ""),
                severity=Severity(cve_data.get("severity", "LOW")),
                description=cve_data.get("description", ""),
                cvss_score=cve_data.get("cvss_score"),
                data_source=cve_data.get("data_source", "ai_knowledge")
            )
            cves.append(cve)
        
        return PackageAnalysis(
            cves=cves,
            confidence=raw_analysis.get("confidence", 0.8)
        )