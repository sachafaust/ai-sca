"""
Integration utilities for automatically collecting telemetry from the AI scanner.
Provides seamless integration with existing components without breaking changes.
"""

import functools
import logging
import time
from typing import Optional, Dict, Any, Callable
from contextlib import asynccontextmanager

from .engine import TelemetryEngine, TelemetryEventType, MetricType

logger = logging.getLogger(__name__)


class TelemetryIntegration:
    """Integration utilities for automatic telemetry collection."""
    
    def __init__(self, telemetry_engine: TelemetryEngine):
        self.engine = telemetry_engine
    
    def track_scan_lifecycle(self, scan_func: Callable) -> Callable:
        """Decorator to automatically track scan lifecycle events."""
        
        @functools.wraps(scan_func)
        async def wrapper(*args, **kwargs):
            # Extract relevant info from args/kwargs
            packages_count = 0
            if args and hasattr(args[1], '__len__'):  # Assuming packages is second arg
                packages_count = len(args[1])
            
            # Start scan tracking
            self.engine.log_event(
                event_type=TelemetryEventType.SCAN_STARTED,
                message=f"Starting vulnerability scan",
                data={
                    "packages_count": packages_count,
                    "function": scan_func.__name__
                }
            )
            
            timer_id = self.engine.start_timer("scan_duration")
            
            try:
                result = await scan_func(*args, **kwargs)
                
                # Extract result metrics
                vulnerable_count = 0
                if hasattr(result, 'get_vulnerable_packages'):
                    vulnerable_count = len(result.get_vulnerable_packages())
                
                duration = self.engine.stop_timer(timer_id, tags={
                    "status": "success",
                    "packages": str(packages_count)
                })
                
                self.engine.log_event(
                    event_type=TelemetryEventType.SCAN_COMPLETED,
                    message="Vulnerability scan completed successfully",
                    data={
                        "packages_scanned": packages_count,
                        "vulnerable_packages": vulnerable_count,
                        "duration_seconds": duration
                    },
                    duration_ms=duration * 1000
                )
                
                # Record performance metrics
                self.engine.record_metric("scans_completed_total", 1, MetricType.COUNTER)
                self.engine.record_metric("packages_scanned_total", packages_count, MetricType.COUNTER)
                self.engine.record_metric("vulnerabilities_found_total", vulnerable_count, MetricType.COUNTER)
                
                return result
                
            except Exception as e:
                duration = self.engine.stop_timer(timer_id, tags={
                    "status": "error",
                    "packages": str(packages_count)
                })
                
                self.engine.log_event(
                    event_type=TelemetryEventType.SCAN_FAILED,
                    message=f"Vulnerability scan failed: {str(e)}",
                    level="ERROR",
                    data={
                        "packages_count": packages_count,
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                        "duration_seconds": duration
                    },
                    duration_ms=duration * 1000
                )
                
                self.engine.record_metric("scans_failed_total", 1, MetricType.COUNTER, 
                                        tags={"error_type": type(e).__name__})
                
                raise
        
        return wrapper
    
    def track_ai_requests(self, request_func: Callable) -> Callable:
        """Decorator to automatically track AI API requests and costs."""
        
        @functools.wraps(request_func)
        async def wrapper(*args, **kwargs):
            # Extract AI client info if available
            client_info = {}
            if args and hasattr(args[0], 'provider'):  # Assuming self is first arg
                client = args[0]
                client_info = {
                    "provider": getattr(client, 'provider', 'unknown'),
                    "model": getattr(client, 'config', {}).model if hasattr(client, 'config') else 'unknown'
                }
            
            self.engine.log_event(
                event_type=TelemetryEventType.API_REQUEST_STARTED,
                message=f"AI API request started",
                data=client_info,
                ai_provider=client_info.get('provider'),
                model_name=client_info.get('model')
            )
            
            timer_id = self.engine.start_timer("api_request")
            
            try:
                result = await request_func(*args, **kwargs)
                
                duration = self.engine.stop_timer(timer_id, tags={
                    "status": "success",
                    "provider": client_info.get('provider', 'unknown')
                })
                
                # Extract cost information from result if available
                cost = 0.0
                tokens = {"input": 0, "output": 0}
                
                if isinstance(result, dict):
                    cost = result.get('cost', 0.0)
                    tokens = result.get('tokens', tokens)
                
                self.engine.log_event(
                    event_type=TelemetryEventType.API_REQUEST_COMPLETED,
                    message="AI API request completed",
                    data={
                        **client_info,
                        "duration_seconds": duration,
                        "cost_usd": cost,
                        "tokens": tokens
                    },
                    duration_ms=duration * 1000,
                    ai_provider=client_info.get('provider'),
                    model_name=client_info.get('model'),
                    token_usage=tokens,
                    cost_usd=cost
                )
                
                # Track costs in telemetry engine
                if cost > 0 and client_info.get('provider') and client_info.get('model'):
                    self.engine.track_ai_cost(
                        provider=client_info['provider'],
                        model=client_info['model'],
                        input_tokens=tokens.get('input', 0),
                        output_tokens=tokens.get('output', 0),
                        cost_usd=cost
                    )
                
                # Record metrics
                self.engine.record_metric(
                    "api_requests_completed_total", 1, MetricType.COUNTER,
                    tags={"provider": client_info.get('provider', 'unknown')}
                )
                
                return result
                
            except Exception as e:
                duration = self.engine.stop_timer(timer_id, tags={
                    "status": "error",
                    "provider": client_info.get('provider', 'unknown')
                })
                
                self.engine.log_event(
                    event_type=TelemetryEventType.API_REQUEST_FAILED,
                    message=f"AI API request failed: {str(e)}",
                    level="ERROR",
                    data={
                        **client_info,
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                        "duration_seconds": duration
                    },
                    duration_ms=duration * 1000,
                    ai_provider=client_info.get('provider'),
                    model_name=client_info.get('model')
                )
                
                self.engine.record_metric(
                    "api_requests_failed_total", 1, MetricType.COUNTER,
                    tags={
                        "provider": client_info.get('provider', 'unknown'),
                        "error_type": type(e).__name__
                    }
                )
                
                raise
        
        return wrapper
    
    def track_batch_processing(self, batch_func: Callable) -> Callable:
        """Decorator to track batch processing performance."""
        
        @functools.wraps(batch_func)
        async def wrapper(*args, **kwargs):
            # Extract batch info
            batch_size = 0
            if len(args) > 1 and hasattr(args[1], '__len__'):
                batch_size = len(args[1])
            
            self.engine.log_event(
                event_type=TelemetryEventType.BATCH_STARTED,
                message="Batch processing started",
                data={
                    "batch_size": batch_size,
                    "function": batch_func.__name__
                }
            )
            
            timer_id = self.engine.start_timer("batch_processing")
            
            try:
                result = await batch_func(*args, **kwargs)
                
                duration = self.engine.stop_timer(timer_id, tags={
                    "status": "success",
                    "batch_size": str(batch_size)
                })
                
                self.engine.log_event(
                    event_type=TelemetryEventType.BATCH_COMPLETED,
                    message="Batch processing completed",
                    data={
                        "batch_size": batch_size,
                        "duration_seconds": duration,
                        "throughput_per_second": batch_size / duration if duration > 0 else 0
                    },
                    duration_ms=duration * 1000
                )
                
                # Record performance metrics
                self.engine.record_metric("batches_processed_total", 1, MetricType.COUNTER)
                self.engine.record_metric("batch_size_total", batch_size, MetricType.COUNTER)
                self.engine.record_metric("batch_throughput", 
                                        batch_size / duration if duration > 0 else 0, 
                                        MetricType.GAUGE,
                                        help_text="Items processed per second in last batch")
                
                return result
                
            except Exception as e:
                duration = self.engine.stop_timer(timer_id, tags={
                    "status": "error",
                    "batch_size": str(batch_size)
                })
                
                self.engine.log_event(
                    event_type=TelemetryEventType.BATCH_FAILED,
                    message=f"Batch processing failed: {str(e)}",
                    level="ERROR",
                    data={
                        "batch_size": batch_size,
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                        "duration_seconds": duration
                    },
                    duration_ms=duration * 1000
                )
                
                self.engine.record_metric("batches_failed_total", 1, MetricType.COUNTER,
                                        tags={"error_type": type(e).__name__})
                
                raise
        
        return wrapper


@asynccontextmanager
async def telemetry_session(
    session_id: Optional[str] = None,
    export_directory: Optional[str] = None,
    compliance_mode: bool = False,
    auto_flush_interval: int = 60
):
    """
    Context manager for a complete telemetry session.
    
    Usage:
        async with telemetry_session(compliance_mode=True) as telemetry:
            # Use telemetry.engine for manual telemetry
            # Use telemetry.integration for decorators
            pass
    """
    
    class TelemetrySession:
        def __init__(self, engine: TelemetryEngine):
            self.engine = engine
            self.integration = TelemetryIntegration(engine)
    
    engine = TelemetryEngine(
        session_id=session_id,
        export_directory=export_directory,
        compliance_mode=compliance_mode,
        auto_flush_interval=auto_flush_interval
    )
    
    try:
        async with engine:
            session = TelemetrySession(engine)
            
            # Log session start
            engine.log_event(
                event_type=TelemetryEventType.AUDIT_LOG,
                message="Telemetry session started",
                level="INFO",
                data={
                    "compliance_mode": compliance_mode,
                    "auto_flush_interval": auto_flush_interval
                }
            )
            
            yield session
            
    finally:
        # Log session end
        engine.log_event(
            event_type=TelemetryEventType.AUDIT_LOG,
            message="Telemetry session ended",
            level="INFO",
            data=engine.get_cost_summary()
        )


def add_telemetry_to_ai_client(client_class):
    """
    Class decorator to add telemetry to an AI client class.
    
    Usage:
        @add_telemetry_to_ai_client
        class AIVulnerabilityClient:
            # ... existing code ...
    """
    
    def decorator(cls):
        original_init = cls.__init__
        
        def __init__(self, *args, **kwargs):
            original_init(self, *args, **kwargs)
            
            # Add telemetry engine if not present
            if not hasattr(self, '_telemetry_engine'):
                self._telemetry_engine = TelemetryEngine(
                    session_id=getattr(self, 'session_id', None)
                )
                self._telemetry_integration = TelemetryIntegration(self._telemetry_engine)
        
        # Wrap bulk_analyze method
        if hasattr(cls, 'bulk_analyze'):
            original_bulk_analyze = cls.bulk_analyze
            
            async def bulk_analyze_with_telemetry(self, *args, **kwargs):
                if hasattr(self, '_telemetry_integration'):
                    decorated = self._telemetry_integration.track_scan_lifecycle(original_bulk_analyze)
                    return await decorated(self, *args, **kwargs)
                else:
                    return await original_bulk_analyze(self, *args, **kwargs)
            
            cls.bulk_analyze = bulk_analyze_with_telemetry
        
        # Wrap API request methods
        for method_name in ['_analyze_with_live_search', '_analyze_knowledge_only']:
            if hasattr(cls, method_name):
                original_method = getattr(cls, method_name)
                
                async def wrapped_method(self, *args, **kwargs):
                    if hasattr(self, '_telemetry_integration'):
                        decorated = self._telemetry_integration.track_ai_requests(original_method)
                        return await decorated(self, *args, **kwargs)
                    else:
                        return await original_method(self, *args, **kwargs)
                
                setattr(cls, method_name, wrapped_method)
        
        cls.__init__ = __init__
        return cls
    
    return decorator


# Example usage functions for demonstration
async def example_integration_usage():
    """Example showing how to use telemetry integration."""
    
    # Method 1: Using context manager
    async with telemetry_session(compliance_mode=True) as telemetry:
        # Manual telemetry logging
        telemetry.engine.log_event(
            event_type=TelemetryEventType.SCAN_STARTED,
            message="Starting manual scan"
        )
        
        # Track AI costs
        telemetry.engine.track_ai_cost("openai", "gpt-4o", 100, 50, 0.02)
        
        # Use decorators on functions
        @telemetry.integration.track_scan_lifecycle
        async def scan_packages(packages):
            # Simulate scan work
            await asyncio.sleep(0.1)
            return {"vulnerable": len(packages) // 2}
        
        result = await scan_packages([{"name": "pkg1"}, {"name": "pkg2"}])
        
    # Method 2: Standalone telemetry engine
    engine = TelemetryEngine(compliance_mode=True)
    integration = TelemetryIntegration(engine)
    
    async with engine:
        @integration.track_batch_processing
        async def process_batch(items):
            # Simulate batch processing
            for item in items:
                await asyncio.sleep(0.01)
            return len(items)
        
        result = await process_batch(list(range(10)))


if __name__ == "__main__":
    import asyncio
    asyncio.run(example_integration_usage())