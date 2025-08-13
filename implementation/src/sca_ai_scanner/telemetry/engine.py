"""
Production-grade Telemetry Engine for AI-powered SCA scanner.
Provides comprehensive monitoring, cost tracking, compliance logging, and performance metrics.

Key Features:
- AI API cost tracking per provider with token usage analytics
- Performance monitoring (scan duration, package counts, batch efficiency)
- Event logging with structured data for enterprise compliance  
- Memory-efficient buffering and async export capabilities
- Multiple export formats (JSON, Prometheus, CSV)
- Production observability and alerting support
"""

import asyncio
import csv
import json
import logging
import os
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, AsyncIterator, Callable
from dataclasses import dataclass, asdict, field
import threading
from concurrent.futures import ThreadPoolExecutor

import aiofiles

logger = logging.getLogger(__name__)


class TelemetryEventType(str, Enum):
    """Telemetry event types for structured logging."""
    # Scan lifecycle events
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed" 
    SCAN_FAILED = "scan_failed"
    
    # Batch processing events
    BATCH_STARTED = "batch_started"
    BATCH_COMPLETED = "batch_completed"
    BATCH_FAILED = "batch_failed"
    
    # AI API events
    API_REQUEST_STARTED = "api_request_started"
    API_REQUEST_COMPLETED = "api_request_completed"
    API_REQUEST_FAILED = "api_request_failed"
    API_COST_UPDATED = "api_cost_updated"
    
    # Performance events
    PERFORMANCE_METRIC = "performance_metric"
    MEMORY_USAGE = "memory_usage"
    
    # Compliance events
    AUDIT_LOG = "audit_log"
    SECURITY_EVENT = "security_event"
    
    # Error events
    ERROR_OCCURRED = "error_occurred"
    WARNING_ISSUED = "warning_issued"


class MetricType(str, Enum):
    """Metric types for performance monitoring."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


class ExportFormat(str, Enum):
    """Supported export formats."""
    JSON = "json"
    PROMETHEUS = "prometheus"
    CSV = "csv"
    JSONL = "jsonl"  # JSON Lines for streaming


@dataclass
class TelemetryEvent:
    """Structured telemetry event with comprehensive metadata."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: TelemetryEventType = TelemetryEventType.AUDIT_LOG
    session_id: str = ""
    component: str = ""
    message: str = ""
    level: str = "INFO"  # DEBUG, INFO, WARN, ERROR, CRITICAL
    
    # Core data
    data: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    
    # Performance tracking
    duration_ms: Optional[float] = None
    memory_usage_mb: Optional[float] = None
    
    # AI-specific metadata
    ai_provider: Optional[str] = None
    model_name: Optional[str] = None
    token_usage: Dict[str, int] = field(default_factory=dict)
    cost_usd: Optional[float] = None
    
    # Compliance metadata
    user_id: Optional[str] = None
    organization_id: Optional[str] = None
    compliance_tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = asdict(self)
        # Convert datetime to ISO string for JSON serialization
        result['timestamp'] = self.timestamp.isoformat()
        return result


@dataclass
class PerformanceMetric:
    """Performance metric with metadata."""
    name: str
    value: Union[int, float]
    metric_type: MetricType
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tags: Dict[str, str] = field(default_factory=dict)
    help_text: str = ""


@dataclass
class CostTracker:
    """AI API cost tracking with provider breakdown."""
    provider: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    request_count: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class TelemetryBuffer:
    """Memory-efficient circular buffer for telemetry data."""
    
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.events = deque(maxlen=max_size)
        self.metrics = deque(maxlen=max_size)
        self._lock = threading.RLock()
    
    def add_event(self, event: TelemetryEvent) -> None:
        """Add event to buffer with thread safety."""
        with self._lock:
            self.events.append(event)
    
    def add_metric(self, metric: PerformanceMetric) -> None:
        """Add metric to buffer with thread safety."""
        with self._lock:
            self.metrics.append(metric)
    
    def get_events(self, count: Optional[int] = None) -> List[TelemetryEvent]:
        """Get events from buffer."""
        with self._lock:
            if count is None:
                return list(self.events)
            return list(self.events)[-count:]
    
    def get_metrics(self, count: Optional[int] = None) -> List[PerformanceMetric]:
        """Get metrics from buffer."""
        with self._lock:
            if count is None:
                return list(self.metrics)
            return list(self.metrics)[-count:]
    
    def clear(self) -> None:
        """Clear all buffered data."""
        with self._lock:
            self.events.clear()
            self.metrics.clear()
    
    def size(self) -> Dict[str, int]:
        """Get current buffer sizes."""
        with self._lock:
            return {
                "events": len(self.events),
                "metrics": len(self.metrics)
            }


class TelemetryEngine:
    """
    Production-grade telemetry engine with comprehensive monitoring capabilities.
    
    Features:
    - Async operation with buffering for high performance
    - AI API cost tracking per provider with detailed analytics
    - Performance metrics collection and monitoring
    - Enterprise compliance logging with structured data
    - Multiple export formats with memory-efficient streaming
    - Production observability and alerting integration
    """
    
    def __init__(
        self,
        session_id: Optional[str] = None,
        buffer_size: int = 10000,
        auto_flush_interval: int = 60,
        export_directory: Optional[str] = None,
        enable_async_export: bool = True,
        compliance_mode: bool = False
    ):
        """
        Initialize telemetry engine with production configuration.
        
        Args:
            session_id: Unique session identifier (auto-generated if None)
            buffer_size: Maximum events/metrics in memory buffer
            auto_flush_interval: Automatic flush interval in seconds
            export_directory: Directory for telemetry exports (default: ./telemetry)
            enable_async_export: Enable asynchronous export processing
            compliance_mode: Enable enhanced compliance logging
        """
        self.session_id = session_id or str(uuid.uuid4())
        self.compliance_mode = compliance_mode
        self.enable_async_export = enable_async_export
        
        # Initialize buffer and storage
        self.buffer = TelemetryBuffer(buffer_size)
        self.export_directory = Path(export_directory or "./telemetry")
        self.export_directory.mkdir(parents=True, exist_ok=True)
        
        # Cost tracking
        self.cost_trackers: Dict[str, CostTracker] = {}
        self.total_cost = 0.0
        
        # Performance tracking
        self.performance_counters = defaultdict(float)
        self.performance_gauges = defaultdict(float)
        self.timing_contexts: Dict[str, float] = {}
        
        # Export management
        self.auto_flush_interval = auto_flush_interval
        self._flush_task: Optional[asyncio.Task] = None
        self._running = False
        self._executor = ThreadPoolExecutor(max_workers=2)
        
        # Event hooks for real-time monitoring
        self.event_hooks: List[Callable[[TelemetryEvent], None]] = []
        self.metric_hooks: List[Callable[[PerformanceMetric], None]] = []
        
        logger.info(f"TelemetryEngine initialized: session={self.session_id}, compliance_mode={compliance_mode}")
        
        # Log initialization event
        self.log_event(
            event_type=TelemetryEventType.AUDIT_LOG,
            message="Telemetry engine initialized",
            data={
                "buffer_size": buffer_size,
                "export_directory": str(self.export_directory),
                "compliance_mode": compliance_mode
            }
        )
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()
    
    async def start(self) -> None:
        """Start telemetry engine with async processing."""
        if self._running:
            logger.warning("Telemetry engine already running")
            return
            
        self._running = True
        
        # Start auto-flush task if enabled
        if self.enable_async_export and self.auto_flush_interval > 0:
            self._flush_task = asyncio.create_task(self._auto_flush_loop())
        
        self.log_event(
            event_type=TelemetryEventType.AUDIT_LOG,
            message="Telemetry engine started",
            level="INFO"
        )
        
        logger.info("Telemetry engine started successfully")
    
    async def stop(self) -> None:
        """Stop telemetry engine and flush all data."""
        if not self._running:
            return
            
        self._running = False
        
        # Cancel auto-flush task
        if self._flush_task and not self._flush_task.done():
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        
        # Final flush of all data
        await self.flush_all()
        
        # Shutdown executor
        self._executor.shutdown(wait=True)
        
        self.log_event(
            event_type=TelemetryEventType.AUDIT_LOG,
            message="Telemetry engine stopped",
            level="INFO"
        )
        
        logger.info("Telemetry engine stopped successfully")
    
    async def _auto_flush_loop(self) -> None:
        """Background task for automatic data flushing."""
        while self._running:
            try:
                await asyncio.sleep(self.auto_flush_interval)
                if self._running:
                    await self.flush_all()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in auto-flush loop: {e}")
    
    def log_event(
        self,
        event_type: TelemetryEventType,
        message: str,
        level: str = "INFO",
        data: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        component: str = "scanner",
        **kwargs
    ) -> TelemetryEvent:
        """
        Log structured telemetry event with comprehensive metadata.
        
        Args:
            event_type: Type of event being logged
            message: Human-readable message
            level: Log level (DEBUG, INFO, WARN, ERROR, CRITICAL)
            data: Event-specific data
            context: Additional context information
            component: Component generating the event
            **kwargs: Additional event properties
        
        Returns:
            Created TelemetryEvent
        """
        event = TelemetryEvent(
            event_type=event_type,
            message=message,
            level=level,
            session_id=self.session_id,
            component=component,
            data=data or {},
            context=context or {},
            **kwargs
        )
        
        # Add compliance metadata if in compliance mode
        if self.compliance_mode:
            event.compliance_tags = ["audit", "security", "production"]
            event.organization_id = os.getenv("ORGANIZATION_ID")
            event.user_id = os.getenv("USER_ID")
        
        # Buffer the event
        self.buffer.add_event(event)
        
        # Trigger event hooks for real-time processing
        for hook in self.event_hooks:
            try:
                hook(event)
            except Exception as e:
                logger.error(f"Event hook error: {e}")
        
        # Log to standard logger
        getattr(logger, level.lower(), logger.info)(f"[{event_type}] {message}")
        
        return event
    
    def record_metric(
        self,
        name: str,
        value: Union[int, float],
        metric_type: MetricType = MetricType.GAUGE,
        tags: Optional[Dict[str, str]] = None,
        help_text: str = ""
    ) -> PerformanceMetric:
        """
        Record performance metric with metadata.
        
        Args:
            name: Metric name
            value: Metric value
            metric_type: Type of metric (counter, gauge, histogram, timer)
            tags: Key-value tags for filtering
            help_text: Human-readable description
            
        Returns:
            Created PerformanceMetric
        """
        metric = PerformanceMetric(
            name=name,
            value=value,
            metric_type=metric_type,
            tags=tags or {},
            help_text=help_text
        )
        
        # Update internal counters/gauges
        if metric_type == MetricType.COUNTER:
            self.performance_counters[name] += value
        elif metric_type == MetricType.GAUGE:
            self.performance_gauges[name] = value
        
        # Buffer the metric
        self.buffer.add_metric(metric)
        
        # Trigger metric hooks
        for hook in self.metric_hooks:
            try:
                hook(metric)
            except Exception as e:
                logger.error(f"Metric hook error: {e}")
        
        return metric
    
    def start_timer(self, name: str) -> str:
        """Start a named timer for performance measurement."""
        timer_id = f"{name}_{uuid.uuid4().hex[:8]}"
        self.timing_contexts[timer_id] = time.time()
        return timer_id
    
    def stop_timer(self, timer_id: str, tags: Optional[Dict[str, str]] = None) -> float:
        """Stop a named timer and record the duration."""
        if timer_id not in self.timing_contexts:
            logger.warning(f"Timer {timer_id} not found")
            return 0.0
        
        start_time = self.timing_contexts.pop(timer_id)
        duration = time.time() - start_time
        
        # Extract name from timer_id
        name = timer_id.rsplit('_', 1)[0]
        
        self.record_metric(
            name=f"{name}_duration_seconds",
            value=duration,
            metric_type=MetricType.TIMER,
            tags=tags,
            help_text=f"Duration of {name} operation in seconds"
        )
        
        return duration
    
    def track_ai_cost(
        self,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float
    ) -> None:
        """
        Track AI API costs with provider-specific breakdown.
        
        Args:
            provider: AI provider (openai, anthropic, google, xai)
            model: Model name
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            cost_usd: Cost in USD
        """
        tracker_key = f"{provider}:{model}"
        
        if tracker_key not in self.cost_trackers:
            self.cost_trackers[tracker_key] = CostTracker(
                provider=provider,
                model=model
            )
        
        tracker = self.cost_trackers[tracker_key]
        tracker.input_tokens += input_tokens
        tracker.output_tokens += output_tokens
        tracker.cost_usd += cost_usd
        tracker.request_count += 1
        tracker.timestamp = datetime.now(timezone.utc)
        
        self.total_cost += cost_usd
        
        # Log cost event
        self.log_event(
            event_type=TelemetryEventType.API_COST_UPDATED,
            message=f"AI cost updated for {provider}:{model}",
            data={
                "provider": provider,
                "model": model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost_usd": cost_usd,
                "total_cost_usd": self.total_cost
            },
            ai_provider=provider,
            model_name=model,
            token_usage={"input": input_tokens, "output": output_tokens},
            cost_usd=cost_usd
        )
        
        # Record metrics
        self.record_metric("ai_requests_total", 1, MetricType.COUNTER, 
                          {"provider": provider, "model": model})
        self.record_metric("ai_tokens_input_total", input_tokens, MetricType.COUNTER,
                          {"provider": provider, "model": model})
        self.record_metric("ai_tokens_output_total", output_tokens, MetricType.COUNTER,
                          {"provider": provider, "model": model})
        self.record_metric("ai_cost_usd_total", cost_usd, MetricType.COUNTER,
                          {"provider": provider, "model": model})
        self.record_metric("ai_cost_current_session", self.total_cost, MetricType.GAUGE)
    
    def get_cost_summary(self) -> Dict[str, Any]:
        """Get comprehensive cost summary with analytics."""
        summary = {
            "total_cost_usd": self.total_cost,
            "session_id": self.session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "providers": {},
            "models": {},
            "analytics": {
                "total_requests": sum(t.request_count for t in self.cost_trackers.values()),
                "total_input_tokens": sum(t.input_tokens for t in self.cost_trackers.values()),
                "total_output_tokens": sum(t.output_tokens for t in self.cost_trackers.values())
            }
        }
        
        # Provider breakdown
        provider_costs = defaultdict(float)
        provider_tokens = defaultdict(lambda: {"input": 0, "output": 0})
        
        for tracker in self.cost_trackers.values():
            provider_costs[tracker.provider] += tracker.cost_usd
            provider_tokens[tracker.provider]["input"] += tracker.input_tokens
            provider_tokens[tracker.provider]["output"] += tracker.output_tokens
        
        for provider, cost in provider_costs.items():
            summary["providers"][provider] = {
                "cost_usd": cost,
                "input_tokens": provider_tokens[provider]["input"],
                "output_tokens": provider_tokens[provider]["output"],
                "percentage": (cost / self.total_cost * 100) if self.total_cost > 0 else 0
            }
        
        # Model breakdown
        for key, tracker in self.cost_trackers.items():
            summary["models"][key] = {
                "provider": tracker.provider,
                "model": tracker.model,
                "cost_usd": tracker.cost_usd,
                "input_tokens": tracker.input_tokens,
                "output_tokens": tracker.output_tokens,
                "request_count": tracker.request_count,
                "avg_cost_per_request": tracker.cost_usd / tracker.request_count if tracker.request_count > 0 else 0
            }
        
        return summary
    
    def add_event_hook(self, hook: Callable[[TelemetryEvent], None]) -> None:
        """Add event hook for real-time processing."""
        self.event_hooks.append(hook)
    
    def add_metric_hook(self, hook: Callable[[PerformanceMetric], None]) -> None:
        """Add metric hook for real-time processing."""
        self.metric_hooks.append(hook)
    
    async def export_events(self, format: ExportFormat, filename: Optional[str] = None) -> Path:
        """Export events in specified format."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            format_ext = format.value if hasattr(format, 'value') else str(format)
            filename = f"telemetry_events_{timestamp}.{format_ext}"
        
        output_path = self.export_directory / filename
        events = self.buffer.get_events()
        
        if format == ExportFormat.JSON:
            await self._export_json(output_path, [event.to_dict() for event in events])
        elif format == ExportFormat.CSV:
            await self._export_events_csv(output_path, events)
        elif format == ExportFormat.JSONL:
            await self._export_jsonl(output_path, [event.to_dict() for event in events])
        else:
            raise ValueError(f"Unsupported export format: {format}")
        
        logger.info(f"Exported {len(events)} events to {output_path}")
        return output_path
    
    async def export_metrics(self, format: ExportFormat, filename: Optional[str] = None) -> Path:
        """Export metrics in specified format."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            format_ext = format.value if hasattr(format, 'value') else str(format)
            filename = f"telemetry_metrics_{timestamp}.{format_ext}"
        
        output_path = self.export_directory / filename
        metrics = self.buffer.get_metrics()
        
        if format == ExportFormat.JSON:
            await self._export_json(output_path, [asdict(metric) for metric in metrics])
        elif format == ExportFormat.PROMETHEUS:
            await self._export_prometheus(output_path, metrics)
        elif format == ExportFormat.CSV:
            await self._export_metrics_csv(output_path, metrics)
        else:
            raise ValueError(f"Unsupported export format: {format}")
        
        logger.info(f"Exported {len(metrics)} metrics to {output_path}")
        return output_path
    
    async def export_cost_summary(self, format: ExportFormat = ExportFormat.JSON) -> Path:
        """Export comprehensive cost summary."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        format_ext = format.value if hasattr(format, 'value') else str(format)
        filename = f"cost_summary_{timestamp}.{format_ext}"
        output_path = self.export_directory / filename
        
        cost_summary = self.get_cost_summary()
        
        if format == ExportFormat.JSON:
            await self._export_json(output_path, cost_summary)
        elif format == ExportFormat.CSV:
            await self._export_cost_csv(output_path, cost_summary)
        else:
            raise ValueError(f"Unsupported format for cost summary: {format}")
        
        logger.info(f"Exported cost summary to {output_path}")
        return output_path
    
    async def flush_all(self) -> Dict[str, List[Path]]:
        """Flush all telemetry data to exports."""
        exported_files = {
            "events": [],
            "metrics": [],
            "cost_summary": []
        }
        
        try:
            # Export events
            if self.buffer.get_events():
                events_path = await self.export_events(ExportFormat.JSON)
                exported_files["events"].append(events_path)
            
            # Export metrics  
            if self.buffer.get_metrics():
                metrics_path = await self.export_metrics(ExportFormat.JSON)
                exported_files["metrics"].append(metrics_path)
                
                # Also export as Prometheus format for monitoring systems
                prom_path = await self.export_metrics(ExportFormat.PROMETHEUS)
                exported_files["metrics"].append(prom_path)
            
            # Export cost summary
            if self.cost_trackers:
                cost_path = await self.export_cost_summary()
                exported_files["cost_summary"].append(cost_path)
            
            # Clear buffer after successful export
            self.buffer.clear()
            
        except Exception as e:
            logger.error(f"Error during flush_all: {e}")
            raise
        
        return exported_files
    
    async def _export_json(self, path: Path, data: Any) -> None:
        """Export data as JSON with async I/O."""
        async with aiofiles.open(path, 'w') as f:
            await f.write(json.dumps(data, indent=2, default=str))
    
    async def _export_jsonl(self, path: Path, data: List[Dict[str, Any]]) -> None:
        """Export data as JSON Lines with async I/O."""
        async with aiofiles.open(path, 'w') as f:
            for item in data:
                await f.write(json.dumps(item, default=str) + '\n')
    
    async def _export_events_csv(self, path: Path, events: List[TelemetryEvent]) -> None:
        """Export events as CSV."""
        if not events:
            return
        
        # Run CSV export in executor to avoid blocking
        await asyncio.get_event_loop().run_in_executor(
            self._executor, self._export_events_csv_sync, path, events
        )
    
    def _export_events_csv_sync(self, path: Path, events: List[TelemetryEvent]) -> None:
        """Synchronous CSV export for events."""
        with open(path, 'w', newline='') as csvfile:
            fieldnames = [
                'event_id', 'timestamp', 'event_type', 'session_id', 
                'component', 'message', 'level', 'duration_ms',
                'ai_provider', 'model_name', 'cost_usd'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for event in events:
                row = {
                    'event_id': event.event_id,
                    'timestamp': event.timestamp.isoformat(),
                    'event_type': event.event_type,
                    'session_id': event.session_id,
                    'component': event.component,
                    'message': event.message,
                    'level': event.level,
                    'duration_ms': event.duration_ms,
                    'ai_provider': event.ai_provider,
                    'model_name': event.model_name,
                    'cost_usd': event.cost_usd
                }
                writer.writerow(row)
    
    async def _export_metrics_csv(self, path: Path, metrics: List[PerformanceMetric]) -> None:
        """Export metrics as CSV."""
        if not metrics:
            return
            
        await asyncio.get_event_loop().run_in_executor(
            self._executor, self._export_metrics_csv_sync, path, metrics
        )
    
    def _export_metrics_csv_sync(self, path: Path, metrics: List[PerformanceMetric]) -> None:
        """Synchronous CSV export for metrics."""
        with open(path, 'w', newline='') as csvfile:
            fieldnames = ['name', 'value', 'metric_type', 'timestamp', 'tags', 'help_text']
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for metric in metrics:
                row = {
                    'name': metric.name,
                    'value': metric.value,
                    'metric_type': metric.metric_type,
                    'timestamp': metric.timestamp.isoformat(),
                    'tags': json.dumps(metric.tags),
                    'help_text': metric.help_text
                }
                writer.writerow(row)
    
    async def _export_prometheus(self, path: Path, metrics: List[PerformanceMetric]) -> None:
        """Export metrics in Prometheus format."""
        await asyncio.get_event_loop().run_in_executor(
            self._executor, self._export_prometheus_sync, path, metrics
        )
    
    def _export_prometheus_sync(self, path: Path, metrics: List[PerformanceMetric]) -> None:
        """Synchronous Prometheus format export."""
        with open(path, 'w') as f:
            # Group metrics by name
            metric_groups = defaultdict(list)
            for metric in metrics:
                metric_groups[metric.name].append(metric)
            
            for metric_name, metric_list in metric_groups.items():
                if metric_list[0].help_text:
                    f.write(f"# HELP {metric_name} {metric_list[0].help_text}\n")
                
                metric_type = "gauge"  # Default
                if metric_list[0].metric_type == MetricType.COUNTER:
                    metric_type = "counter"
                
                f.write(f"# TYPE {metric_name} {metric_type}\n")
                
                for metric in metric_list:
                    if metric.tags:
                        tags_str = ",".join([f'{k}="{v}"' for k, v in metric.tags.items()])
                        f.write(f"{metric_name}{{{tags_str}}} {metric.value}\n")
                    else:
                        f.write(f"{metric_name} {metric.value}\n")
                
                f.write("\n")
    
    async def _export_cost_csv(self, path: Path, cost_summary: Dict[str, Any]) -> None:
        """Export cost summary as CSV."""
        await asyncio.get_event_loop().run_in_executor(
            self._executor, self._export_cost_csv_sync, path, cost_summary
        )
    
    def _export_cost_csv_sync(self, path: Path, cost_summary: Dict[str, Any]) -> None:
        """Synchronous CSV export for cost summary."""
        with open(path, 'w', newline='') as csvfile:
            fieldnames = [
                'provider_model', 'provider', 'model', 'cost_usd', 
                'input_tokens', 'output_tokens', 'request_count', 'avg_cost_per_request'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for model_key, model_data in cost_summary.get("models", {}).items():
                row = {
                    'provider_model': model_key,
                    'provider': model_data['provider'],
                    'model': model_data['model'],
                    'cost_usd': model_data['cost_usd'],
                    'input_tokens': model_data['input_tokens'],
                    'output_tokens': model_data['output_tokens'],
                    'request_count': model_data['request_count'],
                    'avg_cost_per_request': model_data['avg_cost_per_request']
                }
                writer.writerow(row)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive telemetry statistics."""
        buffer_size = self.buffer.size()
        
        return {
            "session_id": self.session_id,
            "running": self._running,
            "compliance_mode": self.compliance_mode,
            "buffer": {
                "events_count": buffer_size["events"],
                "metrics_count": buffer_size["metrics"],
                "max_size": self.buffer.max_size
            },
            "costs": {
                "total_usd": self.total_cost,
                "providers_tracked": len(set(t.provider for t in self.cost_trackers.values())),
                "models_tracked": len(self.cost_trackers)
            },
            "performance": {
                "counters": dict(self.performance_counters),
                "gauges": dict(self.performance_gauges),
                "active_timers": len(self.timing_contexts)
            },
            "hooks": {
                "event_hooks": len(self.event_hooks),
                "metric_hooks": len(self.metric_hooks)
            }
        }