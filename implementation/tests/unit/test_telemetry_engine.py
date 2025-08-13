"""
Comprehensive unit tests for the Telemetry Engine.
Tests cover all functionality including cost tracking, performance monitoring, 
compliance logging, export formats, and production scenarios.

Test Categories:
- Basic functionality and initialization
- Event logging and structured data
- Performance metrics and monitoring  
- AI API cost tracking per provider
- Export formats (JSON, Prometheus, CSV)
- Async operations and buffering
- Compliance and audit logging
- Error handling and edge cases
- Production scenarios and stress tests
"""

import asyncio
import json
import os
import pytest
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch, call
import csv

from sca_ai_scanner.telemetry.engine import (
    TelemetryEngine, TelemetryEvent, TelemetryEventType, 
    PerformanceMetric, MetricType, ExportFormat,
    TelemetryBuffer, CostTracker
)


class TestTelemetryEngineInitialization:
    """Test telemetry engine initialization and configuration."""
    
    def test_init_default_configuration(self):
        """Test initialization with default configuration."""
        engine = TelemetryEngine()
        
        assert engine.session_id is not None
        assert len(engine.session_id) > 0
        assert engine.compliance_mode is False
        assert engine.enable_async_export is True
        assert engine.buffer.max_size == 10000
        assert engine.total_cost == 0.0
        assert len(engine.cost_trackers) == 0
        assert engine.export_directory.exists()
    
    def test_init_custom_configuration(self):
        """Test initialization with custom configuration."""
        session_id = "test-session-123"
        buffer_size = 5000
        auto_flush = 30
        
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = TelemetryEngine(
                session_id=session_id,
                buffer_size=buffer_size,
                auto_flush_interval=auto_flush,
                export_directory=tmpdir,
                compliance_mode=True
            )
            
            assert engine.session_id == session_id
            assert engine.buffer.max_size == buffer_size
            assert engine.auto_flush_interval == auto_flush
            assert engine.compliance_mode is True
            assert str(engine.export_directory) == tmpdir
    
    def test_init_creates_export_directory(self):
        """Test that export directory is created during initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            export_path = Path(tmpdir) / "telemetry_test"
            engine = TelemetryEngine(export_directory=str(export_path))
            
            assert export_path.exists()
            assert export_path.is_dir()
    
    def test_init_logs_initialization_event(self):
        """Test that initialization event is logged."""
        engine = TelemetryEngine()
        events = engine.buffer.get_events()
        
        assert len(events) > 0
        init_event = events[0]
        assert init_event.event_type == TelemetryEventType.AUDIT_LOG
        assert "initialized" in init_event.message.lower()
        assert init_event.session_id == engine.session_id


class TestEventLogging:
    """Test telemetry event logging functionality."""
    
    def test_log_basic_event(self):
        """Test logging a basic event."""
        engine = TelemetryEngine()
        
        event = engine.log_event(
            event_type=TelemetryEventType.SCAN_STARTED,
            message="Test scan started",
            level="INFO"
        )
        
        assert event.event_type == TelemetryEventType.SCAN_STARTED
        assert event.message == "Test scan started"
        assert event.level == "INFO"
        assert event.session_id == engine.session_id
        assert event.component == "scanner"
        assert event.timestamp is not None
        
        # Check event is buffered
        events = engine.buffer.get_events()
        assert len(events) >= 1  # At least our event (plus init event)
        assert any(e.message == "Test scan started" for e in events)
    
    def test_log_event_with_data_and_context(self):
        """Test logging event with additional data and context."""
        engine = TelemetryEngine()
        
        data = {"packages_count": 42, "file_types": ["requirements.txt", "pyproject.toml"]}
        context = {"user_agent": "SCA-Scanner/1.0", "environment": "production"}
        
        event = engine.log_event(
            event_type=TelemetryEventType.BATCH_STARTED,
            message="Processing batch",
            data=data,
            context=context,
            duration_ms=1500.5
        )
        
        assert event.data == data
        assert event.context == context
        assert event.duration_ms == 1500.5
    
    def test_log_event_with_ai_metadata(self):
        """Test logging event with AI-specific metadata."""
        engine = TelemetryEngine()
        
        event = engine.log_event(
            event_type=TelemetryEventType.API_REQUEST_STARTED,
            message="AI request started",
            ai_provider="openai",
            model_name="gpt-4o-mini",
            token_usage={"input": 100, "output": 50},
            cost_usd=0.02
        )
        
        assert event.ai_provider == "openai"
        assert event.model_name == "gpt-4o-mini"
        assert event.token_usage == {"input": 100, "output": 50}
        assert event.cost_usd == 0.02
    
    def test_log_event_compliance_mode(self):
        """Test logging event in compliance mode."""
        with patch.dict(os.environ, {"ORGANIZATION_ID": "org-123", "USER_ID": "user-456"}):
            engine = TelemetryEngine(compliance_mode=True)
            
            event = engine.log_event(
                event_type=TelemetryEventType.SECURITY_EVENT,
                message="Security event logged"
            )
            
            assert "audit" in event.compliance_tags
            assert "security" in event.compliance_tags
            assert event.organization_id == "org-123"
            assert event.user_id == "user-456"
    
    def test_event_hooks_triggered(self):
        """Test that event hooks are triggered when logging events."""
        engine = TelemetryEngine()
        hook_calls = []
        
        def test_hook(event):
            hook_calls.append(event)
        
        engine.add_event_hook(test_hook)
        
        event = engine.log_event(
            event_type=TelemetryEventType.SCAN_COMPLETED,
            message="Test event for hooks"
        )
        
        assert len(hook_calls) >= 1  # At least our event (init event may trigger too)
        assert any(e.message == "Test event for hooks" for e in hook_calls)
    
    def test_event_hook_error_handling(self):
        """Test that event hook errors don't break event logging."""
        engine = TelemetryEngine()
        
        def failing_hook(event):
            raise Exception("Hook failure")
        
        engine.add_event_hook(failing_hook)
        
        # Should not raise exception
        event = engine.log_event(
            event_type=TelemetryEventType.WARNING_ISSUED,
            message="Test with failing hook"
        )
        
        assert event is not None
        events = engine.buffer.get_events()
        assert any(e.message == "Test with failing hook" for e in events)


class TestPerformanceMetrics:
    """Test performance metrics recording and monitoring."""
    
    def test_record_basic_metric(self):
        """Test recording a basic performance metric."""
        engine = TelemetryEngine()
        
        metric = engine.record_metric(
            name="test_counter",
            value=42,
            metric_type=MetricType.COUNTER,
            help_text="Test counter metric"
        )
        
        assert metric.name == "test_counter"
        assert metric.value == 42
        assert metric.metric_type == MetricType.COUNTER
        assert metric.help_text == "Test counter metric"
        assert metric.timestamp is not None
        
        # Check metric is buffered
        metrics = engine.buffer.get_metrics()
        assert len(metrics) >= 1
        assert any(m.name == "test_counter" for m in metrics)
    
    def test_record_metric_with_tags(self):
        """Test recording metric with tags."""
        engine = TelemetryEngine()
        
        tags = {"provider": "openai", "model": "gpt-4o", "environment": "prod"}
        metric = engine.record_metric(
            name="api_requests",
            value=10,
            tags=tags
        )
        
        assert metric.tags == tags
    
    def test_counter_metric_accumulation(self):
        """Test that counter metrics accumulate properly."""
        engine = TelemetryEngine()
        
        engine.record_metric("requests_total", 5, MetricType.COUNTER)
        engine.record_metric("requests_total", 3, MetricType.COUNTER)
        engine.record_metric("requests_total", 2, MetricType.COUNTER)
        
        assert engine.performance_counters["requests_total"] == 10
    
    def test_gauge_metric_replacement(self):
        """Test that gauge metrics replace previous values."""
        engine = TelemetryEngine()
        
        engine.record_metric("cpu_usage", 45.5, MetricType.GAUGE)
        engine.record_metric("cpu_usage", 67.2, MetricType.GAUGE)
        
        assert engine.performance_gauges["cpu_usage"] == 67.2
    
    def test_timer_operations(self):
        """Test timer start/stop operations."""
        engine = TelemetryEngine()
        
        timer_id = engine.start_timer("test_operation")
        assert timer_id.startswith("test_operation_")
        assert timer_id in engine.timing_contexts
        
        # Simulate some work
        import time
        time.sleep(0.01)  # 10ms
        
        duration = engine.stop_timer(timer_id)
        assert duration > 0
        assert timer_id not in engine.timing_contexts
        
        # Check that timer metric was recorded
        metrics = engine.buffer.get_metrics()
        timer_metrics = [m for m in metrics if "test_operation_duration" in m.name]
        assert len(timer_metrics) > 0
        assert timer_metrics[0].metric_type == MetricType.TIMER
    
    def test_timer_with_tags(self):
        """Test timer with tags."""
        engine = TelemetryEngine()
        
        timer_id = engine.start_timer("api_call")
        duration = engine.stop_timer(timer_id, tags={"provider": "anthropic"})
        
        assert duration >= 0
        
        metrics = engine.buffer.get_metrics()
        timer_metrics = [m for m in metrics if "api_call_duration" in m.name]
        assert len(timer_metrics) > 0
        assert timer_metrics[0].tags["provider"] == "anthropic"
    
    def test_timer_not_found(self):
        """Test behavior when stopping non-existent timer."""
        engine = TelemetryEngine()
        
        duration = engine.stop_timer("nonexistent_timer")
        assert duration == 0.0
    
    def test_metric_hooks_triggered(self):
        """Test that metric hooks are triggered when recording metrics."""
        engine = TelemetryEngine()
        hook_calls = []
        
        def test_hook(metric):
            hook_calls.append(metric)
        
        engine.add_metric_hook(test_hook)
        
        metric = engine.record_metric("test_metric", 123)
        
        assert len(hook_calls) == 1
        assert hook_calls[0].name == "test_metric"
        assert hook_calls[0].value == 123
    
    def test_metric_hook_error_handling(self):
        """Test that metric hook errors don't break metric recording."""
        engine = TelemetryEngine()
        
        def failing_hook(metric):
            raise Exception("Hook failure")
        
        engine.add_metric_hook(failing_hook)
        
        # Should not raise exception
        metric = engine.record_metric("test_metric", 456)
        
        assert metric is not None
        assert metric.value == 456


class TestCostTracking:
    """Test AI API cost tracking functionality."""
    
    def test_track_basic_cost(self):
        """Test basic cost tracking."""
        engine = TelemetryEngine()
        
        engine.track_ai_cost(
            provider="openai",
            model="gpt-4o-mini",
            input_tokens=100,
            output_tokens=50,
            cost_usd=0.025
        )
        
        assert engine.total_cost == 0.025
        assert len(engine.cost_trackers) == 1
        
        tracker = engine.cost_trackers["openai:gpt-4o-mini"]
        assert tracker.provider == "openai"
        assert tracker.model == "gpt-4o-mini"
        assert tracker.input_tokens == 100
        assert tracker.output_tokens == 50
        assert tracker.cost_usd == 0.025
        assert tracker.request_count == 1
    
    def test_track_multiple_requests_same_model(self):
        """Test cost tracking with multiple requests to same model."""
        engine = TelemetryEngine()
        
        # First request
        engine.track_ai_cost("anthropic", "claude-3.5-sonnet", 200, 100, 0.05)
        # Second request  
        engine.track_ai_cost("anthropic", "claude-3.5-sonnet", 150, 75, 0.03)
        
        assert engine.total_cost == 0.08
        assert len(engine.cost_trackers) == 1
        
        tracker = engine.cost_trackers["anthropic:claude-3.5-sonnet"]
        assert tracker.input_tokens == 350  # 200 + 150
        assert tracker.output_tokens == 175  # 100 + 75
        assert tracker.cost_usd == 0.08     # 0.05 + 0.03
        assert tracker.request_count == 2
    
    def test_track_multiple_providers(self):
        """Test cost tracking across multiple providers."""
        engine = TelemetryEngine()
        
        engine.track_ai_cost("openai", "gpt-4o", 100, 50, 0.02)
        engine.track_ai_cost("anthropic", "claude-3.5-haiku", 150, 75, 0.01)
        engine.track_ai_cost("google", "gemini-2.0-flash", 200, 100, 0.005)
        
        assert abs(engine.total_cost - 0.035) < 0.001  # Handle floating point precision
        assert len(engine.cost_trackers) == 3
        
        assert "openai:gpt-4o" in engine.cost_trackers
        assert "anthropic:claude-3.5-haiku" in engine.cost_trackers
        assert "google:gemini-2.0-flash" in engine.cost_trackers
    
    def test_cost_tracking_logs_event(self):
        """Test that cost tracking logs telemetry events."""
        engine = TelemetryEngine()
        
        engine.track_ai_cost("xai", "grok-3", 300, 150, 0.04)
        
        events = engine.buffer.get_events()
        cost_events = [e for e in events if e.event_type == TelemetryEventType.API_COST_UPDATED]
        
        assert len(cost_events) >= 1
        cost_event = cost_events[-1]  # Get the most recent one
        assert cost_event.ai_provider == "xai"
        assert cost_event.model_name == "grok-3"
        assert cost_event.cost_usd == 0.04
        assert cost_event.token_usage == {"input": 300, "output": 150}
    
    def test_cost_tracking_records_metrics(self):
        """Test that cost tracking records performance metrics."""
        engine = TelemetryEngine()
        
        engine.track_ai_cost("openai", "o1-mini", 500, 250, 0.1)
        
        metrics = engine.buffer.get_metrics()
        
        # Check for expected metrics
        metric_names = [m.name for m in metrics]
        assert "ai_requests_total" in metric_names
        assert "ai_tokens_input_total" in metric_names
        assert "ai_tokens_output_total" in metric_names
        assert "ai_cost_usd_total" in metric_names
        assert "ai_cost_current_session" in metric_names
        
        # Check tags are properly set
        request_metrics = [m for m in metrics if m.name == "ai_requests_total"]
        assert len(request_metrics) > 0
        assert request_metrics[0].tags["provider"] == "openai"
        assert request_metrics[0].tags["model"] == "o1-mini"
    
    def test_get_cost_summary(self):
        """Test comprehensive cost summary generation."""
        engine = TelemetryEngine()
        
        engine.track_ai_cost("openai", "gpt-4o", 100, 50, 0.02)
        engine.track_ai_cost("anthropic", "claude-3.5-sonnet", 200, 100, 0.05)
        engine.track_ai_cost("openai", "gpt-4o-mini", 300, 150, 0.01)
        
        summary = engine.get_cost_summary()
        
        # Check top-level summary
        assert summary["total_cost_usd"] == 0.08
        assert summary["session_id"] == engine.session_id
        assert "timestamp" in summary
        
        # Check analytics
        analytics = summary["analytics"]
        assert analytics["total_requests"] == 3
        assert analytics["total_input_tokens"] == 600
        assert analytics["total_output_tokens"] == 300
        
        # Check provider breakdown
        providers = summary["providers"]
        assert "openai" in providers
        assert "anthropic" in providers
        
        openai_data = providers["openai"]
        assert openai_data["cost_usd"] == 0.03  # 0.02 + 0.01
        assert openai_data["input_tokens"] == 400  # 100 + 300
        assert openai_data["percentage"] == 37.5  # 0.03/0.08 * 100
        
        # Check model breakdown
        models = summary["models"]
        assert "openai:gpt-4o" in models
        assert "anthropic:claude-3.5-sonnet" in models
        
        gpt4o_data = models["openai:gpt-4o"]
        assert gpt4o_data["request_count"] == 1
        assert gpt4o_data["avg_cost_per_request"] == 0.02
    
    def test_cost_summary_empty_trackers(self):
        """Test cost summary with no cost trackers."""
        engine = TelemetryEngine()
        
        summary = engine.get_cost_summary()
        
        assert summary["total_cost_usd"] == 0.0
        assert len(summary["providers"]) == 0
        assert len(summary["models"]) == 0
        assert summary["analytics"]["total_requests"] == 0


class TestTelemetryBuffer:
    """Test telemetry buffer functionality."""
    
    def test_buffer_initialization(self):
        """Test buffer initialization."""
        buffer = TelemetryBuffer(max_size=100)
        
        assert buffer.max_size == 100
        assert len(buffer.events) == 0
        assert len(buffer.metrics) == 0
    
    def test_add_events(self):
        """Test adding events to buffer."""
        buffer = TelemetryBuffer()
        
        event1 = TelemetryEvent(message="Event 1")
        event2 = TelemetryEvent(message="Event 2")
        
        buffer.add_event(event1)
        buffer.add_event(event2)
        
        events = buffer.get_events()
        assert len(events) == 2
        assert events[0].message == "Event 1"
        assert events[1].message == "Event 2"
    
    def test_add_metrics(self):
        """Test adding metrics to buffer."""
        buffer = TelemetryBuffer()
        
        metric1 = PerformanceMetric("metric1", 10, MetricType.COUNTER)
        metric2 = PerformanceMetric("metric2", 20, MetricType.GAUGE)
        
        buffer.add_metric(metric1)
        buffer.add_metric(metric2)
        
        metrics = buffer.get_metrics()
        assert len(metrics) == 2
        assert metrics[0].name == "metric1"
        assert metrics[1].name == "metric2"
    
    def test_buffer_max_size_events(self):
        """Test buffer respects max size for events."""
        buffer = TelemetryBuffer(max_size=3)
        
        for i in range(5):
            event = TelemetryEvent(message=f"Event {i}")
            buffer.add_event(event)
        
        events = buffer.get_events()
        assert len(events) == 3  # Only last 3 events
        assert events[0].message == "Event 2"
        assert events[2].message == "Event 4"
    
    def test_buffer_max_size_metrics(self):
        """Test buffer respects max size for metrics."""
        buffer = TelemetryBuffer(max_size=2)
        
        for i in range(4):
            metric = PerformanceMetric(f"metric{i}", i, MetricType.GAUGE)
            buffer.add_metric(metric)
        
        metrics = buffer.get_metrics()
        assert len(metrics) == 2  # Only last 2 metrics
        assert metrics[0].name == "metric2"
        assert metrics[1].name == "metric3"
    
    def test_get_events_with_count(self):
        """Test getting limited number of events."""
        buffer = TelemetryBuffer()
        
        for i in range(5):
            buffer.add_event(TelemetryEvent(message=f"Event {i}"))
        
        recent_events = buffer.get_events(count=2)
        assert len(recent_events) == 2
        assert recent_events[0].message == "Event 3"  # Last 2
        assert recent_events[1].message == "Event 4"
    
    def test_buffer_clear(self):
        """Test clearing buffer."""
        buffer = TelemetryBuffer()
        
        buffer.add_event(TelemetryEvent(message="Test event"))
        buffer.add_metric(PerformanceMetric("test", 1, MetricType.COUNTER))
        
        assert len(buffer.get_events()) == 1
        assert len(buffer.get_metrics()) == 1
        
        buffer.clear()
        
        assert len(buffer.get_events()) == 0
        assert len(buffer.get_metrics()) == 0
    
    def test_buffer_size_reporting(self):
        """Test buffer size reporting."""
        buffer = TelemetryBuffer()
        
        buffer.add_event(TelemetryEvent(message="Test"))
        buffer.add_metric(PerformanceMetric("test", 1, MetricType.COUNTER))
        buffer.add_metric(PerformanceMetric("test2", 2, MetricType.GAUGE))
        
        size = buffer.size()
        assert size["events"] == 1
        assert size["metrics"] == 2
    
    def test_buffer_thread_safety(self):
        """Test buffer thread safety with concurrent access."""
        import threading
        
        buffer = TelemetryBuffer()
        results = []
        
        def add_events():
            for i in range(100):
                buffer.add_event(TelemetryEvent(message=f"Thread event {i}"))
        
        def add_metrics():
            for i in range(100):
                buffer.add_metric(PerformanceMetric(f"metric{i}", i, MetricType.COUNTER))
        
        # Start concurrent threads
        thread1 = threading.Thread(target=add_events)
        thread2 = threading.Thread(target=add_metrics)
        
        thread1.start()
        thread2.start()
        
        thread1.join()
        thread2.join()
        
        # Should have all events and metrics without crashes
        assert len(buffer.get_events()) == 100
        assert len(buffer.get_metrics()) == 100


class TestAsyncOperations:
    """Test async operations and lifecycle management."""
    
    @pytest.mark.asyncio
    async def test_async_context_manager(self):
        """Test async context manager functionality."""
        with tempfile.TemporaryDirectory() as tmpdir:
            async with TelemetryEngine(export_directory=tmpdir) as engine:
                assert engine._running is True
                
                engine.log_event(
                    event_type=TelemetryEventType.SCAN_STARTED,
                    message="Test scan"
                )
                
                assert len(engine.buffer.get_events()) >= 2  # Init + our event
            
            # Should be stopped after context exit
            assert engine._running is False
    
    @pytest.mark.asyncio
    async def test_start_stop_lifecycle(self):
        """Test manual start/stop lifecycle."""
        engine = TelemetryEngine()
        
        assert engine._running is False
        
        await engine.start()
        assert engine._running is True
        
        await engine.stop()
        assert engine._running is False
    
    @pytest.mark.asyncio
    async def test_double_start_warning(self):
        """Test that double start logs warning."""
        engine = TelemetryEngine()
        
        await engine.start()
        assert engine._running is True
        
        # Second start should not fail but log warning
        await engine.start()
        assert engine._running is True
        
        await engine.stop()
    
    @pytest.mark.asyncio
    async def test_stop_without_start(self):
        """Test that stop without start doesn't fail."""
        engine = TelemetryEngine()
        
        # Should not fail
        await engine.stop()
        assert engine._running is False


class TestExportFormats:
    """Test telemetry data export in various formats."""
    
    @pytest.mark.asyncio
    async def test_export_events_json(self):
        """Test exporting events in JSON format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = TelemetryEngine(export_directory=tmpdir)
            
            engine.log_event(
                event_type=TelemetryEventType.SCAN_COMPLETED,
                message="Test scan completed",
                data={"packages": 10}
            )
            
            output_path = await engine.export_events(ExportFormat.JSON, "test_events.json")
            
            assert output_path.exists()
            assert output_path.name == "test_events.json"
            
            # Verify JSON content
            with open(output_path) as f:
                data = json.load(f)
            
            assert isinstance(data, list)
            assert len(data) >= 1  # At least our event
            
            # Find our test event
            test_event = next(e for e in data if e["message"] == "Test scan completed")
            assert test_event["event_type"] == "scan_completed"
            assert test_event["data"]["packages"] == 10
    
    @pytest.mark.asyncio
    async def test_export_events_csv(self):
        """Test exporting events in CSV format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = TelemetryEngine(export_directory=tmpdir)
            
            engine.log_event(
                event_type=TelemetryEventType.API_REQUEST_COMPLETED,
                message="API request completed",
                ai_provider="openai",
                model_name="gpt-4o",
                cost_usd=0.05
            )
            
            output_path = await engine.export_events(ExportFormat.CSV, "test_events.csv")
            
            assert output_path.exists()
            
            # Verify CSV content
            with open(output_path, newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                rows = list(reader)
            
            assert len(rows) >= 1
            
            # Find our test event
            test_row = next(r for r in rows if r["message"] == "API request completed")
            assert test_row["event_type"] == "api_request_completed"
            assert test_row["ai_provider"] == "openai"
            assert test_row["cost_usd"] == "0.05"
    
    @pytest.mark.asyncio
    async def test_export_events_jsonl(self):
        """Test exporting events in JSON Lines format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = TelemetryEngine(export_directory=tmpdir)
            
            engine.log_event(TelemetryEventType.WARNING_ISSUED, "Test warning")
            
            output_path = await engine.export_events(ExportFormat.JSONL, "test_events.jsonl")
            
            assert output_path.exists()
            
            # Verify JSONL content
            with open(output_path) as f:
                lines = f.readlines()
            
            assert len(lines) >= 1
            
            # Each line should be valid JSON
            for line in lines:
                event_data = json.loads(line.strip())
                assert "event_id" in event_data
                assert "timestamp" in event_data
    
    @pytest.mark.asyncio
    async def test_export_metrics_json(self):
        """Test exporting metrics in JSON format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = TelemetryEngine(export_directory=tmpdir)
            
            engine.record_metric(
                "test_metric",
                42.5,
                MetricType.GAUGE,
                tags={"environment": "test"},
                help_text="Test metric"
            )
            
            output_path = await engine.export_metrics(ExportFormat.JSON, "test_metrics.json")
            
            assert output_path.exists()
            
            with open(output_path) as f:
                data = json.load(f)
            
            assert isinstance(data, list)
            assert len(data) >= 1
            
            test_metric = next(m for m in data if m["name"] == "test_metric")
            assert test_metric["value"] == 42.5
            assert test_metric["metric_type"] == "gauge"
            assert test_metric["tags"]["environment"] == "test"
    
    @pytest.mark.asyncio
    async def test_export_metrics_prometheus(self):
        """Test exporting metrics in Prometheus format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = TelemetryEngine(export_directory=tmpdir)
            
            engine.record_metric(
                "http_requests_total",
                150,
                MetricType.COUNTER,
                tags={"method": "GET", "status": "200"},
                help_text="Total HTTP requests"
            )
            
            output_path = await engine.export_metrics(ExportFormat.PROMETHEUS, "metrics.prom")
            
            assert output_path.exists()
            
            with open(output_path) as f:
                content = f.read()
            
            # Check Prometheus format elements
            assert "# HELP http_requests_total Total HTTP requests" in content
            assert "# TYPE http_requests_total counter" in content
            assert 'http_requests_total{method="GET",status="200"} 150' in content
    
    @pytest.mark.asyncio
    async def test_export_metrics_csv(self):
        """Test exporting metrics in CSV format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = TelemetryEngine(export_directory=tmpdir)
            
            engine.record_metric("cpu_usage", 75.5, MetricType.GAUGE)
            
            output_path = await engine.export_metrics(ExportFormat.CSV, "test_metrics.csv")
            
            assert output_path.exists()
            
            with open(output_path, newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                rows = list(reader)
            
            assert len(rows) >= 1
            test_row = next(r for r in rows if r["name"] == "cpu_usage")
            assert test_row["value"] == "75.5"
            assert test_row["metric_type"] == "gauge"
    
    @pytest.mark.asyncio
    async def test_export_cost_summary(self):
        """Test exporting cost summary."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = TelemetryEngine(export_directory=tmpdir)
            
            engine.track_ai_cost("openai", "gpt-4o", 100, 50, 0.02)
            
            output_path = await engine.export_cost_summary(ExportFormat.JSON)
            
            assert output_path.exists()
            assert "cost_summary_" in output_path.name
            assert output_path.suffix == ".json"
            
            with open(output_path) as f:
                data = json.load(f)
            
            assert data["total_cost_usd"] == 0.02
            assert "openai" in data["providers"]
            assert "openai:gpt-4o" in data["models"]
    
    @pytest.mark.asyncio
    async def test_export_cost_summary_csv(self):
        """Test exporting cost summary in CSV format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = TelemetryEngine(export_directory=tmpdir)
            
            engine.track_ai_cost("anthropic", "claude-3.5-sonnet", 200, 100, 0.05)
            
            output_path = await engine.export_cost_summary(ExportFormat.CSV)
            
            assert output_path.exists()
            assert output_path.suffix == ".csv"
            
            with open(output_path, newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                rows = list(reader)
            
            assert len(rows) == 1
            assert rows[0]["provider"] == "anthropic"
            assert rows[0]["model"] == "claude-3.5-sonnet"
            assert rows[0]["cost_usd"] == "0.05"
    
    @pytest.mark.asyncio
    async def test_flush_all(self):
        """Test comprehensive data flush."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = TelemetryEngine(export_directory=tmpdir)
            
            # Add some data
            engine.log_event(TelemetryEventType.SCAN_STARTED, "Test scan")
            engine.record_metric("test_metric", 100, MetricType.COUNTER)
            engine.track_ai_cost("openai", "gpt-4o-mini", 50, 25, 0.01)
            
            exported_files = await engine.flush_all()
            
            # Check that files were exported
            assert "events" in exported_files
            assert "metrics" in exported_files
            assert "cost_summary" in exported_files
            
            assert len(exported_files["events"]) >= 1
            assert len(exported_files["metrics"]) >= 1  # JSON + Prometheus
            assert len(exported_files["cost_summary"]) >= 1
            
            # Check buffer was cleared
            assert len(engine.buffer.get_events()) == 0
            assert len(engine.buffer.get_metrics()) == 0
    
    @pytest.mark.asyncio
    async def test_export_empty_data(self):
        """Test exporting when no data is available."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = TelemetryEngine(export_directory=tmpdir)
            
            # Clear any initialization events
            engine.buffer.clear()
            
            exported_files = await engine.flush_all()
            
            # Should handle empty data gracefully
            assert "events" in exported_files
            assert "metrics" in exported_files
            assert "cost_summary" in exported_files
            
            # Most lists should be empty
            assert len(exported_files["events"]) == 0
            assert len(exported_files["metrics"]) == 0
            assert len(exported_files["cost_summary"]) == 0
    
    @pytest.mark.asyncio
    async def test_export_unsupported_format(self):
        """Test error handling for unsupported export formats."""
        engine = TelemetryEngine()
        
        with pytest.raises((ValueError, AttributeError)):
            await engine.export_events("unsupported_format")


class TestProductionScenarios:
    """Test production scenarios and stress conditions."""
    
    @pytest.mark.asyncio
    async def test_high_volume_events(self):
        """Test handling high volume of events."""
        engine = TelemetryEngine(buffer_size=1000)
        
        # Generate many events
        for i in range(500):
            engine.log_event(
                event_type=TelemetryEventType.API_REQUEST_COMPLETED,
                message=f"Request {i}",
                data={"request_id": i}
            )
        
        events = engine.buffer.get_events()
        assert len(events) >= 500  # May include initialization event
        
        # Test that buffer respects max size
        for i in range(600):  # Exceed buffer size
            engine.log_event(
                event_type=TelemetryEventType.PERFORMANCE_METRIC,
                message=f"Metric update {i}"
            )
        
        events = engine.buffer.get_events()
        assert len(events) == 1000  # Should be limited to buffer size
    
    @pytest.mark.asyncio
    async def test_concurrent_operations(self):
        """Test concurrent telemetry operations."""
        import asyncio
        
        engine = TelemetryEngine()
        
        async def log_events():
            for i in range(50):
                engine.log_event(
                    TelemetryEventType.BATCH_COMPLETED,
                    f"Batch {i}",
                    data={"batch_id": i}
                )
                await asyncio.sleep(0.001)  # Small delay
        
        async def record_metrics():
            for i in range(50):
                engine.record_metric(f"metric_{i}", i * 10, MetricType.COUNTER)
                await asyncio.sleep(0.001)
        
        async def track_costs():
            for i in range(25):
                engine.track_ai_cost("openai", "gpt-4o", 100, 50, 0.01)
                await asyncio.sleep(0.002)
        
        # Run concurrent operations
        await asyncio.gather(log_events(), record_metrics(), track_costs())
        
        # Verify all operations completed
        events = engine.buffer.get_events()
        metrics = engine.buffer.get_metrics()
        
        assert len([e for e in events if "Batch" in e.message]) == 50
        assert len([m for m in metrics if "metric_" in m.name]) == 50
        assert abs(engine.total_cost - 0.25) < 0.001  # Handle floating point precision
    
    def test_memory_usage_tracking(self):
        """Test memory usage tracking functionality."""
        engine = TelemetryEngine()
        
        # Use simulated memory usage since psutil not available
        simulated_memory = 128.5  # MB
        
        # Add memory usage to event
        event = engine.log_event(
            event_type=TelemetryEventType.PERFORMANCE_METRIC,
            message="Memory usage snapshot",
            memory_usage_mb=simulated_memory
        )
        
        assert event.memory_usage_mb == simulated_memory
        assert event.memory_usage_mb > 0
    
    def test_error_handling_robustness(self):
        """Test error handling doesn't break telemetry."""
        engine = TelemetryEngine()
        
        # Test with invalid data
        try:
            engine.log_event(
                event_type="invalid_event_type",  # Invalid enum value
                message="This should handle gracefully"
            )
        except ValueError:
            pass  # Expected for invalid enum
        
        # Engine should still work
        valid_event = engine.log_event(
            event_type=TelemetryEventType.WARNING_ISSUED,
            message="Valid event after error"
        )
        
        assert valid_event is not None
        assert len(engine.buffer.get_events()) >= 1
    
    @pytest.mark.asyncio
    async def test_large_export_operations(self):
        """Test exporting large amounts of data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = TelemetryEngine(export_directory=tmpdir, buffer_size=2000)
            
            # Generate large dataset
            for i in range(1000):
                engine.log_event(
                    event_type=TelemetryEventType.SCAN_COMPLETED,
                    message=f"Large scan {i}",
                    data={"scan_id": i, "packages": list(range(10))}
                )
                
                if i % 10 == 0:
                    engine.record_metric(f"scan_metric_{i}", i, MetricType.COUNTER)
            
            # Export should handle large data
            exported_files = await engine.flush_all()
            
            # Verify exports completed
            assert len(exported_files["events"]) > 0
            assert len(exported_files["metrics"]) > 0
            
            # Check file sizes are reasonable
            for file_list in exported_files.values():
                for file_path in file_list:
                    assert file_path.exists()
                    assert file_path.stat().st_size > 0


class TestStatisticsAndMonitoring:
    """Test telemetry statistics and monitoring capabilities."""
    
    def test_get_statistics_basic(self):
        """Test basic statistics reporting."""
        engine = TelemetryEngine()
        
        stats = engine.get_statistics()
        
        assert stats["session_id"] == engine.session_id
        assert stats["running"] is False
        assert stats["compliance_mode"] is False
        
        assert "buffer" in stats
        assert "costs" in stats
        assert "performance" in stats
        assert "hooks" in stats
    
    def test_get_statistics_with_data(self):
        """Test statistics with actual data."""
        engine = TelemetryEngine()
        
        # Add some data
        engine.log_event(TelemetryEventType.SCAN_STARTED, "Test")
        engine.record_metric("test_counter", 10, MetricType.COUNTER)
        engine.track_ai_cost("openai", "gpt-4o", 100, 50, 0.02)
        
        stats = engine.get_statistics()
        
        # Buffer stats
        assert stats["buffer"]["events_count"] >= 1  # At least our event + init
        assert stats["buffer"]["metrics_count"] >= 1  # At least our metric + cost metrics
        
        # Cost stats
        assert stats["costs"]["total_usd"] == 0.02
        assert stats["costs"]["providers_tracked"] == 1
        assert stats["costs"]["models_tracked"] == 1
        
        # Performance stats
        assert stats["performance"]["counters"]["test_counter"] == 10
    
    def test_statistics_with_hooks(self):
        """Test statistics reporting with hooks."""
        engine = TelemetryEngine()
        
        # Add hooks
        engine.add_event_hook(lambda e: None)
        engine.add_metric_hook(lambda m: None)
        engine.add_event_hook(lambda e: None)  # Add another
        
        stats = engine.get_statistics()
        
        assert stats["hooks"]["event_hooks"] == 2
        assert stats["hooks"]["metric_hooks"] == 1
    
    def test_statistics_with_timers(self):
        """Test statistics with active timers."""
        engine = TelemetryEngine()
        
        # Start some timers
        timer1 = engine.start_timer("operation1")
        timer2 = engine.start_timer("operation2")
        
        stats = engine.get_statistics()
        assert stats["performance"]["active_timers"] == 2
        
        # Stop one timer
        engine.stop_timer(timer1)
        
        stats = engine.get_statistics()
        assert stats["performance"]["active_timers"] == 1


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling scenarios."""
    
    def test_telemetry_event_to_dict(self):
        """Test TelemetryEvent to_dict conversion."""
        event = TelemetryEvent(
            message="Test event",
            event_type=TelemetryEventType.AUDIT_LOG,
            data={"key": "value"},
            ai_provider="openai"
        )
        
        event_dict = event.to_dict()
        
        assert event_dict["message"] == "Test event"
        assert event_dict["event_type"] == TelemetryEventType.AUDIT_LOG
        assert event_dict["data"] == {"key": "value"}
        assert event_dict["ai_provider"] == "openai"
        assert isinstance(event_dict["timestamp"], str)  # Should be ISO string
    
    def test_cost_tracker_initialization(self):
        """Test CostTracker initialization."""
        tracker = CostTracker(provider="anthropic", model="claude-3.5-sonnet")
        
        assert tracker.provider == "anthropic"
        assert tracker.model == "claude-3.5-sonnet"
        assert tracker.input_tokens == 0
        assert tracker.output_tokens == 0
        assert tracker.cost_usd == 0.0
        assert tracker.request_count == 0
        assert tracker.timestamp is not None
    
    def test_performance_metric_initialization(self):
        """Test PerformanceMetric initialization."""
        metric = PerformanceMetric(
            name="test_metric",
            value=42.5,
            metric_type=MetricType.GAUGE,
            tags={"env": "test"},
            help_text="Test metric"
        )
        
        assert metric.name == "test_metric"
        assert metric.value == 42.5
        assert metric.metric_type == MetricType.GAUGE
        assert metric.tags == {"env": "test"}
        assert metric.help_text == "Test metric"
        assert metric.timestamp is not None
    
    @pytest.mark.asyncio
    async def test_export_with_io_error(self):
        """Test export handling when I/O errors occur."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create valid engine first
            engine = TelemetryEngine(export_directory=tmpdir)
            
            # Then change to invalid path to force I/O error during export
            engine.export_directory = Path("/invalid/path/that/doesnt/exist")
            
            engine.log_event(TelemetryEventType.SCAN_STARTED, "Test")
            
            # Should handle I/O errors gracefully
            with pytest.raises(Exception):  # Could be FileNotFoundError or PermissionError
                await engine.flush_all()
    
    def test_enum_values(self):
        """Test that enum values are correct."""
        # Test TelemetryEventType
        assert TelemetryEventType.SCAN_STARTED == "scan_started"
        assert TelemetryEventType.API_COST_UPDATED == "api_cost_updated"
        
        # Test MetricType
        assert MetricType.COUNTER == "counter"
        assert MetricType.GAUGE == "gauge"
        
        # Test ExportFormat
        assert ExportFormat.JSON == "json"
        assert ExportFormat.PROMETHEUS == "prometheus"
    
    @pytest.mark.asyncio
    async def test_auto_flush_disabled(self):
        """Test behavior when auto-flush is disabled."""
        engine = TelemetryEngine(auto_flush_interval=0)  # Disable auto-flush
        
        await engine.start()
        assert engine._flush_task is None  # No auto-flush task should be created
        
        await engine.stop()
    
    def test_default_values_and_factory_functions(self):
        """Test default values and factory functions work correctly."""
        event = TelemetryEvent()
        
        assert event.event_id is not None
        assert len(event.event_id) > 0
        assert event.timestamp is not None
        assert event.data == {}
        assert event.context == {}
        assert event.token_usage == {}
        assert event.compliance_tags == []
    
    @pytest.mark.asyncio
    async def test_context_manager_exception_handling(self):
        """Test that context manager properly handles exceptions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                async with TelemetryEngine(export_directory=tmpdir) as engine:
                    engine.log_event(TelemetryEventType.ERROR_OCCURRED, "Test error")
                    raise ValueError("Test exception")
            except ValueError:
                pass  # Expected
            
            # Engine should be properly stopped even after exception
            assert engine._running is False


# Performance benchmarks (marked as slow tests)
@pytest.mark.slow
class TestPerformanceBenchmarks:
    """Performance benchmark tests for telemetry engine."""
    
    def test_event_logging_performance(self):
        """Benchmark event logging performance."""
        import time
        
        engine = TelemetryEngine(buffer_size=10000)
        
        start_time = time.time()
        
        for i in range(1000):
            engine.log_event(
                event_type=TelemetryEventType.PERFORMANCE_METRIC,
                message=f"Performance test {i}",
                data={"iteration": i, "timestamp": time.time()}
            )
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Should be able to log 1000 events in reasonable time (< 1 second)
        assert duration < 1.0
        
        # Check all events were logged
        events = engine.buffer.get_events()
        assert len(events) >= 1000  # Including init event
    
    def test_metric_recording_performance(self):
        """Benchmark metric recording performance."""
        import time
        
        engine = TelemetryEngine(buffer_size=10000)
        
        start_time = time.time()
        
        for i in range(1000):
            engine.record_metric(
                name=f"performance_metric_{i % 10}",  # Reuse names to test accumulation
                value=i,
                metric_type=MetricType.COUNTER,
                tags={"batch": str(i // 100)}
            )
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Should be able to record 1000 metrics quickly
        assert duration < 1.0
        
        metrics = engine.buffer.get_metrics()
        assert len(metrics) >= 1000  # May include cost metrics from init
    
    @pytest.mark.asyncio
    async def test_export_performance(self):
        """Benchmark export performance with large dataset."""
        import time
        
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = TelemetryEngine(export_directory=tmpdir, buffer_size=5000)
            
            # Generate significant amount of data
            for i in range(2000):
                engine.log_event(
                    event_type=TelemetryEventType.BATCH_COMPLETED,
                    message=f"Batch processing {i}",
                    data={"batch_size": i % 100, "processing_time": i * 0.1}
                )
                
                if i % 10 == 0:
                    engine.record_metric(f"batch_metric_{i}", i, MetricType.GAUGE)
            
            start_time = time.time()
            exported_files = await engine.flush_all()
            end_time = time.time()
            
            export_duration = end_time - start_time
            
            # Should export large dataset in reasonable time
            assert export_duration < 5.0  # 5 seconds max
            
            # Verify exports completed
            assert len(exported_files["events"]) > 0
            assert len(exported_files["metrics"]) > 0