# Telemetry Engine Implementation

## Overview

The Telemetry Engine is a production-grade monitoring and cost tracking system for the AI-powered SCA scanner. It provides comprehensive observability, performance metrics, compliance logging, and AI API cost analytics.

## Key Features

### 🔍 **Comprehensive Monitoring**
- Structured event logging with metadata
- Performance metrics collection (counters, gauges, histograms, timers)
- Memory-efficient circular buffering
- Real-time event and metric hooks for monitoring systems

### 💰 **AI API Cost Tracking**
- Per-provider cost breakdown (OpenAI, Anthropic, Google, X.AI)
- Token usage analytics (input/output tokens)
- Request-level cost tracking with averages
- Session and daily cost summaries

### 📊 **Export Capabilities**
- Multiple formats: JSON, Prometheus, CSV, JSON Lines
- Async export operations for high performance
- Automatic data flushing with configurable intervals
- Memory-efficient streaming for large datasets

### 🛡️ **Enterprise Compliance**
- Structured audit logging
- Compliance tags and metadata
- User and organization tracking
- Security event logging

### ⚡ **Production Ready**
- Async operations with context managers
- Thread-safe buffer operations
- Graceful error handling
- High-volume data support

## Architecture

```
TelemetryEngine
├── TelemetryBuffer (circular buffer)
├── CostTrackers (per provider/model)
├── PerformanceCounters/Gauges
├── EventHooks/MetricHooks
└── ExportManager (JSON/Prometheus/CSV)
```

## Installation

The telemetry engine is included in the SCA scanner package:

```python
from sca_ai_scanner.telemetry import TelemetryEngine, telemetry_session
```

## Quick Start

### Basic Usage

```python
import asyncio
from sca_ai_scanner.telemetry import TelemetryEngine, TelemetryEventType

async def main():
    async with TelemetryEngine() as telemetry:
        # Log events
        telemetry.log_event(
            event_type=TelemetryEventType.SCAN_STARTED,
            message="Starting vulnerability scan",
            data={"packages_count": 42}
        )
        
        # Record performance metrics
        telemetry.record_metric("packages_scanned", 42, MetricType.COUNTER)
        
        # Track AI costs
        telemetry.track_ai_cost(
            provider="openai",
            model="gpt-4o-mini",
            input_tokens=100,
            output_tokens=50,
            cost_usd=0.02
        )
        
        # Export all data
        exported = await telemetry.flush_all()
        print(f"Exported: {exported}")

asyncio.run(main())
```

### Using Context Manager

```python
from sca_ai_scanner.telemetry import telemetry_session

async with telemetry_session(
    compliance_mode=True,
    export_directory="./production_telemetry"
) as session:
    # Access telemetry engine
    session.engine.log_event(...)
    
    # Use integration decorators
    @session.integration.track_scan_lifecycle
    async def scan_packages(packages):
        return scan_results
```

## Integration with AI Client

### Automatic Integration

```python
from sca_ai_scanner.telemetry import add_telemetry_to_ai_client

@add_telemetry_to_ai_client
class AIVulnerabilityClient:
    # Existing code remains unchanged
    # Telemetry automatically added to:
    # - bulk_analyze() method
    # - AI API request methods
    pass
```

### Manual Integration

```python
from sca_ai_scanner.telemetry import TelemetryIntegration

telemetry = TelemetryEngine()
integration = TelemetryIntegration(telemetry)

@integration.track_ai_requests
async def make_api_call(self, ...):
    # AI API call logic
    return result
```

## Event Types

The system supports structured event types:

```python
class TelemetryEventType(str, Enum):
    # Scan lifecycle
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed" 
    SCAN_FAILED = "scan_failed"
    
    # Batch processing
    BATCH_STARTED = "batch_started"
    BATCH_COMPLETED = "batch_completed"
    BATCH_FAILED = "batch_failed"
    
    # AI API events
    API_REQUEST_STARTED = "api_request_started"
    API_REQUEST_COMPLETED = "api_request_completed"
    API_REQUEST_FAILED = "api_request_failed"
    API_COST_UPDATED = "api_cost_updated"
    
    # Performance and compliance
    PERFORMANCE_METRIC = "performance_metric"
    AUDIT_LOG = "audit_log"
    SECURITY_EVENT = "security_event"
```

## Metric Types

Performance metrics support multiple types:

```python
class MetricType(str, Enum):
    COUNTER = "counter"    # Cumulative values
    GAUGE = "gauge"        # Current values
    HISTOGRAM = "histogram" # Distribution
    TIMER = "timer"        # Duration tracking
```

## Export Formats

### JSON Export
```python
# Events and metrics as JSON
await telemetry.export_events(ExportFormat.JSON)
await telemetry.export_metrics(ExportFormat.JSON)
```

### Prometheus Export
```python
# Metrics in Prometheus format for monitoring
await telemetry.export_metrics(ExportFormat.PROMETHEUS)
```

Output example:
```
# HELP api_requests_total Total API requests
# TYPE api_requests_total counter
api_requests_total{provider="openai",model="gpt-4o"} 150

# HELP scan_duration_seconds Scan duration in seconds  
# TYPE scan_duration_seconds gauge
scan_duration_seconds 45.2
```

### CSV Export
```python
# Tabular data for analysis
await telemetry.export_events(ExportFormat.CSV)
await telemetry.export_cost_summary(ExportFormat.CSV)
```

## Cost Tracking

### Comprehensive Cost Analytics

```python
# Get detailed cost breakdown
cost_summary = telemetry.get_cost_summary()

print(f"Total cost: ${cost_summary['total_cost_usd']:.4f}")
print(f"Providers: {list(cost_summary['providers'].keys())}")

# Provider breakdown
for provider, data in cost_summary['providers'].items():
    print(f"{provider}: ${data['cost_usd']:.4f} ({data['percentage']:.1f}%)")

# Model-level analytics
for model, data in cost_summary['models'].items():
    print(f"{model}: {data['request_count']} requests, "
          f"avg ${data['avg_cost_per_request']:.4f}/request")
```

### Output Example:
```json
{
  "total_cost_usd": 0.85,
  "providers": {
    "openai": {
      "cost_usd": 0.65,
      "input_tokens": 50000,
      "output_tokens": 25000,
      "percentage": 76.5
    },
    "anthropic": {
      "cost_usd": 0.20,
      "input_tokens": 15000,
      "output_tokens": 7500,
      "percentage": 23.5
    }
  },
  "models": {
    "openai:gpt-4o-mini": {
      "cost_usd": 0.35,
      "request_count": 45,
      "avg_cost_per_request": 0.0078
    }
  }
}
```

## Performance Monitoring

### Timer Operations
```python
# Track operation duration
timer_id = telemetry.start_timer("vulnerability_analysis")
# ... perform work ...
duration = telemetry.stop_timer(timer_id, tags={"batch_size": "100"})
```

### Custom Metrics
```python
# Counter - cumulative values
telemetry.record_metric("vulnerabilities_found", 5, MetricType.COUNTER)

# Gauge - current values  
telemetry.record_metric("memory_usage_mb", 256.7, MetricType.GAUGE)

# With tags for filtering
telemetry.record_metric(
    "api_latency", 
    145.2, 
    MetricType.TIMER,
    tags={"provider": "openai", "model": "gpt-4o"}
)
```

## Compliance and Audit

### Enterprise Compliance Mode

```python
telemetry = TelemetryEngine(compliance_mode=True)

# Automatically adds:
# - compliance_tags: ["audit", "security", "production"]
# - organization_id from environment
# - user_id from environment
# - Enhanced audit logging
```

### Security Events

```python
telemetry.log_event(
    event_type=TelemetryEventType.SECURITY_EVENT,
    message="Suspicious API usage detected",
    level="WARN",
    data={
        "api_calls_per_minute": 150,
        "threshold": 100,
        "action": "rate_limited"
    }
)
```

## Production Configuration

### Memory Management

```python
telemetry = TelemetryEngine(
    buffer_size=50000,           # Events/metrics in memory
    auto_flush_interval=300,     # Auto-export every 5 minutes  
    export_directory="/var/log/telemetry"
)
```

### Real-time Monitoring Hooks

```python
def alert_on_high_cost(event):
    if event.cost_usd and event.cost_usd > 1.0:
        send_alert(f"High API cost: ${event.cost_usd}")

def metrics_to_datadog(metric):
    datadog_client.gauge(metric.name, metric.value, tags=metric.tags)

telemetry.add_event_hook(alert_on_high_cost)
telemetry.add_metric_hook(metrics_to_datadog)
```

## Testing

The telemetry engine includes comprehensive unit tests with 70+ test cases:

```bash
# Run all telemetry tests
pytest tests/unit/test_telemetry_engine.py -v

# Run specific test categories
pytest tests/unit/test_telemetry_engine.py::TestCostTracking -v
pytest tests/unit/test_telemetry_engine.py::TestExportFormats -v
pytest tests/unit/test_telemetry_engine.py::TestProductionScenarios -v
```

### Test Coverage

- ✅ Basic functionality and initialization
- ✅ Event logging with structured data
- ✅ Performance metrics and monitoring
- ✅ AI API cost tracking per provider
- ✅ Export formats (JSON, Prometheus, CSV)
- ✅ Async operations and buffering
- ✅ Compliance and audit logging
- ✅ Error handling and edge cases
- ✅ Production scenarios and stress tests

## Statistics and Monitoring

### Runtime Statistics

```python
stats = telemetry.get_statistics()
print(f"Buffer usage: {stats['buffer']['events_count']}/{stats['buffer']['max_size']}")
print(f"Total cost: ${stats['costs']['total_usd']:.4f}")
print(f"Providers tracked: {stats['costs']['providers_tracked']}")
```

## Best Practices

### 1. Use Context Managers
```python
# ✅ Recommended - automatic start/stop and flush
async with TelemetryEngine() as telemetry:
    # ... telemetry operations ...

# ✅ Also good - session-based approach
async with telemetry_session() as session:
    # ... use session.engine ...
```

### 2. Structure Event Data
```python
# ✅ Good - structured data
telemetry.log_event(
    event_type=TelemetryEventType.SCAN_COMPLETED,
    message="Vulnerability scan completed",
    data={
        "packages_scanned": 156,
        "vulnerabilities_found": 23,
        "scan_duration_seconds": 45.2,
        "high_severity_count": 3
    }
)
```

### 3. Tag Metrics for Filtering
```python
# ✅ Good - tags enable filtering and aggregation
telemetry.record_metric(
    "api_requests_total",
    1,
    MetricType.COUNTER,
    tags={
        "provider": "openai",
        "model": "gpt-4o-mini", 
        "status": "success"
    }
)
```

### 4. Use Decorators for Integration
```python
# ✅ Recommended - automatic telemetry without code changes
@integration.track_scan_lifecycle
async def vulnerability_scan(packages):
    return scan_results
```

### 5. Configure for Production
```python
# ✅ Production configuration
telemetry = TelemetryEngine(
    compliance_mode=True,          # Enterprise compliance
    buffer_size=100000,            # Large buffer for high volume
    auto_flush_interval=180,       # Export every 3 minutes
    export_directory="/opt/telemetry", # Persistent storage
    enable_async_export=True       # Non-blocking exports
)
```

## File Structure

```
src/sca_ai_scanner/telemetry/
├── __init__.py              # Public API exports
├── engine.py                # Core TelemetryEngine implementation
└── integration.py           # Integration utilities and decorators

tests/unit/
└── test_telemetry_engine.py # Comprehensive test suite (70+ tests)

export_directory/
├── telemetry_events_YYYYMMDD_HHMMSS.json
├── telemetry_metrics_YYYYMMDD_HHMMSS.json
├── telemetry_metrics_YYYYMMDD_HHMMSS.prom
└── cost_summary_YYYYMMDD_HHMMSS.json
```

## Dependencies

The telemetry engine uses only standard library modules and existing project dependencies:

- `asyncio` - Async operations
- `aiofiles` - Async file I/O  
- `json` - JSON serialization
- `csv` - CSV export
- `pathlib` - Path handling
- `datetime` - Timestamps
- `uuid` - Unique identifiers
- `threading` - Thread safety
- `collections` - Data structures
- `enum` - Enumerations
- `dataclasses` - Data models

## Performance Characteristics

- **Memory Usage**: Circular buffer prevents unbounded growth
- **Async Operations**: Non-blocking I/O for exports
- **Thread Safety**: Safe for concurrent access
- **Export Performance**: Can handle 10,000+ events efficiently
- **Cost Tracking**: Real-time accumulation with minimal overhead

## Monitoring Integration

The telemetry system is designed to integrate with common monitoring platforms:

- **Prometheus**: Native metrics export format
- **DataDog**: Via metric hooks
- **Grafana**: Prometheus data source
- **ELK Stack**: JSON/JSONL event export
- **Custom Systems**: Event/metric hooks and CSV export

---

This telemetry implementation provides production-grade monitoring, cost tracking, and compliance logging for the AI-powered SCA scanner, enabling comprehensive observability and optimization of scanner operations.