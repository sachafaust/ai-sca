"""
CLI interface for AI-powered SCA vulnerability scanner.
Implements AI Agent First design with secure API key handling.
"""

import asyncio
import os
import sys
from pathlib import Path
from typing import Optional, Dict, Any
import json
import logging

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

from .core.client import AIVulnerabilityClient
from .core.models import ScanConfig, VulnerabilityResults
from .core.recommendation_strategies import StrategyManager
from .core.location_aware_config import LocationAwareConfig
# ValidationPipeline removed - using AI-only approach
from .parsers.python import PythonParser
from .parsers.javascript import JavaScriptParser
from .formatters.json_output import JSONOutputFormatter
from .formatters.markdown_report import MarkdownReportFormatter
from .config.manager import ConfigManager
from .telemetry.engine import TelemetryEngine
from .exceptions import (
    AuthenticationError, BudgetExceededError, UnsupportedModelError,
    ConfigurationError
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Console for rich output
console = Console()


@click.command()
@click.argument('target_path', type=click.Path(exists=True, path_type=Path), required=False)
@click.option(
    '--model', 
    default='gpt-4o-mini-with-search',
    help='AI model for analysis - supports ALL OpenAI, Anthropic, Google, X.AI models (default: gpt-4o-mini-with-search)'
)
@click.option(
    '--knowledge-only',
    is_flag=True,
    help='Disable live search, use training data only'
)
@click.option(
    '--config',
    type=click.Path(path_type=Path),
    help='YAML config file path'
)
@click.option(
    '--batch-size',
    type=int,
    default=None,
    help='Override batch size for rare edge cases (default: auto-optimize for model context)'
)
@click.option(
    '--budget',
    type=float,
    default=None,
    help='Daily spending limit in USD (enables budget checking when specified)'
)
@click.option(
    '--vulnerability-data',
    type=click.Path(path_type=Path),
    help='Export structured vulnerability data for AI agents'
)
@click.option(
    '--report',
    type=click.Path(path_type=Path),
    help='Generate human-readable markdown report'
)
@click.option(
    '--telemetry-file',
    type=click.Path(path_type=Path),
    default=Path('./sca_telemetry.jsonl'),
    help='AI agent telemetry output (default: ./sca_telemetry.jsonl)'
)
@click.option(
    '--telemetry-level',
    type=click.Choice(['info', 'debug', 'trace'], case_sensitive=False),
    default='info',
    help='AI agent telemetry verbosity (default: info)'
)
@click.option(
    '--exclusions',
    type=click.Path(exists=True, path_type=Path),
    help='User-controlled exclusions config file'
)
@click.option(
    '--force-fresh',
    is_flag=True,
    help='Ignore caches, full AI agent analysis'
)
@click.option(
    '--audit-trail',
    type=click.Path(path_type=Path),
    help='Complete audit trail for AI agent review'
)
@click.option(
    '--validate-critical',
    is_flag=True,
    default=False,
    help='Always validate CRITICAL/HIGH findings (default: disabled)'
)
@click.option(
    '--output-format',
    type=click.Choice(['json', 'table', 'summary'], case_sensitive=False),
    default='table',
    help='Output format (default: table)'
)
@click.option(
    '--quiet',
    is_flag=True,
    help='Minimal output for automated scripts'
)
@click.option(
    '--verbose',
    is_flag=True,
    help='Verbose output with detailed progress'
)
@click.option(
    '--recommendation-strategy',
    default='balanced_security',
    help='Recommendation strategy: balanced_security, conservative_stability, aggressive_security, rapid_development (default: balanced_security)'
)
@click.option(
    '--custom-strategy',
    type=click.Path(exists=True, path_type=Path),
    help='Path to custom recommendation strategy YAML file'
)
@click.option(
    '--location-config',
    type=click.Path(exists=True, path_type=Path),
    help='Path to location-aware recommendation configuration (advanced)'
)
@click.option(
    '--create-location-config',
    type=click.Path(path_type=Path),
    help='Create example location-aware config file and exit'
)
@click.option(
    '--list-strategies',
    is_flag=True,
    help='List available recommendation strategies and exit'
)
def main(
    target_path: Optional[Path],
    model: str,
    knowledge_only: bool,
    config: Optional[Path],
    batch_size: int,
    budget: float,
    vulnerability_data: Optional[Path],
    report: Optional[Path],
    telemetry_file: Path,
    telemetry_level: str,
    exclusions: Optional[Path],
    force_fresh: bool,
    audit_trail: Optional[Path],
    validate_critical: bool,
    output_format: str,
    quiet: bool,
    verbose: bool,
    recommendation_strategy: str,
    custom_strategy: Optional[Path],
    location_config: Optional[Path],
    create_location_config: Optional[Path],
    list_strategies: bool
):
    """
    AI-Powered SCA Vulnerability Scanner
    
    Fast, accurate vulnerability scanning powered by AI agents for multi-language codebases.
    
    TARGET_PATH: Path to the project directory to scan
    """
    
    # Handle location config creation
    if create_location_config:
        try:
            location_config = LocationAwareConfig()
            location_config.create_example_config_file(create_location_config)
            console.print(f"\n[green]✅ Created example location config: {create_location_config}[/green]")
            console.print("\n[cyan]📋 Progressive Configuration Levels:[/cyan]")
            console.print("  1. [yellow]Simple[/yellow]: sca-scanner . (uses balanced_security everywhere)")
            console.print("  2. [yellow]Organizational[/yellow]: sca-scanner . --recommendation-strategy conservative_stability")
            console.print("  3. [yellow]Location-Aware[/yellow]: sca-scanner . --location-config my-location.yml")
            console.print(f"\n[blue]💡 Edit {create_location_config} to customize location-specific strategies[/blue]")
            return
        except Exception as e:
            console.print(f"\n[red]❌ Failed to create location config: {e}[/red]")
            sys.exit(1)

    # Handle strategy listing
    if list_strategies:
        strategy_manager = StrategyManager()
        console.print("\n[cyan]📋 Available Recommendation Strategies:[/cyan]")
        
        for strategy_name in strategy_manager.list_strategies():
            strategy = strategy_manager.get_strategy(strategy_name)
            if strategy:
                console.print(f"\n[yellow]{strategy_name}[/yellow]")
                console.print(f"  Description: {strategy.description}")
                console.print(f"  Max version jump: {strategy.upgrade_constraints.max_version_jump.value}")
                console.print(f"  Allow breaking changes: {strategy.upgrade_constraints.allow_breaking_changes}")
                console.print(f"  Max effort level: {strategy.upgrade_constraints.max_effort_level.value}")
        
        console.print(f"\n[green]💡 Usage Levels:[/green]")
        console.print("  [yellow]Simple[/yellow]: sca-scanner . (default: balanced_security)")
        console.print("  [yellow]Organizational[/yellow]: sca-scanner . --recommendation-strategy <strategy_name>")
        console.print("  [yellow]Location-Aware[/yellow]: sca-scanner . --location-config /path/to/config.yml")
        console.print(f"\n[green]📄 Custom Strategy:[/green] sca-scanner . --custom-strategy /path/to/strategy.yml")
        console.print(f"[green]🏗️  Location Config:[/green] sca-scanner --create-location-config my-locations.yml")
        return
    
    # Require target_path for actual scanning
    if not target_path:
        console.print("\n[red]Error: TARGET_PATH is required for scanning[/red]")
        console.print("Use --list-strategies to see available recommendation strategies")
        sys.exit(1)
    
    # Setup logging level
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif quiet:
        logging.getLogger().setLevel(logging.WARNING)
    
    try:
        # Run async main function
        asyncio.run(async_main(
            target_path=target_path,
            model=model,
            knowledge_only=knowledge_only,
            config=config,
            batch_size=batch_size,
            budget=budget,
            vulnerability_data=vulnerability_data,
            report=report,
            telemetry_file=telemetry_file,
            telemetry_level=telemetry_level,
            exclusions=exclusions,
            force_fresh=force_fresh,
            audit_trail=audit_trail,
            validate_critical=validate_critical,
            output_format=output_format,
            quiet=quiet,
            verbose=verbose,
            recommendation_strategy=recommendation_strategy,
            custom_strategy=custom_strategy
        ))
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        if verbose:
            console.print_exception()
        sys.exit(1)


async def async_main(**kwargs):
    """Async main function to handle the scanning workflow."""
    
    # Extract parameters
    target_path = kwargs['target_path']
    model = kwargs['model']
    knowledge_only = kwargs['knowledge_only']
    budget = kwargs['budget']
    batch_size = kwargs['batch_size']
    validate_critical = kwargs['validate_critical']
    output_format = kwargs['output_format']
    quiet = kwargs['quiet']
    verbose = kwargs['verbose']
    
    # Initialize configuration
    config_manager = ConfigManager(kwargs.get('config'))
    scan_config = create_scan_config(kwargs, config_manager)
    
    # Validate environment and configuration
    validate_environment(scan_config)
    
    if not quiet:
        print_banner(scan_config)
    
    # Initialize telemetry
    telemetry = TelemetryEngine(
        output_file=kwargs['telemetry_file'],
        level=kwargs['telemetry_level']
    )
    
    # Start scan
    scan_start_time = asyncio.get_event_loop().time()
    
    try:
        # Initialize AI client
        async with AIVulnerabilityClient(scan_config) as ai_client:
            
            # AI-only approach - no external validation needed
            
            # Discover and parse dependencies
            if not quiet:
                console.print("\n[cyan]🔍 Discovering dependencies...[/cyan]")
            
            packages = await discover_dependencies(target_path, telemetry)
            
            if not packages:
                console.print("[yellow]⚠️  No dependencies found to analyze[/yellow]")
                return
            
            if not quiet:
                console.print(f"[green]📦 Found {len(packages)} packages to analyze[/green]")
            
            # AI-powered vulnerability analysis
            if not quiet:
                console.print("\n[cyan]🤖 Running AI vulnerability analysis...[/cyan]")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                disable=quiet
            ) as progress:
                
                analysis_task = progress.add_task(
                    f"Analyzing {len(packages)} packages with {model}...", 
                    total=None
                )
                
                # Run AI analysis
                results = await ai_client.bulk_analyze(packages)
                
                progress.update(analysis_task, completed=True)
            
            # AI-only analysis complete - no external validation needed
            
            # Generate output
            scan_duration = asyncio.get_event_loop().time() - scan_start_time
            await generate_output(
                results, 
                scan_duration,
                kwargs,
                telemetry
            )
                
    except AuthenticationError as e:
        console.print(f"\n[red]❌ Authentication Error[/red]: {e}")
        console.print(_get_auth_help_message(scan_config.model))
        sys.exit(1)
        
    except BudgetExceededError as e:
        console.print(f"\n[red]❌ Budget Exceeded[/red]: {e}")
        console.print(f"💡 Increase budget with: --budget {budget * 2 if budget else 100}")
        sys.exit(1)
        
    except UnsupportedModelError as e:
        console.print(f"\n[red]❌ Unsupported Model[/red]: {e}")
        console.print(_get_model_help_message())
        sys.exit(1)


def create_scan_config(cli_args: Dict[str, Any], config_manager: ConfigManager) -> ScanConfig:
    """Create scan configuration from CLI args and config file."""
    
    # Load base config from file
    base_config = config_manager.load_config()
    
    # Override with CLI arguments
    budget_enabled = cli_args['budget'] is not None
    daily_budget_limit = cli_args['budget'] if budget_enabled else base_config.get('budget', {}).get('daily_limit', 50.0)
    
    config_data = {
        'model': cli_args['model'],
        'enable_live_search': not cli_args['knowledge_only'],
        'context_optimization': base_config.get('analysis', {}).get('context_optimization', True),
        'batch_size': cli_args['batch_size'],
        'budget_enabled': budget_enabled,
        'daily_budget_limit': daily_budget_limit,
        'confidence_threshold': base_config.get('analysis', {}).get('confidence_threshold', 0.8),
        'max_retries': base_config.get('analysis', {}).get('max_retries', 3),
        'timeout_seconds': base_config.get('analysis', {}).get('timeout_seconds', 30),
        'validate_critical': cli_args['validate_critical'],
        'recommendation_strategy': cli_args.get('recommendation_strategy', 'balanced_security'),
        'custom_strategy_path': str(cli_args['custom_strategy']) if cli_args['custom_strategy'] else None
    }
    
    return ScanConfig(**config_data)


def validate_environment(config: ScanConfig):
    """Validate environment and API keys."""
    
    # Detect provider from model (comprehensive 2025 coverage)
    if (config.model.startswith('gpt-') or 
        config.model.startswith('o1') or config.model == 'o1' or
        config.model.startswith('o2') or config.model == 'o2' or
        config.model.startswith('o3') or config.model == 'o3' or
        config.model.startswith('o4') or config.model == 'o4' or
        config.model.startswith('chat-') or config.model.startswith('text-')):
        provider = 'openai'
        required_env = 'OPENAI_API_KEY'
    elif config.model.startswith('claude-'):
        provider = 'anthropic'
        required_env = 'ANTHROPIC_API_KEY'
    elif config.model.startswith('gemini-'):
        provider = 'google'
        required_env = 'GOOGLE_AI_API_KEY'
    elif config.model.startswith('grok-') or config.model == 'grok':
        provider = 'xai'
        required_env = 'XAI_API_KEY'
    else:
        raise UnsupportedModelError(f"Unknown model provider for: {config.model}")
    
    # Check if API key is set
    api_key = os.getenv(required_env)
    if not api_key:
        raise AuthenticationError(
            f"API key not found for {provider}. "
            f"Set environment variable: {required_env}"
        )


def print_banner(config: ScanConfig):
    """Print scanner banner with configuration info."""
    
    # Determine data source info
    if config.enable_live_search:
        data_source = "AI Knowledge + Live Web Search (current vulnerability databases)"
        data_freshness = "Current as of scan time (live lookup enabled by default)"
    else:
        data_source = "AI Training Knowledge (cutoff: varies by model)"
        data_freshness = "Training cutoff date - may miss recent CVEs"
    
    banner_text = f"""[bold cyan]🤖 AI Agent First SCA Scanner[/bold cyan]
   🎯 Model: {config.model}
   🔍 Data Source: {data_source}
   🔄 Agentic workflow: INPUT → SCAN → ANALYSIS → REMEDIATION
   📊 Data Freshness: {data_freshness}
   ✅ Data Integrity: COMPLETE results - NO sampling or truncation"""
    
    console.print(Panel(banner_text, title="AI-Powered SCA Scanner", border_style="cyan"))


async def discover_dependencies(target_path: Path, telemetry: TelemetryEngine) -> list:
    """Discover all dependencies across supported languages."""
    
    all_packages = []
    
    # Initialize parsers
    parsers = [
        PythonParser(str(target_path)),
        JavaScriptParser(str(target_path))
    ]
    
    # Parse dependencies from each language
    for parser in parsers:
        try:
            packages = parser.parse_all_files()
            all_packages.extend(packages)
            
            telemetry.log_event(
                'dependency_discovery',
                {
                    'parser': parser.__class__.__name__,
                    'packages_found': len(packages),
                    'ecosystem': parser.get_ecosystem_name()
                }
            )
            
        except Exception as e:
            logger.warning(f"Failed to parse {parser.__class__.__name__}: {e}")
            continue
    
    # Remove duplicates while preserving source locations
    unique_packages = {}
    for package in all_packages:
        key = f"{package.name}:{package.version}:{package.ecosystem}"
        if key in unique_packages:
            # Merge source locations
            existing = unique_packages[key]
            existing.source_locations.extend(package.source_locations)
        else:
            unique_packages[key] = package
    
    return list(unique_packages.values())


async def generate_output(
    results: VulnerabilityResults,
    scan_duration: float,
    cli_args: Dict[str, Any],
    telemetry: TelemetryEngine
):
    """Generate and display scan results."""
    
    output_format = cli_args['output_format']
    quiet = cli_args['quiet']
    vulnerability_data_file = cli_args.get('vulnerability_data')
    report_file = cli_args.get('report')
    
    # Export structured data for AI agents
    if vulnerability_data_file:
        formatter = JSONOutputFormatter()
        await formatter.export_vulnerability_data(results, vulnerability_data_file)
        
        if not quiet:
            console.print(f"\n[green]💾 Exported structured data to {vulnerability_data_file}[/green]")
    
    # Generate human-readable markdown report
    if report_file:
        markdown_formatter = MarkdownReportFormatter()
        markdown_formatter.generate_report(
            results, 
            scan_duration, 
            cli_args, 
            report_file
        )
        
        if not quiet:
            console.print(f"\n[green]📄 Generated markdown report: {report_file}[/green]")
    
    # Display results based on format
    if output_format == 'json':
        print(json.dumps(results.dict(), indent=2, default=str))
    elif output_format == 'summary':
        print_summary(results, scan_duration)
    else:  # table format
        print_table_results(results, scan_duration)
    
    # Log telemetry
    telemetry.log_event(
        'scan_completed',
        {
            'duration_seconds': scan_duration,
            'total_packages': results.vulnerability_summary.total_packages_analyzed,
            'vulnerable_packages': results.vulnerability_summary.vulnerable_packages,
            'output_format': output_format
        }
    )


def print_summary(results: VulnerabilityResults, duration: float):
    """Print concise summary of results."""
    
    summary = results.vulnerability_summary
    
    rprint(f"\n[bold green]✅ Scan completed in {duration:.1f} seconds[/bold green]")
    rprint(f"🧠 AI Model: {results.scan_metadata.get('model', 'Unknown')}")
    rprint(f"📦 Scanned {summary.total_packages_analyzed} dependencies")
    
    if summary.vulnerable_packages > 0:
        severity_text = []
        for severity, count in summary.severity_breakdown.items():
            if count > 0:
                color = {
                    'CRITICAL': 'red',
                    'HIGH': 'orange1', 
                    'MEDIUM': 'yellow',
                    'LOW': 'blue'
                }.get(severity, 'white')
                severity_text.append(f"[{color}]{count} {severity.lower()}[/{color}]")
        
        rprint(f"🚨 Found {summary.vulnerable_packages} vulnerabilities ({', '.join(severity_text)})")
    else:
        rprint("[green]🛡️  No vulnerabilities found[/green]")


def print_table_results(results: VulnerabilityResults, duration: float):
    """Print COMPLETE table of vulnerability results.
    
    CRITICAL: Shows ALL vulnerabilities and ALL packages - NO SAMPLING.
    Includes AI model context for result interpretation.
    """
    
    summary = results.vulnerability_summary
    
    # Summary header
    rprint(f"\n[bold green]🤖 AI Agent First SCA Scanner Results[/bold green]")
    rprint(f"⏱️  Scan duration: {duration:.1f} seconds")
    rprint(f"🧠 AI Model: {results.scan_metadata.get('model', 'Unknown')}")
    rprint(f"📦 Packages analyzed: {summary.total_packages_analyzed}")
    rprint(f"🚨 Vulnerabilities: {summary.vulnerable_packages}")
    
    if summary.vulnerable_packages == 0:
        rprint("\n[green]🛡️  No vulnerabilities found! All packages appear secure.[/green]")
        return
    
    # Vulnerability table
    table = Table(title="Vulnerability Findings", show_header=True, header_style="bold magenta")
    table.add_column("Package", style="cyan", width=20)
    table.add_column("Version", style="blue", width=10)
    table.add_column("CVE ID", style="yellow", width=15)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("CVSS", style="red", width=6)
    table.add_column("Source", style="green", width=25)
    table.add_column("Description", width=30)
    
    # Sort by severity for display
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    
    # CRITICAL: This shows ALL vulnerabilities - NO SAMPLING or truncation
    vulnerable_packages = []
    for pkg_id, analysis in results.vulnerability_analysis.items():
        if analysis.cves:
            # Include ALL CVEs for this package - never truncate
            for cve in analysis.cves:
                vulnerable_packages.append((pkg_id, analysis, cve))
    
    # Sort by severity
    vulnerable_packages.sort(key=lambda x: severity_order.get(x[2].severity.value, 4))
    
    for pkg_id, analysis, cve in vulnerable_packages:
        # Handle both package:version and package==version formats
        if ':' in pkg_id:
            package_name, version = pkg_id.split(':', 1)
        elif '==' in pkg_id:
            package_name, version = pkg_id.split('==', 1)
        else:
            package_name = pkg_id
            version = 'unknown'
        
        # Color code severity
        severity_color = {
            'CRITICAL': '[bold red]',
            'HIGH': '[bold orange1]',
            'MEDIUM': '[bold yellow]',
            'LOW': '[bold blue]'
        }.get(cve.severity.value, '[white]')
        
        severity_text = f"{severity_color}{cve.severity.value}[/]"
        cvss_text = f"{cve.cvss_score:.1f}" if cve.cvss_score else "N/A"
        description = cve.description[:27] + "..." if len(cve.description) > 30 else cve.description
        
        # Get source location for display
        source_locations = results.source_locations.get(pkg_id, [])
        if source_locations:
            if len(source_locations) == 1:
                location = source_locations[0]
                source_text = f"{location.file_path}:{location.line_number}"
                if len(source_text) > 24:
                    source_text = "..." + source_text[-21:]
            else:
                # Multiple locations - show count and first location
                first_location = source_locations[0]
                source_text = f"{first_location.file_path}:{first_location.line_number} (+{len(source_locations)-1} more)"
                if len(source_text) > 24:
                    source_text = f"...{first_location.file_path.split('/')[-1]}:{first_location.line_number} (+{len(source_locations)-1})"
        else:
            source_text = "Unknown"
        
        table.add_row(
            package_name,
            version,
            cve.id,
            severity_text,
            cvss_text,
            source_text,
            description
        )
    
    console.print(table)
    
    # Next steps
    rprint(f"\n[bold cyan]🎯 AI Agent Intelligence Output:[/bold cyan]")
    rprint("📋 Vulnerability data: Ready for AI agent consumption")
    rprint("🤖 Remediation-ready: Data optimized for specialized remediation AI agents")
    rprint("✅ Completeness: ALL vulnerabilities and source locations included - NO SAMPLING")
    
    for step in summary.recommended_next_steps:
        rprint(f"   • {step}")


def _get_auth_help_message(model: str) -> str:
    """Get authentication help message for the model."""
    
    if (model.startswith('gpt-') or 
        model.startswith('o1') or model == 'o1' or
        model.startswith('o2') or model == 'o2' or
        model.startswith('o3') or model == 'o3' or
        model.startswith('o4') or model == 'o4' or
        model.startswith('chat-') or model.startswith('text-')):
        return """
💡 To fix this:
   export OPENAI_API_KEY="sk-..."
   
🔗 Get your API key at: https://platform.openai.com/api-keys"""
    
    elif model.startswith('claude-'):
        return """
💡 To fix this:
   export ANTHROPIC_API_KEY="sk-ant-..."
   
🔗 Get your API key at: https://console.anthropic.com/"""
    
    elif model.startswith('gemini-'):
        return """
💡 To fix this:
   export GOOGLE_AI_API_KEY="AIza..."
   
🔗 Get your API key at: https://makersuite.google.com/app/apikey"""
    
    elif model.startswith('grok-'):
        return """
💡 To fix this:
   export XAI_API_KEY="xai-..."
   
🔗 Get your API key at: https://console.x.ai/"""
    
    else:
        return "💡 Set the appropriate API key environment variable for your model"


def _get_model_help_message() -> str:
    """Get help message for model selection."""
    
    return """
💡 Universal Model Support - ALL current AI models supported:

🎯 Reasoning Models (2025 latest):
   --model o3                         (OpenAI's most advanced reasoning)
   --model o4-mini                    (efficient reasoning model)
   --model claude-4                   (Anthropic's latest)
   --model grok-4                     (X.AI's most capable)

⚡ Fast & Efficient (recommended):
   --model gpt-4o-mini               (balanced performance, cost-effective)
   --model gemini-2.5-flash          (ultra-fast with thinking)
   --model claude-haiku              (high-speed processing)

🚀 Ultra-Fast (large-scale):
   --model gemini-2.5-flash-lite     (lowest latency)
   --model grok-3-mini               (efficient alternative)

🎯 Premium (maximum accuracy):
   --model gpt-4.1                   (latest GPT model)
   --model claude-3.7-sonnet         (hybrid reasoning)
   --model gemini-2.5-pro            (thinking model)

🔍 Auto-Detection: Simply specify any model name - provider detected automatically
📋 Full Support: ALL OpenAI, Anthropic, Google, and X.AI models work out-of-the-box"""


if __name__ == '__main__':
    main()