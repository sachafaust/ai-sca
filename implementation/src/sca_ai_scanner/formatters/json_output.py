"""
JSON output formatter for AI agent consumption.
Produces structured vulnerability data optimized for downstream AI processing.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import logging

from ..core.models import VulnerabilityResults, Package
from ..exceptions import OutputFormattingError

logger = logging.getLogger(__name__)


class JSONOutputFormatter:
    """
    JSON output formatter optimized for AI agent consumption.
    
    CRITICAL: Produces COMPLETE machine-readable vulnerability data - ALL vulnerabilities 
    and ALL source locations included with NO SAMPLING or truncation.
    """
    
    def __init__(self):
        """Initialize JSON formatter."""
        self.indent = 2
        self.ensure_ascii = False
        
    async def export_vulnerability_data(
        self, 
        results: VulnerabilityResults, 
        output_path: Path
    ) -> None:
        """
        Export vulnerability results to JSON file optimized for AI agents.
        
        Args:
            results: Vulnerability analysis results
            output_path: Path to output JSON file
        """
        try:
            # Convert results to AI agent optimized format
            ai_agent_data = self._convert_to_ai_agent_format(results)
            
            # Ensure output directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write JSON data
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(
                    ai_agent_data,
                    f,
                    indent=self.indent,
                    ensure_ascii=self.ensure_ascii,
                    default=self._json_serializer
                )
            
            logger.info(f"Exported vulnerability data to {output_path}")
            
        except Exception as e:
            raise OutputFormattingError(f"Failed to export JSON data: {e}", "json")
    
    def _convert_to_ai_agent_format(self, results: VulnerabilityResults) -> Dict[str, Any]:
        """Convert vulnerability results to AI agent optimized format."""
        
        ai_agent_data = {
            "ai_agent_metadata": {
                "workflow_stage": "remediation_ready",
                "confidence_level": self._calculate_overall_confidence(results),
                "autonomous_action_recommended": self._should_recommend_autonomous_action(results),
                "optimization_opportunities": self._identify_optimization_opportunities(results),
                "data_freshness": self._assess_data_freshness(results),
                "remediation_complexity": self._assess_remediation_complexity(results),
                "ai_model_used": results.scan_metadata.get('model', 'Unknown')
            },
            "vulnerability_analysis": self._format_vulnerability_analysis(results),
            "vulnerability_summary": self._format_vulnerability_summary(results),
            "remediation_intelligence": self._generate_remediation_intelligence(results),
            "scan_metadata": self._format_scan_metadata(results)
        }
        
        return ai_agent_data
    
    def _format_vulnerability_analysis(self, results: VulnerabilityResults) -> Dict[str, Any]:
        """Format detailed vulnerability analysis for AI agent consumption."""
        
        formatted_analysis = {}
        
        for pkg_id, analysis in results.vulnerability_analysis.items():
            
            # Extract package info (standardized package:version format)
            if ':' in pkg_id:
                package_name, version = pkg_id.split(':', 1)
            else:
                package_name = pkg_id
                version = 'unknown'
            
            # Format CVE findings
            formatted_cves = []
            for cve in analysis.cves:
                formatted_cve = {
                    "id": cve.id,
                    "severity": cve.severity.value,
                    "description": cve.description,
                    "cvss_score": cve.cvss_score,
                    "business_impact": self._assess_business_impact(cve),
                    "exploitability": self._assess_exploitability(cve),
                    "ai_agent_urgency": self._determine_ai_urgency(cve),
                    "data_source": cve.data_source,
                    "publish_date": cve.publish_date.isoformat() if cve.publish_date else None
                }
                formatted_cves.append(formatted_cve)
            
            # Format source locations with file references
            source_locations = []
            for location in self._get_package_source_locations(pkg_id, results):
                source_locations.append({
                    "file_path": location.file_path,
                    "line_number": location.line_number,
                    "declaration": location.declaration,
                    "file_type": location.file_type.value
                })
            
            # Compile package analysis - simplified to just CVEs and confidence
            formatted_analysis[pkg_id] = {
                "cves": formatted_cves,
                "confidence": analysis.confidence,
                "analysis_timestamp": analysis.analysis_timestamp.isoformat(),
                "source_locations": source_locations
            }
        
        return formatted_analysis
    
    def _format_vulnerability_summary(self, results: VulnerabilityResults) -> Dict[str, Any]:
        """Format vulnerability summary with AI agent insights."""
        
        summary = results.vulnerability_summary
        
        # Calculate additional metrics
        risk_distribution = self._calculate_risk_distribution(results)
        remediation_timeline = self._estimate_remediation_timeline(results)
        
        return {
            "total_packages_analyzed": summary.total_packages_analyzed,
            "vulnerable_packages": summary.vulnerable_packages,
            "security_coverage": (summary.total_packages_analyzed - summary.vulnerable_packages) / max(summary.total_packages_analyzed, 1),
            "severity_breakdown": summary.severity_breakdown,
            "risk_distribution": risk_distribution,
            "remediation_timeline": remediation_timeline,
            "immediate_action_required": self._count_immediate_actions(results),
            "automation_candidates": self._count_automation_candidates(results),
            "recommended_next_steps": summary.recommended_next_steps
        }
    
    def _generate_remediation_intelligence(self, results: VulnerabilityResults) -> Dict[str, Any]:
        """Generate AI agent remediation intelligence."""
        
        # Prioritize vulnerabilities by urgency and impact
        prioritized_vulnerabilities = self._prioritize_vulnerabilities(results)
        
        # Group by remediation strategy
        remediation_strategies = self._group_by_remediation_strategy(results)
        
        # Estimate effort and timeline
        effort_estimate = self._estimate_total_effort(results)
        
        return {
            "prioritized_vulnerabilities": prioritized_vulnerabilities,
            "remediation_strategies": remediation_strategies,
            "effort_estimation": effort_estimate,
            "parallel_opportunities": self._identify_parallel_opportunities(results),
            "dependency_conflicts": self._detect_dependency_conflicts(results),
            "testing_requirements": self._assess_testing_requirements(results)
        }
    
    def _format_scan_metadata(self, results: VulnerabilityResults) -> Dict[str, Any]:
        """Format scan metadata for AI agent context."""
        
        metadata = dict(results.scan_metadata)
        
        # Add AI agent specific metadata
        metadata.update({
            "ai_agent_compatibility": {
                "format_version": "3.0",
                "schema_compliance": "ai_agent_first",
                "machine_readable": True,
                "automation_ready": True
            },
            "quality_indicators": {
                "data_completeness": self._assess_data_completeness(results),
                "confidence_distribution": self._calculate_confidence_distribution(results),
                "validation_coverage": self._calculate_validation_coverage(results)
            },
            "performance_metrics": {
                "scan_efficiency": metadata.get('total_cost', 0) / max(results.vulnerability_summary.total_packages_analyzed, 1),
                "token_utilization": metadata.get('token_efficiency', 'optimal'),
                "cache_hit_ratio": metadata.get('cache_hit_ratio', 0.0)
            }
        })
        
        return metadata
    
    # Helper methods for data processing
    
    def _calculate_overall_confidence(self, results: VulnerabilityResults) -> str:
        """Calculate overall confidence level."""
        if not results.vulnerability_analysis:
            return "high"
        
        avg_confidence = sum(
            analysis.confidence 
            for analysis in results.vulnerability_analysis.values()
        ) / len(results.vulnerability_analysis)
        
        if avg_confidence >= 0.9:
            return "high"
        elif avg_confidence >= 0.7:
            return "medium"
        else:
            return "low"
    
    def _should_recommend_autonomous_action(self, results: VulnerabilityResults) -> bool:
        """Determine if autonomous action should be recommended."""
        # Recommend autonomous action if:
        # 1. High overall confidence
        # 2. Found vulnerabilities that need attention
        
        overall_confidence = self._calculate_overall_confidence(results)
        has_vulnerabilities = any(
            analysis.cves for analysis in results.vulnerability_analysis.values()
        )
        
        return overall_confidence == "high" and has_vulnerabilities
    
    def _identify_optimization_opportunities(self, results: VulnerabilityResults) -> List[str]:
        """Identify optimization opportunities for AI agents."""
        opportunities = []
        
        # Check for batch upgrade opportunities
        vulnerable_packages = sum(
            1 for analysis in results.vulnerability_analysis.values()
            if analysis.cves
        )
        
        if vulnerable_packages > 5:
            opportunities.append("Batch upgrade processing available for efficiency")
        
        # Check for automated testing opportunities
        if self._count_automation_candidates(results) > 3:
            opportunities.append("Multiple packages suitable for automated remediation")
        
        # Check for dependency consolidation
        if self._has_duplicate_dependencies(results):
            opportunities.append("Dependency consolidation possible")
        
        return opportunities
    
    def _assess_data_freshness(self, results: VulnerabilityResults) -> str:
        """Assess data freshness for AI agent context."""
        metadata = results.scan_metadata
        
        if metadata.get('live_search_enabled', False):
            return "current"
        else:
            return "training_data"
    
    def _assess_remediation_complexity(self, results: VulnerabilityResults) -> str:
        """Assess overall remediation complexity."""
        if not results.vulnerability_analysis:
            return "none"
        
        # Assess based on number of vulnerabilities
        total_vulns = sum(
            len(analysis.cves) for analysis in results.vulnerability_analysis.values()
        )
        
        if total_vulns == 0:
            return "none"
        elif total_vulns > 20:
            return "high"
        elif total_vulns > 5:
            return "medium"
        else:
            return "low"
    
    def _get_package_source_locations(self, pkg_id: str, results: VulnerabilityResults) -> List:
        """Get source locations for a package."""
        return results.source_locations.get(pkg_id, [])
    
    def _format_affected_files(self, source_locations: List[Dict]) -> List[str]:
        """Format affected files for AI agent reference."""
        return [
            f"{loc['file_path']}:{loc['line_number']}"
            for loc in source_locations
        ]
    
    def _generate_upgrade_path(self, package_name: str, current_version: str, target_version: str) -> Dict[str, str]:
        """Generate upgrade path information."""
        return {
            "current": current_version,
            "safe_minimum": target_version or "latest",
            "latest_stable": "unknown"  # Would need package registry lookup
        }
    
    def _detect_ecosystem(self, source_locations: List[Dict]) -> str:
        """Detect package ecosystem from source locations."""
        if not source_locations:
            return "unknown"
        
        file_type = source_locations[0].get('file_type', '')
        
        if file_type in ['requirements', 'pyproject_toml']:
            return "pypi"
        elif file_type in ['package_json', 'yarn_lock']:
            return "npm"
        else:
            return "unknown"
    
    def _assess_business_impact(self, cve) -> str:
        """Assess business impact of CVE."""
        if cve.severity.value == "CRITICAL":
            return "Immediate business risk"
        elif cve.severity.value == "HIGH":
            return "Significant business impact"
        elif cve.severity.value == "MEDIUM":
            return "Moderate business impact"
        else:
            return "Low business impact"
    
    def _assess_exploitability(self, cve) -> str:
        """Assess exploitability of CVE."""
        if cve.cvss_score and cve.cvss_score >= 9.0:
            return "Easily exploitable"
        elif cve.cvss_score and cve.cvss_score >= 7.0:
            return "Moderately exploitable"
        else:
            return "Low exploitability"
    
    def _determine_ai_urgency(self, cve) -> str:
        """Determine urgency level for AI agent prioritization."""
        if cve.severity.value == "CRITICAL":
            return "immediate"
        elif cve.severity.value == "HIGH":
            return "high"
        elif cve.severity.value == "MEDIUM":
            return "medium"
        else:
            return "low"
    
    def _determine_urgency_from_cves(self, cves) -> str:
        """Determine urgency from a list of CVEs."""
        if not cves:
            return "low"
        
        # Get highest severity
        severities = [cve.severity.value for cve in cves]
        if "CRITICAL" in severities:
            return "immediate"
        elif "HIGH" in severities:
            return "high"
        elif "MEDIUM" in severities:
            return "medium"
        else:
            return "low"
    
    def _assess_automation_feasibility(self, analysis) -> str:
        """Assess feasibility of automated remediation."""
        # Simplified assessment based on confidence
        if analysis.confidence >= 0.9:
            return "high"
        elif analysis.confidence >= 0.7:
            return "medium"
        else:
            return "low"
    
    def _assess_risk_if_not_fixed(self, analysis) -> str:
        """Assess risk if vulnerability is not fixed."""
        # Base on severity of CVEs
        max_severity = max((cve.cvss_score or 0 for cve in analysis.cves), default=0)
        if max_severity >= 8.0:
            return "high"
        elif max_severity >= 5.0:
            return "medium"
        else:
            return "low"
    
    def _calculate_risk_distribution(self, results: VulnerabilityResults) -> Dict[str, float]:
        """Calculate risk score distribution."""
        if not results.vulnerability_analysis:
            return {"low": 0, "medium": 0, "high": 0}
        
        # Calculate based on CVE severities
        severity_counts = {"low": 0, "medium": 0, "high": 0}
        
        for analysis in results.vulnerability_analysis.values():
            for cve in analysis.cves:
                score = cve.cvss_score or 0
                if score >= 7.0:
                    severity_counts["high"] += 1
                elif score >= 4.0:
                    severity_counts["medium"] += 1
                else:
                    severity_counts["low"] += 1
        
        total = sum(severity_counts.values())
        if total == 0:
            return {"low": 0, "medium": 0, "high": 0}
        
        return {
            k: v / total for k, v in severity_counts.items()
        }
    
    def _estimate_remediation_timeline(self, results: VulnerabilityResults) -> Dict[str, int]:
        """Estimate remediation timeline."""
        # Estimate based on CVE counts and severities
        immediate = sum(1 for analysis in results.vulnerability_analysis.values() 
                       for cve in analysis.cves if cve.severity.value == "CRITICAL")
        short_term = sum(1 for analysis in results.vulnerability_analysis.values() 
                        for cve in analysis.cves if cve.severity.value == "HIGH")
        long_term = sum(1 for analysis in results.vulnerability_analysis.values() 
                       for cve in analysis.cves if cve.severity.value in ["MEDIUM", "LOW"])
        
        return {
            "immediate_fixes": immediate,
            "short_term_fixes": short_term,
            "long_term_fixes": long_term,
            "estimated_days": immediate + (short_term * 3) + (long_term * 7)
        }
    
    def _count_immediate_actions(self, results: VulnerabilityResults) -> int:
        """Count vulnerabilities requiring immediate action."""
        return len([
            analysis for analysis in results.vulnerability_analysis.values()
            if any(cve.severity.value == "CRITICAL" for cve in analysis.cves)
        ])
    
    def _count_automation_candidates(self, results: VulnerabilityResults) -> int:
        """Count vulnerabilities suitable for automation."""
        return len([
            analysis for analysis in results.vulnerability_analysis.values()
            if (analysis.cves and analysis.confidence >= 0.9)
        ])
    
    def _prioritize_vulnerabilities(self, results: VulnerabilityResults) -> List[Dict[str, Any]]:
        """Prioritize vulnerabilities for AI agent action."""
        vulnerability_list = []
        
        for pkg_id, analysis in results.vulnerability_analysis.items():
            if analysis.cves:
                priority_score = self._calculate_priority_score(analysis)
                vulnerability_list.append({
                    "package_id": pkg_id,
                    "priority_score": priority_score,
                    "urgency": self._determine_urgency_from_cves(analysis.cves),
                    "confidence": analysis.confidence
                })
        
        # Sort by priority score (highest first)
        return sorted(vulnerability_list, key=lambda x: x["priority_score"], reverse=True)
    
    def _calculate_priority_score(self, analysis) -> float:
        """Calculate priority score for vulnerability."""
        # Combine severity, exploitability, and confidence
        severity_weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
        
        max_severity_score = 0
        for cve in analysis.cves:
            severity_score = severity_weights.get(cve.severity.value, 1)
            max_severity_score = max(max_severity_score, severity_score)
        
        # Factor in confidence
        priority_score = (
            max_severity_score * 
            analysis.confidence
        )
        
        return round(priority_score, 2)
    
    def _group_by_remediation_strategy(self, results: VulnerabilityResults) -> Dict[str, List[str]]:
        """Group vulnerabilities by remediation strategy."""
        strategies = {}
        
        # Group by severity instead of remediation action
        for pkg_id, analysis in results.vulnerability_analysis.items():
            if analysis.cves:
                max_severity = max(cve.severity.value for cve in analysis.cves)
                if max_severity not in strategies:
                    strategies[max_severity] = []
                strategies[max_severity].append(pkg_id)
        
        return strategies
    
    def _estimate_total_effort(self, results: VulnerabilityResults) -> Dict[str, Any]:
        """Estimate total remediation effort."""
        effort_hours = {"low": 1, "medium": 4, "high": 16}
        total_hours = 0
        effort_breakdown = {"low": 0, "medium": 0, "high": 0}
        
        # Estimate based on number of CVEs
        for analysis in results.vulnerability_analysis.values():
            if analysis.cves:
                # Estimate effort based on number and severity of CVEs
                for cve in analysis.cves:
                    if cve.severity.value == "CRITICAL":
                        effort = "high"
                    elif cve.severity.value == "HIGH":
                        effort = "medium"
                    else:
                        effort = "low"
                    total_hours += effort_hours[effort]
                    effort_breakdown[effort] += 1
        
        return {
            "total_estimated_hours": total_hours,
            "effort_breakdown": effort_breakdown,
            "parallel_execution_hours": max(effort_hours.values()) if effort_breakdown else 0
        }
    
    def _identify_parallel_opportunities(self, results: VulnerabilityResults) -> List[str]:
        """Identify opportunities for parallel remediation."""
        # Group by affected files to identify non-conflicting changes
        file_groups = {}
        
        for pkg_id, analysis in results.vulnerability_analysis.items():
            if analysis.cves:
                # Simplified - packages can be updated independently
                file_groups[pkg_id] = []
        
        return ["Upgrade batching possible", "Independent package updates"]
    
    def _detect_dependency_conflicts(self, results: VulnerabilityResults) -> List[str]:
        """Detect potential dependency conflicts."""
        # Simplified conflict detection
        # All vulnerable packages need upgrades
        upgrade_packages = [
            pkg_id for pkg_id, analysis in results.vulnerability_analysis.items()
            if analysis.cves
        ]
        
        if len(upgrade_packages) > 10:
            return ["High number of upgrades may cause compatibility issues"]
        
        return []
    
    def _assess_testing_requirements(self, results: VulnerabilityResults) -> Dict[str, Any]:
        """Assess testing requirements for remediations."""
        vulnerable_count = results.vulnerability_summary.vulnerable_packages
        
        return {
            "unit_tests_required": vulnerable_count > 0,
            "integration_tests_required": vulnerable_count > 5,
            "security_tests_required": any(
                any(cve.cvss_score and cve.cvss_score >= 7.0 for cve in analysis.cves)
                for analysis in results.vulnerability_analysis.values()
                if analysis.cves
            ),
            "estimated_test_effort_hours": min(vulnerable_count * 2, 20)
        }
    
    def _has_duplicate_dependencies(self, results: VulnerabilityResults) -> bool:
        """Check for duplicate dependencies."""
        # Simplified - would need to check for same package with different versions
        return False
    
    def _assess_data_completeness(self, results: VulnerabilityResults) -> float:
        """Assess completeness of vulnerability data."""
        if not results.vulnerability_analysis:
            return 1.0
        
        complete_analyses = sum(
            1 for analysis in results.vulnerability_analysis.values()
            if analysis.confidence >= 0.8
        )
        
        return complete_analyses / len(results.vulnerability_analysis)
    
    def _calculate_confidence_distribution(self, results: VulnerabilityResults) -> Dict[str, float]:
        """Calculate confidence score distribution."""
        if not results.vulnerability_analysis:
            return {"high": 0, "medium": 0, "low": 0}
        
        confidences = [
            analysis.confidence
            for analysis in results.vulnerability_analysis.values()
        ]
        
        total = len(confidences)
        return {
            "high": len([c for c in confidences if c >= 0.9]) / total,
            "medium": len([c for c in confidences if 0.7 <= c < 0.9]) / total,
            "low": len([c for c in confidences if c < 0.7]) / total
        }
    
    def _calculate_validation_coverage(self, results: VulnerabilityResults) -> float:
        """Calculate validation coverage percentage."""
        validation_info = results.scan_metadata.get('validation', {})
        total_findings = validation_info.get('total_findings', 0)
        validated_findings = validation_info.get('validated_findings', 0)
        
        if total_findings == 0:
            return 1.0
        
        return validated_findings / total_findings
    
    def _json_serializer(self, obj):
        """Custom JSON serializer for datetime and other objects."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif hasattr(obj, 'dict'):
            return obj.dict()
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        else:
            return str(obj)