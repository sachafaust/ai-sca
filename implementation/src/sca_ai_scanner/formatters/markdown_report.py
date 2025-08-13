"""
Human-readable markdown report formatter for vulnerability scan results.
Generates comprehensive reports optimized for human consumption and review.
"""

from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path

from ..core.models import VulnerabilityResults, Severity


class MarkdownReportFormatter:
    """
    Generates COMPLETE human-readable markdown reports from vulnerability scan results.
    
    CRITICAL: Reports include ALL vulnerabilities and ALL source locations - NO SAMPLING.
    Optimized for security teams, developers, and management review.
    """
    
    def __init__(self):
        """Initialize markdown report formatter."""
        self.severity_icons = {
            Severity.CRITICAL: "🚨",
            Severity.HIGH: "🔴", 
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "ℹ️"
        }
        
        self.severity_colors = {
            Severity.CRITICAL: "Critical",
            Severity.HIGH: "High",
            Severity.MEDIUM: "Medium", 
            Severity.LOW: "Low",
            Severity.INFO: "Info"
        }
    
    def generate_report(
        self, 
        results: VulnerabilityResults, 
        scan_duration: float,
        scan_config: Dict[str, Any],
        output_file: Path
    ) -> None:
        """Generate and save markdown report to file."""
        
        report_content = self._generate_report_content(results, scan_duration, scan_config)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
    
    def _generate_report_content(
        self, 
        results: VulnerabilityResults, 
        scan_duration: float,
        scan_config: Dict[str, Any]
    ) -> str:
        """Generate complete markdown report content."""
        
        report_sections = [
            self._generate_header(results, scan_duration, scan_config),
            self._generate_executive_summary(results),
            self._generate_vulnerability_breakdown(results),
            self._generate_detailed_findings(results),
            self._generate_package_inventory(results),
            self._generate_recommendations(results),
            self._generate_scan_metadata(results, scan_duration, scan_config)
        ]
        
        return '\n\n'.join(section for section in report_sections if section)
    
    def _generate_header(
        self, 
        results: VulnerabilityResults, 
        scan_duration: float,
        scan_config: Dict[str, Any]
    ) -> str:
        """Generate report header with scan overview."""
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return f"""# 🛡️ Security Vulnerability Report

**Generated:** {timestamp}  
**Scan Duration:** {scan_duration:.1f} seconds  
**AI Model:** {scan_config.get('model', 'Unknown')}  
**Packages Analyzed:** {results.vulnerability_summary.total_packages_analyzed:,}  
**Vulnerabilities Found:** {results.vulnerability_summary.vulnerable_packages:,}"""
    
    def _generate_executive_summary(self, results: VulnerabilityResults) -> str:
        """Generate executive summary section."""
        
        summary = results.vulnerability_summary
        severity_breakdown = summary.severity_breakdown
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(severity_breakdown)
        risk_level = self._get_risk_level(risk_score)
        
        return f"""## 📊 Executive Summary

**Overall Risk Level:** {risk_level}  
**Security Posture:** {self._get_security_posture(results)}  
**Analysis Model:** {results.scan_metadata.get('model', 'Unknown')}

### Vulnerability Overview
- **Total Packages Scanned:** {summary.total_packages_analyzed:,}
- **Vulnerable Packages:** {summary.vulnerable_packages:,}
- **Clean Packages:** {summary.total_packages_analyzed - summary.vulnerable_packages:,}
- **Security Coverage:** {((summary.total_packages_analyzed - summary.vulnerable_packages) / max(summary.total_packages_analyzed, 1) * 100):.1f}%

### Severity Breakdown
{self._format_severity_table(severity_breakdown)}"""
    
    def _generate_vulnerability_breakdown(self, results: VulnerabilityResults) -> str:
        """Generate detailed vulnerability breakdown."""
        
        if not results.vulnerability_analysis:
            return "## 🔍 Vulnerability Analysis\n\n✅ **No vulnerabilities found** - All packages appear to be secure."
        
        # Group by severity
        by_severity = {}
        for pkg_id, analysis in results.vulnerability_analysis.items():
            for cve in analysis.cves:
                severity = cve.severity
                if severity not in by_severity:
                    by_severity[severity] = []
                by_severity[severity].append((pkg_id, cve, analysis))
        
        sections = []
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            if severity in by_severity:
                sections.append(self._format_severity_section(severity, by_severity[severity]))
        
        return f"""## 🔍 Vulnerability Analysis

{chr(10).join(sections)}"""
    
    def _generate_detailed_findings(self, results: VulnerabilityResults) -> str:
        """Generate detailed findings with source location information."""
        
        if not results.vulnerability_analysis:
            return ""
        
        findings = []
        for pkg_id, analysis in results.vulnerability_analysis.items():
            if analysis.cves:
                findings.append(self._format_package_findings(pkg_id, analysis, results))
        
        if not findings:
            return ""
        
        return f"""## 📝 Detailed Findings

{chr(10).join(findings)}"""
    
    def _generate_package_inventory(self, results: VulnerabilityResults) -> str:
        """Generate package inventory section."""
        
        total_packages = results.vulnerability_summary.total_packages_analyzed
        vulnerable_packages = results.vulnerability_summary.vulnerable_packages
        clean_packages = total_packages - vulnerable_packages
        
        return f"""## 📦 Package Inventory

### Summary
- **Total Packages:** {total_packages:,}
- **Vulnerable:** {vulnerable_packages:,} ({(vulnerable_packages/max(total_packages,1)*100):.1f}%)
- **Clean:** {clean_packages:,} ({(clean_packages/max(total_packages,1)*100):.1f}%)

### Vulnerable Packages
{self._format_vulnerable_packages_list(results)}"""
    
    def _generate_recommendations(self, results: VulnerabilityResults) -> str:
        """Generate recommendations section."""
        
        recommendations = []
        
        # Security recommendations
        critical_count = results.vulnerability_summary.severity_breakdown.get('critical', 0)
        high_count = results.vulnerability_summary.severity_breakdown.get('high', 0)
        
        if critical_count > 0:
            recommendations.append(f"🚨 **Immediate Action Required:** {critical_count} critical vulnerabilities need urgent remediation")
        
        if high_count > 0:
            recommendations.append(f"🔴 **High Priority:** {high_count} high severity vulnerabilities should be addressed soon")
        
        # General recommendations
        recommendations.extend([
            "🔄 **Regular Scanning:** Run vulnerability scans weekly or after dependency updates",
            "📋 **Dependency Management:** Keep dependencies up to date and review new additions",
            "🔒 **Security Policy:** Establish clear policies for vulnerability response and remediation",
            "📊 **Monitoring:** Track vulnerability trends and remediation progress over time"
        ])
        
        return f"""## 💡 Recommendations

{chr(10).join(f"- {rec}" for rec in recommendations)}

### Next Steps
1. **Prioritize** critical and high severity vulnerabilities
2. **Plan** remediation efforts based on business impact
3. **Test** fixes in development environment before production
4. **Monitor** for new vulnerabilities in existing dependencies
5. **Document** remediation actions for audit trail"""
    
    def _generate_scan_metadata(
        self, 
        results: VulnerabilityResults, 
        scan_duration: float,
        scan_config: Dict[str, Any]
    ) -> str:
        """Generate scan metadata section."""
        
        return f"""## 🔧 Scan Details

### Configuration
- **AI Model:** {scan_config.get('model', 'Unknown')}
- **Live Search:** {'Enabled' if scan_config.get('enable_live_search', False) else 'Disabled'}
- **Scan Duration:** {scan_duration:.1f} seconds
- **Packages/Second:** {results.vulnerability_summary.total_packages_analyzed / max(scan_duration, 1):.1f}

### Scan Metadata
- **Session ID:** {results.scan_metadata.get('session_id', 'Unknown')}
- **Timestamp:** {datetime.now().isoformat()}
- **Scanner Version:** AI-Powered SCA Scanner

---
*Report generated by AI-Powered SCA Scanner - For internal security review only*"""
    
    def _format_severity_table(self, severity_breakdown: Dict[str, int]) -> str:
        """Format severity breakdown as a table."""
        
        rows = []
        for severity in ['critical', 'high', 'medium', 'low']:
            count = severity_breakdown.get(severity, 0)
            if count > 0:
                icon = self.severity_icons.get(getattr(Severity, severity.upper()), "•")
                rows.append(f"| {icon} {severity.title()} | {count:,} |")
        
        if not rows:
            return "| Severity | Count |\n|----------|-------|\n| ✅ Clean | All packages |"
        
        return "| Severity | Count |\n|----------|-------|\n" + "\n".join(rows)
    
    def _format_severity_section(self, severity: Severity, findings: List) -> str:
        """Format a section for a specific severity level."""
        
        icon = self.severity_icons[severity]
        color = self.severity_colors[severity]
        
        findings_list = []
        for pkg_id, cve, analysis in findings:
            package_name, version = self._parse_package_id(pkg_id)
            cvss_info = f" (CVSS: {cve.cvss_score})" if cve.cvss_score else ""
            findings_list.append(f"  - **{package_name} {version}**: {cve.id} - {cve.description}{cvss_info}")
        
        return f"""### {icon} {color} Severity ({len(findings)} findings)

{chr(10).join(findings_list)}"""
    
    def _format_package_findings(self, pkg_id: str, analysis, results) -> str:
        """Format detailed findings for a specific package."""
        
        package_name, version = self._parse_package_id(pkg_id)
        
        # Format CVEs
        cve_list = []
        for cve in analysis.cves:
            icon = self.severity_icons[cve.severity]
            cvss_info = f" (CVSS: {cve.cvss_score})" if cve.cvss_score else ""
            cve_list.append(f"  - {icon} **{cve.id}** ({cve.severity.value}){cvss_info}: {cve.description}")
        
        # Format source locations
        source_info = ""
        source_locations = results.source_locations.get(pkg_id, [])
        if source_locations:
            source_info = "\n\n**Source Locations:**\n"
            for location in source_locations:
                source_info += f"  - `{location.file_path}:{location.line_number}` - {location.declaration}\n"
        
        return f"""### {package_name} {version}

**Confidence:** {analysis.confidence:.1f}/1.0  
**CVEs Found:** {len(analysis.cves)}

{chr(10).join(cve_list)}
{source_info}"""
    
    def _format_vulnerable_packages_list(self, results: VulnerabilityResults) -> str:
        """Format list of vulnerable packages."""
        
        if not results.vulnerability_analysis:
            return "*No vulnerable packages found.*"
        
        packages = []
        for pkg_id, analysis in results.vulnerability_analysis.items():
            package_name, version = self._parse_package_id(pkg_id)
            cve_count = len(analysis.cves)
            highest_severity = max((cve.severity for cve in analysis.cves), default=Severity.LOW)
            icon = self.severity_icons[highest_severity]
            packages.append(f"- {icon} **{package_name} {version}** ({cve_count} CVE{'s' if cve_count != 1 else ''})")
        
        return "\n".join(packages)
    
    def _parse_package_id(self, pkg_id: str) -> tuple:
        """Parse package ID into name and version."""
        if ':' in pkg_id:
            return pkg_id.split(':', 1)
        elif '==' in pkg_id:
            return pkg_id.split('==', 1)
        else:
            return pkg_id, 'unknown'
    
    def _calculate_risk_score(self, severity_breakdown: Dict[str, int]) -> float:
        """Calculate overall risk score based on severity breakdown."""
        weights = {'critical': 10, 'high': 5, 'medium': 2, 'low': 1}
        total_score = sum(severity_breakdown.get(severity, 0) * weight 
                         for severity, weight in weights.items())
        return min(total_score / 10, 10.0)  # Normalize to 0-10 scale
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Get risk level description from risk score."""
        if risk_score >= 8:
            return "🚨 **CRITICAL RISK**"
        elif risk_score >= 5:
            return "🔴 **HIGH RISK**" 
        elif risk_score >= 2:
            return "🟡 **MEDIUM RISK**"
        elif risk_score > 0:
            return "🔵 **LOW RISK**"
        else:
            return "✅ **MINIMAL RISK**"
    
    def _get_security_posture(self, results: VulnerabilityResults) -> str:
        """Get overall security posture assessment."""
        total = results.vulnerability_summary.total_packages_analyzed
        vulnerable = results.vulnerability_summary.vulnerable_packages
        
        if vulnerable == 0:
            return "Excellent - No vulnerabilities detected"
        
        percentage = (vulnerable / max(total, 1)) * 100
        
        if percentage <= 5:
            return "Good - Low vulnerability rate"
        elif percentage <= 15:
            return "Fair - Moderate vulnerability rate" 
        else:
            return "Needs Attention - High vulnerability rate"