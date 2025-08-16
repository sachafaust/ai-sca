"""
DSPy ChainOfThought Remediation Pipeline.
Multi-stage reasoning for vulnerability remediation recommendations.
"""

import dspy
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import json
import logging
from functools import lru_cache

from ..core.models import Package, CVEFinding, Severity

logger = logging.getLogger(__name__)


class RiskAssessmentSignature(dspy.Signature):
    """Signature for risk assessment stage."""
    
    # Inputs
    package_name = dspy.InputField(desc="Package name")
    current_version = dspy.InputField(desc="Current package version")
    cve_list = dspy.InputField(desc="List of CVE IDs affecting the package")
    severity_scores = dspy.InputField(desc="CVSS scores for each CVE")
    
    # Outputs
    risk_score = dspy.OutputField(desc="Overall risk score (0-10)", type=float)
    business_impact = dspy.OutputField(desc="Business impact level (LOW/MEDIUM/HIGH/CRITICAL)")
    exploitability = dspy.OutputField(desc="Exploitability assessment (LOW/MEDIUM/HIGH)")
    urgency_level = dspy.OutputField(desc="Remediation urgency (LOW/MEDIUM/HIGH/CRITICAL)")
    
    def validate(self, data: Dict[str, Any]) -> None:
        """Validate risk assessment data."""
        if 'risk_score' in data:
            score = data['risk_score']
            if not isinstance(score, (int, float)) or score < 0 or score > 10:
                raise ValueError(f"Risk score must be 0-10, got {score}")


class VersionAnalysisSignature(dspy.Signature):
    """Signature for version analysis stage."""
    
    # Inputs
    package_name = dspy.InputField(desc="Package name")
    current_version = dspy.InputField(desc="Current package version")
    available_versions = dspy.InputField(desc="List of available package versions")
    cve_fixed_versions = dspy.InputField(desc="Versions that fix the CVEs")
    
    # Outputs
    recommended_version = dspy.OutputField(desc="Recommended target version")
    version_jump_type = dspy.OutputField(desc="Type of version jump (PATCH/MINOR/MAJOR)")
    alternatives = dspy.OutputField(desc="Alternative version options")
    analysis_reasoning = dspy.OutputField(desc="Reasoning for version recommendation")


class BreakingChangeSignature(dspy.Signature):
    """Signature for breaking change detection."""
    
    # Inputs
    package_name = dspy.InputField(desc="Package name")
    current_version = dspy.InputField(desc="Current package version")
    target_version = dspy.InputField(desc="Target package version")
    ecosystem = dspy.InputField(desc="Package ecosystem")
    
    # Outputs
    has_breaking_changes = dspy.OutputField(desc="Whether breaking changes exist", type=bool)
    breaking_change_list = dspy.OutputField(desc="List of breaking changes")
    migration_effort = dspy.OutputField(desc="Migration effort level (LOW/MEDIUM/HIGH)")
    compatibility_notes = dspy.OutputField(desc="Compatibility and migration notes")


class RemediationSignature(dspy.Signature):
    """Final remediation recommendation signature."""
    
    # Inputs from previous stages
    risk_assessment = dspy.InputField(desc="Risk assessment results")
    version_analysis = dspy.InputField(desc="Version analysis results")
    breaking_changes = dspy.InputField(desc="Breaking change analysis")
    strategy = dspy.InputField(desc="Remediation strategy to apply")
    
    # Final outputs
    action = dspy.OutputField(desc="Recommended action (UPGRADE/PATCH/DEFER/MONITOR)")
    target_version = dspy.OutputField(desc="Target version for upgrade/patch")
    urgency = dspy.OutputField(desc="Action urgency (IMMEDIATE/HIGH/MEDIUM/LOW)")
    estimated_effort = dspy.OutputField(desc="Estimated implementation effort")
    confidence = dspy.OutputField(desc="Recommendation confidence (0-1)", type=float)


class ChainOfThoughtRemediation(dspy.Module):
    """Multi-stage chain of thought reasoning for remediation."""
    
    def __init__(self):
        """Initialize chain of thought remediation module."""
        super().__init__()
        
        # Initialize stage modules
        self.risk_assessor = dspy.ChainOfThought(RiskAssessmentSignature)
        self.version_analyzer = dspy.ChainOfThought(VersionAnalysisSignature)
        self.breaking_change_detector = dspy.ChainOfThought(BreakingChangeSignature)
        self.final_recommender = dspy.ChainOfThought(RemediationSignature)
    
    def forward(
        self,
        package_name: str,
        current_version: str,
        cve_list: List[str],
        severity_scores: List[float],
        available_versions: Optional[List[str]] = None,
        strategy: str = "balanced_security"
    ) -> dspy.Prediction:
        """Execute the complete remediation pipeline.
        
        Args:
            package_name: Name of the package
            current_version: Current version
            cve_list: List of CVE IDs
            severity_scores: CVSS scores
            available_versions: Available package versions
            strategy: Remediation strategy
            
        Returns:
            Final remediation recommendation
        """
        # Stage 1: Risk Assessment
        risk_result = self.risk_assessor(
            package_name=package_name,
            current_version=current_version,
            cve_list=json.dumps(cve_list),
            severity_scores=json.dumps(severity_scores)
        )
        
        # Stage 2: Version Analysis
        if available_versions is None:
            available_versions = self._infer_available_versions(package_name, current_version)
        
        version_result = self.version_analyzer(
            package_name=package_name,
            current_version=current_version,
            available_versions=json.dumps(available_versions),
            cve_fixed_versions=json.dumps([])  # Would be populated from CVE data
        )
        
        # Stage 3: Breaking Change Detection
        target_version = version_result.recommended_version
        breaking_result = self.breaking_change_detector(
            package_name=package_name,
            current_version=current_version,
            target_version=target_version,
            ecosystem=self._detect_ecosystem(package_name)
        )
        
        # Stage 4: Final Recommendation
        final_result = self.final_recommender(
            risk_assessment=json.dumps({
                'risk_score': risk_result.risk_score,
                'business_impact': risk_result.business_impact,
                'urgency_level': risk_result.urgency_level
            }),
            version_analysis=json.dumps({
                'recommended_version': version_result.recommended_version,
                'version_jump_type': version_result.version_jump_type,
                'alternatives': version_result.alternatives
            }),
            breaking_changes=json.dumps({
                'has_breaking_changes': breaking_result.has_breaking_changes,
                'migration_effort': breaking_result.migration_effort
            }),
            strategy=strategy
        )
        
        return final_result
    
    def _infer_available_versions(self, package_name: str, current_version: str) -> List[str]:
        """Infer available versions based on current version."""
        # Simplified version inference
        parts = current_version.split('.')
        if len(parts) >= 3:
            major, minor, patch = parts[0], parts[1], parts[2].split('-')[0]
            return [
                f"{major}.{minor}.{int(patch)+1}",  # Patch update
                f"{major}.{int(minor)+1}.0",        # Minor update
                f"{int(major)+1}.0.0"                # Major update
            ]
        return [current_version]
    
    def _detect_ecosystem(self, package_name: str) -> str:
        """Detect package ecosystem from name patterns."""
        # Simple heuristic - would be more sophisticated in practice
        if '@' in package_name:
            return 'npm'
        elif package_name.lower() in ['django', 'flask', 'requests', 'numpy']:
            return 'pypi'
        return 'unknown'


class RemediationPipeline:
    """Complete remediation pipeline with caching and strategy management."""
    
    def __init__(self):
        """Initialize remediation pipeline."""
        self.chain_of_thought = ChainOfThoughtRemediation()
        self.strategy_selector = StrategySelector()
        self.cache = {}
    
    def generate_recommendation(
        self,
        package: Package,
        vulnerabilities: List[CVEFinding],
        strategy: str = "balanced_security"
    ) -> Dict[str, Any]:
        """Generate remediation recommendation for a package.
        
        Args:
            package: Package with vulnerabilities
            vulnerabilities: List of CVE findings
            strategy: Remediation strategy
            
        Returns:
            Remediation recommendation
        """
        # Create cache key
        cache_key = f"{package.name}:{package.version}:{strategy}:{len(vulnerabilities)}"
        
        # Check cache
        if cache_key in self.cache:
            logger.debug(f"Using cached recommendation for {package.name}")
            return self.cache[cache_key]
        
        # Extract CVE data
        cve_list = [v.id for v in vulnerabilities]
        severity_scores = [v.cvss_score or 5.0 for v in vulnerabilities]
        
        # Adjust strategy based on context
        adjusted_strategy = self.strategy_selector.select(
            package=package,
            vulnerabilities=vulnerabilities,
            base_strategy=strategy
        )
        
        # Run chain of thought
        try:
            result = self.chain_of_thought.forward(
                package_name=package.name,
                current_version=package.version,
                cve_list=cve_list,
                severity_scores=severity_scores,
                strategy=adjusted_strategy
            )
            
            recommendation = self._parse_result(result)
            
            # Cache result
            self.cache[cache_key] = recommendation
            
            return recommendation
            
        except Exception as e:
            logger.error(f"Failed to generate recommendation for {package.name}: {e}")
            return self._fallback_recommendation(package, vulnerabilities)
    
    def batch_process(
        self,
        packages_with_vulns: List[Dict[str, Any]],
        strategy: str = "balanced_security"
    ) -> List[Dict[str, Any]]:
        """Process multiple packages in batch.
        
        Args:
            packages_with_vulns: List of packages with their vulnerabilities
            strategy: Remediation strategy
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        for item in packages_with_vulns:
            package = item['package']
            vulnerabilities = item['vulnerabilities']
            
            rec = self.generate_recommendation(
                package=package,
                vulnerabilities=vulnerabilities,
                strategy=strategy
            )
            
            recommendations.append({
                'package': f"{package.name}:{package.version}",
                'recommendation': rec
            })
        
        return recommendations
    
    def _parse_result(self, result) -> Dict[str, Any]:
        """Parse chain of thought result."""
        return {
            'action': getattr(result, 'action', 'MONITOR'),
            'target_version': getattr(result, 'target_version', None),
            'urgency': getattr(result, 'urgency', 'MEDIUM'),
            'estimated_effort': getattr(result, 'estimated_effort', 'UNKNOWN'),
            'confidence': getattr(result, 'confidence', 0.5)
        }
    
    def _fallback_recommendation(
        self,
        package: Package,
        vulnerabilities: List[CVEFinding]
    ) -> Dict[str, Any]:
        """Fallback recommendation when chain of thought fails."""
        max_severity = max(
            (v.severity for v in vulnerabilities),
            default=Severity.LOW
        )
        
        if max_severity in [Severity.CRITICAL, Severity.HIGH]:
            return {
                'action': 'UPGRADE',
                'target_version': 'latest',
                'urgency': 'HIGH',
                'estimated_effort': 'UNKNOWN',
                'confidence': 0.3
            }
        
        return {
            'action': 'MONITOR',
            'target_version': None,
            'urgency': 'LOW',
            'estimated_effort': 'NONE',
            'confidence': 0.3
        }


class StrategySelector:
    """Select and adjust remediation strategies based on context."""
    
    def __init__(self):
        """Initialize strategy selector."""
        self.strategies = {
            'balanced_security': self._balanced_strategy,
            'conservative_stability': self._conservative_strategy,
            'aggressive_security': self._aggressive_strategy,
            'rapid_development': self._rapid_strategy
        }
    
    def select(
        self,
        package: Package,
        vulnerabilities: List[CVEFinding],
        base_strategy: str
    ) -> str:
        """Select appropriate strategy based on context.
        
        Args:
            package: Package being analyzed
            vulnerabilities: List of vulnerabilities
            base_strategy: Base strategy name
            
        Returns:
            Adjusted strategy name
        """
        # Get strategy function
        strategy_fn = self.strategies.get(base_strategy, self._balanced_strategy)
        
        # Apply strategy logic
        return strategy_fn(package, vulnerabilities)
    
    def _balanced_strategy(self, package: Package, vulns: List[CVEFinding]) -> str:
        """Balanced security strategy."""
        critical_count = sum(1 for v in vulns if v.severity == Severity.CRITICAL)
        
        if critical_count > 0:
            return 'aggressive'
        elif len(vulns) > 5:
            return 'balanced'
        else:
            return 'conservative'
    
    def _conservative_strategy(self, package: Package, vulns: List[CVEFinding]) -> str:
        """Conservative stability-focused strategy."""
        return 'conservative'
    
    def _aggressive_strategy(self, package: Package, vulns: List[CVEFinding]) -> str:
        """Aggressive security-focused strategy."""
        return 'aggressive'
    
    def _rapid_strategy(self, package: Package, vulns: List[CVEFinding]) -> str:
        """Rapid development strategy."""
        if any(v.severity == Severity.CRITICAL for v in vulns):
            return 'balanced'
        return 'rapid'