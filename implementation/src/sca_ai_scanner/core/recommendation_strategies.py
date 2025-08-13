"""
Config-driven recommendation strategy system for contextual vulnerability remediation.

This implements the breakthrough insight from our research: instead of one-size-fits-all
recommendations, provide contextual options based on organizational priorities and constraints.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Union, Any, Tuple
from pydantic import BaseModel, Field, validator
import yaml
from pathlib import Path
import pkg_resources
import os
import logging

from .models import CVEFinding, Severity

logger = logging.getLogger(__name__)


class RecommendationAction(str, Enum):
    """Available remediation actions."""
    UPGRADE = "upgrade"
    PATCH = "patch"
    MITIGATE = "mitigate"
    NO_ACTION = "no_action"
    INVESTIGATE = "investigate"
    DEFER = "defer"


class Priority(str, Enum):
    """Recommendation priority levels."""
    IMMEDIATE = "immediate"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    DEFERRED = "deferred"


class EffortLevel(str, Enum):
    """Effort estimation levels."""
    TRIVIAL = "trivial"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    COMPLEX = "complex"
    
    @property
    def numeric_value(self) -> float:
        """Get numeric value for calculations."""
        mapping = {
            "trivial": 1.0,
            "low": 2.0,
            "medium": 3.0,
            "high": 4.0,
            "complex": 5.0
        }
        return mapping.get(self.value, 3.0)


class VersionJumpConstraint(str, Enum):
    """Maximum allowed version jump."""
    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"
    ANY = "any"


class SeverityPriority(BaseModel):
    """Severity-based priority mapping."""
    critical: Priority = Priority.IMMEDIATE
    high: Priority = Priority.HIGH
    medium: Priority = Priority.MEDIUM
    low: Priority = Priority.LOW


class UpgradeConstraints(BaseModel):
    """Version upgrade constraints."""
    max_version_jump: VersionJumpConstraint = VersionJumpConstraint.MINOR
    allow_breaking_changes: bool = False
    max_effort_level: EffortLevel = EffortLevel.MEDIUM
    prefer_stable_releases: bool = True


class RecommendationStrategy(BaseModel):
    """Complete recommendation strategy configuration."""
    name: str = Field(..., description="Strategy name")
    description: str = Field(..., description="Strategy description")
    severity_priorities: SeverityPriority = Field(default_factory=SeverityPriority)
    upgrade_constraints: UpgradeConstraints = Field(default_factory=UpgradeConstraints)
    
    # Advanced configuration
    minimum_fix_threshold: Optional[Severity] = Field(
        default=None,
        description="Only recommend fixes for this severity and above"
    )
    batch_upgrades_preferred: bool = Field(
        default=False,
        description="Prefer batching multiple upgrades together"
    )
    zero_downtime_required: bool = Field(
        default=False,
        description="Require zero-downtime deployment strategies"
    )
    compliance_mode: bool = Field(
        default=False,
        description="Enable compliance-focused recommendations"
    )
    
    @validator('name')
    def validate_name(cls, v):
        if not v or not v.strip():
            raise ValueError("Strategy name cannot be empty")
        return v.strip()


class RecommendationOption(BaseModel):
    """Individual recommendation option with trade-off analysis."""
    strategy_name: str = Field(..., description="Strategy that generated this option")
    action: RecommendationAction = Field(..., description="Recommended action")
    priority: Priority = Field(..., description="Recommendation priority")
    target_version: Optional[str] = Field(None, description="Target version for upgrade")
    effort_estimate: EffortLevel = Field(..., description="Estimated implementation effort")
    
    # Impact analysis
    fixes_cves: List[str] = Field(default_factory=list, description="CVE IDs this option fixes")
    remaining_risk: str = Field(..., description="Risk level after applying this option")
    breaking_changes: str = Field(..., description="Expected breaking changes")
    
    # Business considerations
    recommendation_text: str = Field(..., description="Human-readable recommendation")
    business_justification: str = Field(..., description="Business case for this option")
    implementation_notes: List[str] = Field(default_factory=list, description="Implementation guidance")
    
    # Scoring for comparison
    security_improvement: float = Field(..., description="Security improvement score (0-10)")
    stability_risk: float = Field(..., description="Stability risk score (0-10)")
    effort_cost: float = Field(..., description="Implementation effort score (0-10)")


class PackageRecommendations(BaseModel):
    """Complete recommendation analysis for a package."""
    package_name: str = Field(..., description="Package name")
    current_version: str = Field(..., description="Current version")
    current_risk_level: str = Field(..., description="Current risk assessment")
    total_cves: int = Field(..., description="Total CVEs affecting this package")
    
    # Multiple recommendation options
    recommendation_options: List[RecommendationOption] = Field(
        default_factory=list,
        description="All available recommendation options"
    )
    
    # AI agent guidance
    default_choice: Optional[str] = Field(
        None,
        description="Default recommendation based on strategy"
    )
    reasoning: str = Field(..., description="Reasoning for default choice")
    confidence: float = Field(..., description="Confidence in recommendations (0-1)")


class RecommendationEngine:
    """Core engine for generating contextual recommendations."""
    
    def __init__(self, strategy: RecommendationStrategy):
        """Initialize with a specific strategy."""
        self.strategy = strategy
    
    def analyze_package(
        self, 
        package_name: str, 
        current_version: str, 
        cves: List[CVEFinding],
        available_versions: Optional[List[str]] = None
    ) -> PackageRecommendations:
        """Generate comprehensive recommendations for a package."""
        
        if not cves:
            return self._create_no_action_recommendation(package_name, current_version)
        
        # Analyze current risk
        current_risk = self._assess_current_risk(cves)
        
        # Generate multiple recommendation options
        options = self._generate_recommendation_options(
            package_name, current_version, cves, available_versions or []
        )
        
        # Select default based on strategy
        default_choice, reasoning = self._select_default_recommendation(options)
        
        return PackageRecommendations(
            package_name=package_name,
            current_version=current_version,
            current_risk_level=current_risk,
            total_cves=len(cves),
            recommendation_options=options,
            default_choice=default_choice,
            reasoning=reasoning,
            confidence=self._calculate_confidence(cves, options)
        )
    
    def _create_no_action_recommendation(
        self, package_name: str, current_version: str
    ) -> PackageRecommendations:
        """Create recommendation for packages with no vulnerabilities."""
        
        no_action_option = RecommendationOption(
            strategy_name=self.strategy.name,
            action=RecommendationAction.NO_ACTION,
            priority=Priority.LOW,
            target_version=None,
            effort_estimate=EffortLevel.TRIVIAL,
            fixes_cves=[],
            remaining_risk="none",
            breaking_changes="none",
            recommendation_text="No action required - package appears secure",
            business_justification="No known vulnerabilities in current version",
            security_improvement=0.0,
            stability_risk=0.0,
            effort_cost=0.0
        )
        
        return PackageRecommendations(
            package_name=package_name,
            current_version=current_version,
            current_risk_level="none",
            total_cves=0,
            recommendation_options=[no_action_option],
            default_choice="no_action",
            reasoning="No vulnerabilities detected in current version",
            confidence=0.95
        )
    
    def _assess_current_risk(self, cves: List[CVEFinding]) -> str:
        """Assess current risk level based on CVEs."""
        
        if any(cve.severity == Severity.CRITICAL for cve in cves):
            return "critical"
        elif any(cve.severity == Severity.HIGH for cve in cves):
            return "high"
        elif any(cve.severity == Severity.MEDIUM for cve in cves):
            return "medium"
        else:
            return "low"
    
    def _generate_recommendation_options(
        self,
        package_name: str,
        current_version: str,
        cves: List[CVEFinding],
        available_versions: List[str]
    ) -> List[RecommendationOption]:
        """Generate multiple recommendation options with different trade-offs."""
        
        options = []
        
        # Option 1: Minimal safe upgrade (patch/minor only)
        minimal_option = self._create_minimal_upgrade_option(
            package_name, current_version, cves, available_versions
        )
        if minimal_option:
            options.append(minimal_option)
        
        # Option 2: Comprehensive upgrade (latest stable)
        comprehensive_option = self._create_comprehensive_upgrade_option(
            package_name, current_version, cves, available_versions
        )
        if comprehensive_option:
            options.append(comprehensive_option)
        
        # Option 3: Mitigation-only (if upgrades constrained)
        if self.strategy.upgrade_constraints.max_effort_level in [EffortLevel.TRIVIAL, EffortLevel.LOW]:
            mitigation_option = self._create_mitigation_option(
                package_name, current_version, cves
            )
            if mitigation_option:
                options.append(mitigation_option)
        
        # Option 4: Investigate for complex cases
        if len(cves) > 5 or any(cve.severity == Severity.CRITICAL for cve in cves):
            investigate_option = self._create_investigation_option(
                package_name, current_version, cves
            )
            options.append(investigate_option)
        
        return options
    
    def _create_minimal_upgrade_option(
        self,
        package_name: str,
        current_version: str,
        cves: List[CVEFinding],
        available_versions: List[str]
    ) -> Optional[RecommendationOption]:
        """Create minimal upgrade option respecting constraints."""
        
        # Filter CVEs by strategy minimum threshold
        relevant_cves = self._filter_cves_by_threshold(cves)
        if not relevant_cves:
            return None
        
        # Find minimal version that fixes critical/high issues
        target_version = self._find_minimal_safe_version(
            current_version, relevant_cves, available_versions
        )
        
        if not target_version:
            return None
        
        critical_high_cves = [
            cve for cve in relevant_cves 
            if cve.severity in [Severity.CRITICAL, Severity.HIGH]
        ]
        
        remaining_cves = [
            cve for cve in cves 
            if cve not in critical_high_cves
        ]
        
        return RecommendationOption(
            strategy_name=self.strategy.name,
            action=RecommendationAction.UPGRADE,
            priority=self._map_severity_to_priority(
                max(cve.severity for cve in critical_high_cves) if critical_high_cves else Severity.MEDIUM
            ),
            target_version=target_version,
            effort_estimate=EffortLevel.LOW,
            fixes_cves=[cve.id for cve in critical_high_cves],
            remaining_risk=self._assess_current_risk(remaining_cves) if remaining_cves else "none",
            breaking_changes="minimal" if target_version != current_version else "none",
            recommendation_text=f"Quick security win with minimal effort - upgrade to {target_version}",
            business_justification=f"Fixes {len(critical_high_cves)} critical/high severity issues with low risk",
            security_improvement=7.0 if critical_high_cves else 4.0,
            stability_risk=2.0,
            effort_cost=3.0
        )
    
    def _create_comprehensive_upgrade_option(
        self,
        package_name: str,
        current_version: str,
        cves: List[CVEFinding],
        available_versions: List[str]
    ) -> Optional[RecommendationOption]:
        """Create comprehensive upgrade option to latest stable."""
        
        if not available_versions:
            return None
        
        latest_version = available_versions[-1]  # Assume sorted
        
        # Check if this would violate constraints
        effort = self._estimate_upgrade_effort(current_version, latest_version)
        if effort.numeric_value > self.strategy.upgrade_constraints.max_effort_level.numeric_value:
            return None
        
        return RecommendationOption(
            strategy_name=self.strategy.name,
            action=RecommendationAction.UPGRADE,
            priority=Priority.HIGH,
            target_version=latest_version,
            effort_estimate=effort,
            fixes_cves=[cve.id for cve in cves],
            remaining_risk="none",
            breaking_changes="moderate" if effort in [EffortLevel.MEDIUM, EffortLevel.HIGH] else "minimal",
            recommendation_text=f"Complete security resolution - upgrade to {latest_version}",
            business_justification=f"Resolves all {len(cves)} known vulnerabilities, future-proofs security",
            security_improvement=10.0,
            stability_risk=5.0,
            effort_cost=effort.numeric_value * 2.0
        )
    
    def _create_mitigation_option(
        self,
        package_name: str,
        current_version: str,
        cves: List[CVEFinding]
    ) -> Optional[RecommendationOption]:
        """Create mitigation-only option."""
        
        high_severity_cves = [
            cve for cve in cves 
            if cve.severity in [Severity.CRITICAL, Severity.HIGH]
        ]
        
        if not high_severity_cves:
            return None
        
        return RecommendationOption(
            strategy_name=self.strategy.name,
            action=RecommendationAction.MITIGATE,
            priority=Priority.HIGH,
            target_version=None,
            effort_estimate=EffortLevel.MEDIUM,
            fixes_cves=[],
            remaining_risk="mitigated",
            breaking_changes="none",
            recommendation_text="Implement security controls without version changes",
            business_justification="Addresses security risks while maintaining current version stability",
            implementation_notes=[
                "Configure firewall rules to limit exposure",
                "Implement input validation at application level",
                "Monitor for exploitation attempts",
                "Plan upgrade path for future maintenance window"
            ],
            security_improvement=6.0,
            stability_risk=1.0,
            effort_cost=4.0
        )
    
    def _create_investigation_option(
        self,
        package_name: str,
        current_version: str,
        cves: List[CVEFinding]
    ) -> RecommendationOption:
        """Create investigation option for complex cases."""
        
        return RecommendationOption(
            strategy_name=self.strategy.name,
            action=RecommendationAction.INVESTIGATE,
            priority=Priority.MEDIUM,
            target_version=None,
            effort_estimate=EffortLevel.LOW,
            fixes_cves=[],
            remaining_risk="under_investigation",
            breaking_changes="to_be_determined",
            recommendation_text="Detailed analysis required before remediation",
            business_justification=f"Complex vulnerability profile ({len(cves)} CVEs) requires expert review",
            implementation_notes=[
                "Review each CVE for actual applicability to your use case",
                "Assess business criticality of affected functionality",
                "Evaluate upgrade path complexity and testing requirements",
                "Consider phased remediation approach"
            ],
            security_improvement=0.0,
            stability_risk=0.0,
            effort_cost=2.0
        )
    
    def _filter_cves_by_threshold(self, cves: List[CVEFinding]) -> List[CVEFinding]:
        """Filter CVEs based on strategy minimum threshold."""
        
        if not self.strategy.minimum_fix_threshold:
            return cves
        
        threshold_order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0
        }
        
        min_level = threshold_order[self.strategy.minimum_fix_threshold]
        
        return [
            cve for cve in cves 
            if threshold_order.get(cve.severity, 0) >= min_level
        ]
    
    def _find_minimal_safe_version(
        self,
        current_version: str,
        cves: List[CVEFinding],
        available_versions: List[str]
    ) -> Optional[str]:
        """Find minimal version that addresses high-severity CVEs."""
        # Simplified implementation - in practice would check CVE fix versions
        # For now, return next minor version if available
        if available_versions:
            return available_versions[0]  # Simplified
        return None
    
    def _estimate_upgrade_effort(self, current_version: str, target_version: str) -> EffortLevel:
        """Estimate effort required for version upgrade."""
        # Simplified implementation - in practice would analyze version diff
        if current_version == target_version:
            return EffortLevel.TRIVIAL
        return EffortLevel.MEDIUM  # Simplified
    
    def _map_severity_to_priority(self, severity: Severity) -> Priority:
        """Map CVE severity to recommendation priority using strategy."""
        
        mapping = {
            Severity.CRITICAL: self.strategy.severity_priorities.critical,
            Severity.HIGH: self.strategy.severity_priorities.high,
            Severity.MEDIUM: self.strategy.severity_priorities.medium,
            Severity.LOW: self.strategy.severity_priorities.low,
            Severity.INFO: Priority.LOW
        }
        
        return mapping.get(severity, Priority.MEDIUM)
    
    def _select_default_recommendation(
        self, options: List[RecommendationOption]
    ) -> Tuple[Optional[str], str]:
        """Select default recommendation based on strategy."""
        
        if not options:
            return None, "No viable recommendations available"
        
        # Score each option based on strategy preferences
        scored_options = []
        for option in options:
            score = self._score_option(option)
            scored_options.append((score, option))
        
        # Sort by score (higher is better)
        scored_options.sort(key=lambda x: x[0], reverse=True)
        best_option = scored_options[0][1]
        
        reasoning = self._generate_reasoning(best_option, scored_options)
        
        return best_option.action.value, reasoning
    
    def _score_option(self, option: RecommendationOption) -> float:
        """Score a recommendation option based on strategy preferences."""
        
        score = 0.0
        
        # Security improvement weight
        score += option.security_improvement * 0.4
        
        # Stability risk penalty
        score -= option.stability_risk * 0.3
        
        # Effort cost penalty
        score -= option.effort_cost * 0.2
        
        # Priority bonus
        priority_bonus = {
            Priority.IMMEDIATE: 2.0,
            Priority.HIGH: 1.5,
            Priority.MEDIUM: 1.0,
            Priority.LOW: 0.5,
            Priority.DEFERRED: 0.0
        }
        score += priority_bonus.get(option.priority, 0.0)
        
        # Strategy-specific adjustments
        if self.strategy.upgrade_constraints.allow_breaking_changes:
            score += 1.0  # Less penalty for complex upgrades
        
        if self.strategy.zero_downtime_required and option.breaking_changes != "none":
            score -= 3.0  # Heavy penalty for breaking changes
        
        return score
    
    def _generate_reasoning(
        self, 
        selected_option: RecommendationOption,
        all_options: List[Tuple[float, RecommendationOption]]
    ) -> str:
        """Generate human-readable reasoning for the selection."""
        
        reasoning_parts = [
            f"Selected {selected_option.action.value} based on {self.strategy.name} strategy"
        ]
        
        if selected_option.fixes_cves:
            reasoning_parts.append(f"Addresses {len(selected_option.fixes_cves)} vulnerabilities")
        
        if selected_option.effort_estimate in [EffortLevel.TRIVIAL, EffortLevel.LOW]:
            reasoning_parts.append("Low implementation effort")
        
        if selected_option.breaking_changes == "none":
            reasoning_parts.append("No breaking changes expected")
        
        return "; ".join(reasoning_parts)
    
    def _calculate_confidence(
        self, 
        cves: List[CVEFinding], 
        options: List[RecommendationOption]
    ) -> float:
        """Calculate confidence in recommendations."""
        
        base_confidence = 0.8
        
        # Higher confidence with more CVE data
        if len(cves) >= 3:
            base_confidence += 0.1
        
        # Higher confidence with multiple viable options
        if len(options) >= 2:
            base_confidence += 0.05
        
        # Lower confidence for complex cases
        if any(cve.severity == Severity.CRITICAL for cve in cves) and len(cves) > 5:
            base_confidence -= 0.1
        
        return min(0.95, max(0.6, base_confidence))


class StrategyManager:
    """Manager for loading and using recommendation strategies."""
    
    def __init__(self):
        """Initialize strategy manager."""
        self.strategies: Dict[str, RecommendationStrategy] = {}
        self._load_built_in_strategies()
    
    def _load_built_in_strategies(self):
        """Load built-in recommendation strategies from YAML files."""
        
        # Try to load from package resources first
        strategies_loaded = False
        
        try:
            # Method 1: Load from installed package
            if pkg_resources.resource_exists('sca_ai_scanner', 'strategies'):
                strategy_files = pkg_resources.resource_listdir('sca_ai_scanner', 'strategies')
                for filename in strategy_files:
                    if filename.endswith('.yml') or filename.endswith('.yaml'):
                        try:
                            content = pkg_resources.resource_string(
                                'sca_ai_scanner', 
                                f'strategies/{filename}'
                            ).decode('utf-8')
                            strategy_data = yaml.safe_load(content)
                            strategy = RecommendationStrategy(**strategy_data)
                            self.strategies[strategy.name] = strategy
                            strategies_loaded = True
                            logger.info(f"Loaded built-in strategy: {strategy.name}")
                        except Exception as e:
                            logger.warning(f"Failed to load strategy {filename}: {e}")
                            pass
        except:
            pass
        
        # Method 2: Load from file system (development mode)
        if not strategies_loaded:
            # Try relative to this file
            strategies_dir = Path(__file__).parent.parent / 'strategies'
            if strategies_dir.exists():
                for strategy_file in strategies_dir.glob('*.yml'):
                    try:
                        strategy = self.load_strategy_from_file(strategy_file)
                        self.strategies[strategy.name] = strategy
                        strategies_loaded = True
                        logger.info(f"Loaded built-in strategy from file: {strategy.name}")
                    except Exception as e:
                        logger.warning(f"Failed to load strategy from {strategy_file}: {e}")
                        pass
        
        # Fallback: If no YAML files found, create minimal default strategy
        if not strategies_loaded:
            self.strategies["balanced_security"] = RecommendationStrategy(
                name="balanced_security",
                description="Balance security improvements with stability",
                severity_priorities=SeverityPriority(
                    critical=Priority.IMMEDIATE,
                    high=Priority.HIGH,
                    medium=Priority.MEDIUM,
                    low=Priority.LOW
                ),
                upgrade_constraints=UpgradeConstraints(
                    max_version_jump=VersionJumpConstraint.MINOR,
                    allow_breaking_changes=False,
                    max_effort_level=EffortLevel.MEDIUM
                )
            )
    
    def load_strategy_from_file(self, strategy_path: Path) -> RecommendationStrategy:
        """Load strategy from YAML file."""
        
        try:
            with open(strategy_path, 'r', encoding='utf-8') as f:
                strategy_data = yaml.safe_load(f)
            
            return RecommendationStrategy(**strategy_data)
            
        except Exception as e:
            raise ValueError(f"Failed to load strategy from {strategy_path}: {e}")
    
    def get_strategy(self, name: str) -> Optional[RecommendationStrategy]:
        """Get strategy by name."""
        return self.strategies.get(name)
    
    def list_strategies(self) -> List[str]:
        """List available strategy names."""
        return list(self.strategies.keys())
    
    def get_default_strategy(self) -> RecommendationStrategy:
        """Get default recommendation strategy."""
        return self.strategies["balanced_security"]