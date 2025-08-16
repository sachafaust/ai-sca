"""
DSPy Adaptive Batch Processing Optimizer.
Automatically tunes batch sizes and prompts for optimal performance.
"""

import dspy
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
import json
import time
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
import math

from ..core.models import Package

logger = logging.getLogger(__name__)


class BatchAnalysisSignature(dspy.Signature):
    """Signature for batch vulnerability analysis."""
    
    # Inputs
    packages_json = dspy.InputField(desc="JSON array of packages to analyze")
    batch_size = dspy.InputField(desc="Number of packages in this batch", type=int)
    model_context_window = dspy.InputField(desc="Model's context window size", type=int)
    optimization_goal = dspy.InputField(desc="Optimization goal: speed/cost/balanced")
    
    # Outputs
    vulnerability_results = dspy.OutputField(desc="JSON vulnerability results for all packages")
    tokens_used = dspy.OutputField(desc="Total tokens used", type=int)
    processing_time = dspy.OutputField(desc="Processing time in seconds", type=float)
    batch_efficiency = dspy.OutputField(desc="Efficiency score 0-1", type=float)
    
    def validate(self, data: Dict[str, Any]) -> None:
        """Validate batch analysis data."""
        if 'batch_efficiency' in data:
            eff = data['batch_efficiency']
            if not isinstance(eff, (int, float)) or eff < 0 or eff > 1:
                raise ValueError(f"Batch efficiency must be 0-1, got {eff}")


@dataclass
class BatchStrategy:
    """Batch processing strategy configuration."""
    batch_size: int
    max_tokens_per_batch: int
    parallel_batches: int
    optimization_mode: str
    
    def is_valid(self) -> bool:
        """Check if strategy is valid."""
        return (
            1 <= self.batch_size <= 200 and
            1000 <= self.max_tokens_per_batch <= 128000 and
            1 <= self.parallel_batches <= 10
        )
    
    def estimated_cost_factor(self) -> float:
        """Estimate relative cost of this strategy."""
        # Larger batches and less parallelism = lower cost
        batch_factor = 1.0 / self.batch_size
        parallel_factor = self.parallel_batches * 0.1
        return batch_factor + parallel_factor
    
    def copy(self) -> 'BatchStrategy':
        """Create a copy of this strategy."""
        return BatchStrategy(
            batch_size=self.batch_size,
            max_tokens_per_batch=self.max_tokens_per_batch,
            parallel_batches=self.parallel_batches,
            optimization_mode=self.optimization_mode
        )


@dataclass
class ModelCapabilities:
    """Model-specific capabilities and limits."""
    context_window: int
    max_output_tokens: int
    supports_parallel: bool
    cost_per_1k_tokens: float
    optimal_batch_range: Tuple[int, int] = (10, 50)
    
    @classmethod
    def detect(cls, model_name: str) -> 'ModelCapabilities':
        """Detect model capabilities from model name."""
        model_lower = model_name.lower()
        
        # GPT-4 variants
        if 'gpt-4' in model_lower or 'gpt-4o' in model_lower:
            return cls(
                context_window=128000,
                max_output_tokens=4096,
                supports_parallel=True,
                cost_per_1k_tokens=0.01,
                optimal_batch_range=(20, 50)
            )
        
        # Claude variants
        elif 'claude' in model_lower:
            if 'claude-3.5' in model_lower or 'claude-3-5' in model_lower:
                return cls(
                    context_window=200000,
                    max_output_tokens=4096,
                    supports_parallel=True,
                    cost_per_1k_tokens=0.003,
                    optimal_batch_range=(30, 80)
                )
            return cls(
                context_window=100000,
                max_output_tokens=4096,
                supports_parallel=True,
                cost_per_1k_tokens=0.008,
                optimal_batch_range=(20, 60)
            )
        
        # Gemini variants
        elif 'gemini' in model_lower:
            if 'flash' in model_lower:
                return cls(
                    context_window=1000000,
                    max_output_tokens=8192,
                    supports_parallel=True,
                    cost_per_1k_tokens=0.00015,
                    optimal_batch_range=(50, 200)
                )
            return cls(
                context_window=128000,
                max_output_tokens=8192,
                supports_parallel=True,
                cost_per_1k_tokens=0.0005,
                optimal_batch_range=(30, 100)
            )
        
        # Default conservative capabilities
        return cls(
            context_window=8000,
            max_output_tokens=4000,
            supports_parallel=False,
            cost_per_1k_tokens=0.02,
            optimal_batch_range=(5, 20)
        )


@dataclass
class OptimizationMetrics:
    """Metrics for batch optimization."""
    batch_size: int
    tokens_used: int
    time_taken: float
    accuracy: float
    cost_estimate: float = 0.0
    
    def efficiency_score(self) -> float:
        """Calculate overall efficiency score."""
        # Balance between speed, cost, and accuracy
        speed_score = 1.0 / (1 + self.time_taken / 10)  # Normalize to 0-1
        cost_score = 1.0 / (1 + self.cost_estimate)     # Lower cost is better
        accuracy_score = self.accuracy
        
        # Weighted average
        return 0.3 * speed_score + 0.3 * cost_score + 0.4 * accuracy_score


class AdaptiveBatchOptimizer(dspy.Module):
    """Adaptive batch optimizer using DSPy."""
    
    def __init__(self, model: str = 'gpt-4o-mini'):
        """Initialize batch optimizer.
        
        Args:
            model: Model name for capability detection
        """
        super().__init__()
        
        self.model = model
        self.capabilities = ModelCapabilities.detect(model)
        self.batch_analyzer = dspy.ChainOfThought(BatchAnalysisSignature)
        
        # Initialize with default strategy
        self.current_strategy = BatchStrategy(
            batch_size=self.capabilities.optimal_batch_range[0],
            max_tokens_per_batch=min(16000, self.capabilities.context_window // 4),
            parallel_batches=3 if self.capabilities.supports_parallel else 1,
            optimization_mode='balanced'
        )
        
        self.metrics_history: List[OptimizationMetrics] = []
        self.constraints = []
    
    def discover_optimal_batch_size(
        self,
        packages: List[Package],
        test_sizes: Optional[List[int]] = None
    ) -> int:
        """Discover optimal batch size through testing.
        
        Args:
            packages: Sample packages to test with
            test_sizes: Batch sizes to test
            
        Returns:
            Optimal batch size
        """
        if test_sizes is None:
            min_size, max_size = self.capabilities.optimal_batch_range
            test_sizes = [
                min_size,
                (min_size + max_size) // 2,
                max_size,
                max_size + 10
            ]
        
        best_score = 0
        best_size = self.current_strategy.batch_size
        
        for size in test_sizes:
            if size > len(packages):
                continue
            
            try:
                metrics = self._test_batch_size(packages[:size], size)
                score = metrics.efficiency_score()
                
                if score > best_score:
                    best_score = score
                    best_size = size
                
                self.metrics_history.append(metrics)
                
            except Exception as e:
                logger.warning(f"Failed to test batch size {size}: {e}")
        
        logger.info(f"Optimal batch size discovered: {best_size} (score: {best_score:.3f})")
        return best_size
    
    def _test_batch_size(self, packages: List[Package], batch_size: int) -> OptimizationMetrics:
        """Test a specific batch size.
        
        Args:
            packages: Packages to test
            batch_size: Batch size to test
            
        Returns:
            Optimization metrics
        """
        start_time = time.time()
        
        # Convert packages to JSON
        packages_data = [
            {
                'name': p.name,
                'version': p.version,
                'ecosystem': p.ecosystem
            }
            for p in packages
        ]
        
        # Run batch analysis
        result = self.batch_analyzer(
            packages_json=json.dumps(packages_data),
            batch_size=batch_size,
            model_context_window=self.capabilities.context_window,
            optimization_goal=self.current_strategy.optimization_mode
        )
        
        # Extract metrics
        time_taken = time.time() - start_time
        tokens_used = getattr(result, 'tokens_used', batch_size * 100)  # Estimate
        efficiency = getattr(result, 'batch_efficiency', 0.8)
        
        # Calculate cost
        cost_estimate = (tokens_used / 1000) * self.capabilities.cost_per_1k_tokens
        
        return OptimizationMetrics(
            batch_size=batch_size,
            tokens_used=tokens_used,
            time_taken=time_taken,
            accuracy=efficiency,  # Use efficiency as proxy for accuracy
            cost_estimate=cost_estimate
        )
    
    def process_packages_parallel(
        self,
        packages: List[Package]
    ) -> Dict[str, Any]:
        """Process packages in parallel batches.
        
        Args:
            packages: All packages to process
            
        Returns:
            Processing results
        """
        # Create batches
        batches = self._create_batches(packages)
        
        total_tokens = 0
        total_time = 0
        all_results = []
        
        # Process batches in parallel
        with ThreadPoolExecutor(max_workers=self.current_strategy.parallel_batches) as executor:
            futures = []
            for batch in batches:
                future = executor.submit(self.process_batch, batch)
                futures.append(future)
            
            for future in futures:
                result = future.result()
                all_results.append(result)
                total_tokens += result.get('tokens', 0)
                total_time = max(total_time, result.get('time', 0))
        
        return {
            'results': all_results,
            'total_tokens': total_tokens,
            'total_time': total_time,
            'batches_processed': len(batches)
        }
    
    def process_batch(self, packages: List[Package]) -> Dict[str, Any]:
        """Process a single batch of packages.
        
        Args:
            packages: Batch of packages
            
        Returns:
            Batch processing results
        """
        start_time = time.time()
        
        # Convert to JSON
        packages_data = [
            {
                'name': p.name,
                'version': p.version,
                'ecosystem': p.ecosystem
            }
            for p in packages
        ]
        
        # Process with DSPy
        result = self.batch_analyzer(
            packages_json=json.dumps(packages_data),
            batch_size=len(packages),
            model_context_window=self.capabilities.context_window,
            optimization_goal=self.current_strategy.optimization_mode
        )
        
        return {
            'results': json.loads(getattr(result, 'vulnerability_results', '[]')),
            'tokens': getattr(result, 'tokens_used', 0),
            'time': time.time() - start_time,
            'accuracy': getattr(result, 'batch_efficiency', 0.8)
        }
    
    def _create_batches(self, packages: List[Package]) -> List[List[Package]]:
        """Create batches from packages list.
        
        Args:
            packages: All packages
            
        Returns:
            List of batches
        """
        batch_size = self.current_strategy.batch_size
        batches = []
        
        for i in range(0, len(packages), batch_size):
            batch = packages[i:i + batch_size]
            batches.append(batch)
        
        return batches
    
    def adapt_strategy(self) -> None:
        """Adapt strategy based on historical metrics."""
        if len(self.metrics_history) < 3:
            return
        
        # Analyze recent performance
        recent_metrics = self.metrics_history[-5:]
        avg_efficiency = sum(m.efficiency_score() for m in recent_metrics) / len(recent_metrics)
        
        # Adjust batch size
        if avg_efficiency < 0.5:
            # Poor performance - try smaller batches
            self.current_strategy.batch_size = max(
                5,
                self.current_strategy.batch_size - 5
            )
        elif avg_efficiency > 0.8:
            # Good performance - try larger batches
            self.current_strategy.batch_size = min(
                100,
                self.current_strategy.batch_size + 10
            )
        
        logger.info(f"Adapted batch size to {self.current_strategy.batch_size}")
    
    def set_optimization_mode(self, mode: str) -> None:
        """Set optimization mode.
        
        Args:
            mode: 'speed', 'cost', or 'balanced'
        """
        self.current_strategy.optimization_mode = mode
        
        if mode == 'cost':
            # Prefer larger batches, less parallelism
            self.current_strategy.batch_size = self.capabilities.optimal_batch_range[1]
            self.current_strategy.parallel_batches = 1
        elif mode == 'speed':
            # Prefer more parallelism
            self.current_strategy.batch_size = self.capabilities.optimal_batch_range[0]
            self.current_strategy.parallel_batches = min(5, self.capabilities.supports_parallel * 5)
        else:  # balanced
            self.current_strategy.batch_size = sum(self.capabilities.optimal_batch_range) // 2
            self.current_strategy.parallel_batches = 3 if self.capabilities.supports_parallel else 1
    
    def optimize_for_packages(self, packages: List[Package]) -> BatchStrategy:
        """Optimize strategy for specific package set.
        
        Args:
            packages: Packages to optimize for
            
        Returns:
            Optimized batch strategy
        """
        # Discover optimal batch size
        optimal_size = self.discover_optimal_batch_size(packages[:50])  # Test with subset
        
        # Update strategy
        self.current_strategy.batch_size = optimal_size
        
        # Adapt based on package count
        if len(packages) > 1000:
            # Large dataset - increase batch size
            self.current_strategy.batch_size = min(
                optimal_size * 2,
                self.capabilities.optimal_batch_range[1]
            )
        
        return self.current_strategy
    
    def create_token_aware_batches(
        self,
        packages: List[Package],
        max_tokens_per_batch: int
    ) -> List[List[Package]]:
        """Create batches aware of token limits.
        
        Args:
            packages: Packages to batch
            max_tokens_per_batch: Token limit per batch
            
        Returns:
            Token-aware batches
        """
        batches = []
        current_batch = []
        current_tokens = 0
        
        for package in packages:
            estimated_tokens = self.estimate_tokens(package)
            
            if current_tokens + estimated_tokens > max_tokens_per_batch and current_batch:
                batches.append(current_batch)
                current_batch = []
                current_tokens = 0
            
            current_batch.append(package)
            current_tokens += estimated_tokens
        
        if current_batch:
            batches.append(current_batch)
        
        return batches
    
    def estimate_tokens(self, package: Package) -> int:
        """Estimate tokens for a package.
        
        Args:
            package: Package to estimate
            
        Returns:
            Estimated token count
        """
        # Simple estimation based on string lengths
        base_tokens = 50  # Base overhead
        name_tokens = len(package.name) // 4
        version_tokens = len(package.version) // 4
        
        return base_tokens + name_tokens + version_tokens
    
    def process_with_metrics(self, packages: List[Package]) -> Dict[str, Any]:
        """Process packages and record metrics.
        
        Args:
            packages: Packages to process
            
        Returns:
            Processing results with metrics
        """
        result = self.process_packages_parallel(packages)
        
        # Record metrics
        metrics = OptimizationMetrics(
            batch_size=self.current_strategy.batch_size,
            tokens_used=result['total_tokens'],
            time_taken=result['total_time'],
            accuracy=0.95,  # Would be calculated from results
            cost_estimate=(result['total_tokens'] / 1000) * self.capabilities.cost_per_1k_tokens
        )
        
        self.metrics_history.append(metrics)
        
        # Adapt strategy for next run
        self.adapt_strategy()
        
        return result
    
    def add_constraint(self, constraint_fn, message: str):
        """Add optimization constraint.
        
        Args:
            constraint_fn: Function that returns True if constraint is satisfied
            message: Error message if constraint fails
        """
        self.constraints.append((constraint_fn, message))
    
    def process_with_constraints(self, packages: List[Package]) -> Dict[str, Any]:
        """Process packages with constraint checking.
        
        Args:
            packages: Packages to process
            
        Returns:
            Processing results
            
        Raises:
            AssertionError: If constraints are violated
        """
        result = self.process_with_metrics(packages)
        
        # Check constraints
        latest_metrics = self.metrics_history[-1]
        for constraint_fn, msg in self.constraints:
            if not constraint_fn(latest_metrics):
                raise AssertionError(msg)
        
        return result


def calculate_batch_metric(result: Dict[str, Any], mode: str = 'balanced') -> float:
    """Calculate batch optimization metric.
    
    Args:
        result: Batch processing result
        mode: Optimization mode
        
    Returns:
        Metric score between 0 and 1
    """
    tokens = result.get('tokens_used', 10000)
    time = result.get('processing_time', 10.0)
    accuracy = result.get('accuracy', 0.5)
    efficiency = result.get('batch_efficiency', 0.5)
    
    # Normalize values
    token_score = 1.0 / (1 + tokens / 10000)  # Lower is better
    time_score = 1.0 / (1 + time / 5)         # Lower is better
    
    if mode == 'cost':
        # Heavily weight token usage
        return 0.6 * token_score + 0.1 * time_score + 0.2 * accuracy + 0.1 * efficiency
    elif mode == 'speed':
        # Heavily weight processing time
        return 0.1 * token_score + 0.6 * time_score + 0.2 * accuracy + 0.1 * efficiency
    else:  # balanced
        return 0.25 * token_score + 0.25 * time_score + 0.3 * accuracy + 0.2 * efficiency


def create_optimized_batch_processor(
    model: str,
    training_data: List[Dict[str, Any]],
    optimization_goal: str = 'balanced',
    max_iterations: int = 10
) -> AdaptiveBatchOptimizer:
    """Create an optimized batch processor using DSPy.
    
    Args:
        model: Model name
        training_data: Training data with packages and expected results
        optimization_goal: 'speed', 'cost', or 'balanced'
        max_iterations: Optimization iterations
        
    Returns:
        Optimized batch processor
    """
    # Create base optimizer
    optimizer = AdaptiveBatchOptimizer(model=model)
    optimizer.set_optimization_mode(optimization_goal)
    
    # Prepare training examples
    trainset = []
    for item in training_data:
        packages = item['packages']
        expected_results = item.get('expected_results', [])
        
        example = dspy.Example(
            packages=packages,
            expected_results=expected_results
        )
        trainset.append(example)
    
    # Define metric function
    def metric_fn(pred, example):
        return calculate_batch_metric(pred.dict() if hasattr(pred, 'dict') else pred, optimization_goal)
    
    # Setup DSPy optimizer
    dspy_optimizer = dspy.MIPROv2(
        metric=metric_fn,
        max_bootstrapped_demos=5,
        max_labeled_demos=5,
        num_iterations=max_iterations
    )
    
    # Optimize
    optimized = dspy_optimizer.compile(
        optimizer,
        trainset=trainset,
        requires_permission_to_run=False
    )
    
    logger.info(f"Created optimized batch processor for {optimization_goal} mode")
    
    return optimized