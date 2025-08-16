"""
Unit tests for DSPy Adaptive Batch Processing Optimizer.
Tests automatic batch size and prompt optimization.
"""

import pytest
import dspy
from unittest.mock import Mock, patch, MagicMock
from typing import List, Dict, Any
import time

from sca_ai_scanner.dspy_modules.batch_optimizer import (
    BatchAnalysisSignature,
    AdaptiveBatchOptimizer,
    BatchStrategy,
    ModelCapabilities,
    OptimizationMetrics,
    create_optimized_batch_processor
)
from sca_ai_scanner.core.models import Package


class TestBatchAnalysisSignature:
    """Test the batch analysis signature."""
    
    def test_signature_structure(self):
        """Test BatchAnalysisSignature has correct fields."""
        sig = BatchAnalysisSignature()
        
        # Input fields
        assert hasattr(sig, 'packages_json')
        assert hasattr(sig, 'batch_size')
        assert hasattr(sig, 'model_context_window')
        assert hasattr(sig, 'optimization_goal')
        
        # Output fields
        assert hasattr(sig, 'vulnerability_results')
        assert hasattr(sig, 'tokens_used')
        assert hasattr(sig, 'processing_time')
        assert hasattr(sig, 'batch_efficiency')
    
    def test_signature_validation(self):
        """Test validation of batch analysis data."""
        sig = BatchAnalysisSignature()
        
        valid_data = {
            'packages_json': '[{"name": "lodash", "version": "4.17.19"}]',
            'batch_size': 10,
            'model_context_window': 128000,
            'optimization_goal': 'minimize_tokens',
            'vulnerability_results': '{"results": []}',
            'tokens_used': 5000,
            'processing_time': 2.5,
            'batch_efficiency': 0.85
        }
        
        sig.validate(valid_data)


class TestBatchStrategy:
    """Test batch strategy optimization."""
    
    def test_strategy_initialization(self):
        """Test BatchStrategy initialization."""
        strategy = BatchStrategy(
            batch_size=20,
            max_tokens_per_batch=8000,
            parallel_batches=3,
            optimization_mode='balanced'
        )
        
        assert strategy.batch_size == 20
        assert strategy.max_tokens_per_batch == 8000
        assert strategy.parallel_batches == 3
        assert strategy.optimization_mode == 'balanced'
    
    def test_strategy_validation(self):
        """Test strategy validates constraints."""
        # Valid strategy
        strategy = BatchStrategy(
            batch_size=50,
            max_tokens_per_batch=16000,
            parallel_batches=5,
            optimization_mode='speed'
        )
        
        assert strategy.is_valid()
        
        # Invalid strategy (batch size too large)
        strategy_invalid = BatchStrategy(
            batch_size=500,  # Too large
            max_tokens_per_batch=16000,
            parallel_batches=5,
            optimization_mode='speed'
        )
        
        assert not strategy_invalid.is_valid()
    
    def test_strategy_comparison(self):
        """Test comparing different strategies."""
        strategy1 = BatchStrategy(
            batch_size=20,
            max_tokens_per_batch=8000,
            parallel_batches=3,
            optimization_mode='balanced'
        )
        
        strategy2 = BatchStrategy(
            batch_size=50,
            max_tokens_per_batch=16000,
            parallel_batches=1,
            optimization_mode='cost'
        )
        
        # Strategy 2 should be more cost-effective (larger batches, less parallel)
        assert strategy2.estimated_cost_factor() < strategy1.estimated_cost_factor()


class TestModelCapabilities:
    """Test model capabilities detection."""
    
    def test_model_capabilities_detection(self):
        """Test detecting model capabilities."""
        capabilities = ModelCapabilities.detect('gpt-4o-mini')
        
        assert capabilities is not None
        assert capabilities.context_window > 0
        assert capabilities.max_output_tokens > 0
        assert capabilities.supports_parallel is not None
        assert capabilities.cost_per_1k_tokens > 0
    
    def test_model_capabilities_for_different_models(self):
        """Test capabilities for different model types."""
        # GPT model
        gpt_caps = ModelCapabilities.detect('gpt-4o')
        assert gpt_caps.context_window == 128000
        assert gpt_caps.supports_parallel == True
        
        # Claude model
        claude_caps = ModelCapabilities.detect('claude-3.5-sonnet')
        assert claude_caps.context_window == 200000
        assert claude_caps.supports_parallel == True
        
        # Gemini model
        gemini_caps = ModelCapabilities.detect('gemini-2.0-flash')
        assert gemini_caps.context_window == 1000000
        assert gemini_caps.supports_parallel == True
    
    def test_unknown_model_capabilities(self):
        """Test handling unknown model."""
        capabilities = ModelCapabilities.detect('unknown-model-xyz')
        
        # Should return default safe values
        assert capabilities.context_window == 8000  # Conservative default
        assert capabilities.max_output_tokens == 4000
        assert capabilities.supports_parallel == False


class TestAdaptiveBatchOptimizer:
    """Test the adaptive batch optimizer."""
    
    @pytest.fixture
    def mock_lm(self):
        """Mock language model for testing."""
        mock = MagicMock()
        mock.request.return_value = {
            'vulnerability_results': '{"results": []}',
            'tokens_used': 5000,
            'processing_time': 2.5,
            'batch_efficiency': 0.85
        }
        return mock
    
    @pytest.fixture
    def optimizer(self, mock_lm):
        """Create optimizer with mocked LM."""
        with patch('dspy.settings.lm', mock_lm):
            return AdaptiveBatchOptimizer(model='gpt-4o-mini')
    
    def test_optimizer_initialization(self, optimizer):
        """Test optimizer initializes correctly."""
        assert optimizer is not None
        assert hasattr(optimizer, 'model')
        assert hasattr(optimizer, 'capabilities')
        assert hasattr(optimizer, 'current_strategy')
        assert hasattr(optimizer, 'metrics_history')
    
    def test_automatic_batch_size_discovery(self, optimizer):
        """Test optimizer discovers optimal batch size."""
        packages = [
            Package(name=f'package-{i}', version='1.0.0', ecosystem='npm', source_locations=[])
            for i in range(100)
        ]
        
        with patch.object(optimizer, '_test_batch_size') as mock_test:
            mock_test.side_effect = [
                OptimizationMetrics(batch_size=10, tokens_used=5000, time_taken=2.0, accuracy=0.95),
                OptimizationMetrics(batch_size=20, tokens_used=8000, time_taken=2.5, accuracy=0.96),
                OptimizationMetrics(batch_size=30, tokens_used=11000, time_taken=3.0, accuracy=0.94),
                OptimizationMetrics(batch_size=40, tokens_used=14000, time_taken=3.8, accuracy=0.93),
            ]
            
            optimal_size = optimizer.discover_optimal_batch_size(packages)
            
            # Should select batch size 20 (best accuracy/efficiency balance)
            assert optimal_size == 20
            assert mock_test.call_count >= 3
    
    def test_parallel_batch_processing(self, optimizer):
        """Test parallel batch processing."""
        packages = [
            Package(name=f'package-{i}', version='1.0.0', ecosystem='npm', source_locations=[])
            for i in range(50)
        ]
        
        with patch.object(optimizer, 'process_batch') as mock_process:
            mock_process.return_value = {
                'results': [],
                'tokens': 5000,
                'time': 2.0
            }
            
            optimizer.current_strategy.parallel_batches = 3
            optimizer.current_strategy.batch_size = 10
            
            results = optimizer.process_packages_parallel(packages)
            
            # Should create 5 batches (50 packages / 10 per batch)
            assert mock_process.call_count == 5
            assert 'total_tokens' in results
            assert 'total_time' in results
    
    def test_adaptive_strategy_adjustment(self, optimizer):
        """Test optimizer adjusts strategy based on performance."""
        initial_strategy = optimizer.current_strategy.copy()
        
        # Simulate poor performance metrics
        poor_metrics = [
            OptimizationMetrics(
                batch_size=initial_strategy.batch_size,
                tokens_used=20000,  # High token usage
                time_taken=10.0,     # Slow
                accuracy=0.85        # Lower accuracy
            )
        ]
        
        optimizer.metrics_history.extend(poor_metrics)
        optimizer.adapt_strategy()
        
        # Strategy should change
        assert optimizer.current_strategy.batch_size != initial_strategy.batch_size
    
    def test_cost_optimization_mode(self, optimizer):
        """Test cost optimization mode."""
        optimizer.set_optimization_mode('cost')
        
        packages = [
            Package(name=f'package-{i}', version='1.0.0', ecosystem='npm', source_locations=[])
            for i in range(100)
        ]
        
        with patch.object(optimizer, 'process_batch') as mock_process:
            mock_process.return_value = {
                'results': [],
                'tokens': 3000,
                'time': 2.0
            }
            
            strategy = optimizer.optimize_for_packages(packages)
            
            # In cost mode, should prefer larger batches
            assert strategy.batch_size >= 30
            assert strategy.parallel_batches <= 2  # Less parallelism to reduce cost
    
    def test_speed_optimization_mode(self, optimizer):
        """Test speed optimization mode."""
        optimizer.set_optimization_mode('speed')
        
        packages = [
            Package(name=f'package-{i}', version='1.0.0', ecosystem='npm', source_locations=[])
            for i in range(100)
        ]
        
        with patch.object(optimizer, 'process_batch') as mock_process:
            mock_process.return_value = {
                'results': [],
                'tokens': 5000,
                'time': 1.0
            }
            
            strategy = optimizer.optimize_for_packages(packages)
            
            # In speed mode, should prefer more parallelism
            assert strategy.parallel_batches >= 3
            assert strategy.batch_size <= 30  # Smaller batches for faster processing
    
    def test_token_limit_handling(self, optimizer):
        """Test handling of token limits."""
        # Create packages that would exceed token limit
        large_packages = [
            Package(
                name=f'very-long-package-name-{i}' * 10,  # Long names
                version='1.0.0-alpha.beta.gamma.delta',
                ecosystem='npm',
                source_locations=[]
            )
            for i in range(100)
        ]
        
        with patch.object(optimizer, 'estimate_tokens') as mock_estimate:
            mock_estimate.return_value = 500  # Each package uses 500 tokens
            
            batches = optimizer.create_token_aware_batches(
                large_packages,
                max_tokens_per_batch=8000
            )
            
            # Should create smaller batches to stay within token limit
            for batch in batches:
                assert len(batch) <= 16  # 16 * 500 = 8000 tokens
    
    def test_metrics_tracking(self, optimizer):
        """Test that optimizer tracks metrics correctly."""
        packages = [
            Package(name=f'package-{i}', version='1.0.0', ecosystem='npm', source_locations=[])
            for i in range(20)
        ]
        
        with patch.object(optimizer, 'process_batch') as mock_process:
            mock_process.return_value = {
                'results': [],
                'tokens': 5000,
                'time': 2.0,
                'accuracy': 0.95
            }
            
            optimizer.process_with_metrics(packages)
            
            # Check metrics were recorded
            assert len(optimizer.metrics_history) > 0
            last_metric = optimizer.metrics_history[-1]
            assert last_metric.tokens_used == 5000
            assert last_metric.time_taken == 2.0
            assert last_metric.accuracy == 0.95


class TestOptimizedBatchProcessor:
    """Test the optimized batch processor creation."""
    
    def test_create_optimized_processor(self):
        """Test creating an optimized batch processor."""
        training_data = [
            {
                'packages': [
                    Package(name=f'package-{i}', version='1.0.0', ecosystem='npm', source_locations=[])
                    for i in range(50)
                ],
                'expected_results': []
            }
        ]
        
        with patch('dspy.MIPROv2') as mock_optimizer:
            mock_optimizer.return_value.compile.return_value = Mock()
            
            processor = create_optimized_batch_processor(
                model='gpt-4o-mini',
                training_data=training_data,
                optimization_goal='balanced',
                max_iterations=10
            )
            
            assert processor is not None
            mock_optimizer.return_value.compile.assert_called_once()
    
    def test_batch_processor_metric_function(self):
        """Test the metric function for batch optimization."""
        from sca_ai_scanner.dspy_modules.batch_optimizer import calculate_batch_metric
        
        result = {
            'tokens_used': 5000,
            'processing_time': 2.0,
            'accuracy': 0.95,
            'batch_efficiency': 0.85
        }
        
        # Test balanced mode
        score_balanced = calculate_batch_metric(result, mode='balanced')
        assert 0 <= score_balanced <= 1
        
        # Test cost mode (should weight tokens more heavily)
        score_cost = calculate_batch_metric(result, mode='cost')
        assert 0 <= score_cost <= 1
        
        # Test speed mode (should weight time more heavily)
        score_speed = calculate_batch_metric(result, mode='speed')
        assert 0 <= score_speed <= 1
    
    def test_batch_processor_with_constraints(self):
        """Test batch processor with DSPy constraints."""
        optimizer = AdaptiveBatchOptimizer(model='gpt-4o-mini')
        
        # Add constraint for minimum accuracy
        optimizer.add_constraint(
            lambda metrics: metrics.accuracy >= 0.90,
            "Accuracy must be at least 90%"
        )
        
        # Add constraint for maximum tokens
        optimizer.add_constraint(
            lambda metrics: metrics.tokens_used <= 10000,
            "Token usage must not exceed 10000"
        )
        
        with patch.object(optimizer, 'process_batch') as mock_process:
            # Test passing constraints
            mock_process.return_value = {
                'results': [],
                'tokens': 8000,
                'accuracy': 0.92
            }
            
            packages = [Package(name='test', version='1.0.0', ecosystem='npm', source_locations=[])]
            result = optimizer.process_with_constraints(packages)
            assert result is not None
            
            # Test failing constraints
            mock_process.return_value = {
                'results': [],
                'tokens': 12000,  # Exceeds limit
                'accuracy': 0.85   # Below minimum
            }
            
            with pytest.raises(AssertionError):
                optimizer.process_with_constraints(packages)


@pytest.mark.integration
class TestBatchOptimizerIntegration:
    """Integration tests for batch optimizer."""
    
    def test_end_to_end_batch_optimization(self):
        """Test complete batch optimization flow."""
        with patch('dspy.OpenAI') as mock_openai:
            mock_openai.return_value.request.return_value = {
                'vulnerability_results': '{"results": []}',
                'tokens_used': 5000,
                'processing_time': 2.5,
                'batch_efficiency': 0.85
            }
            
            # Configure DSPy
            dspy.settings.configure(lm=mock_openai())
            
            # Create optimizer
            optimizer = AdaptiveBatchOptimizer(model='gpt-4o-mini')
            
            # Test packages
            packages = [
                Package(name=f'package-{i}', version='1.0.0', ecosystem='npm', source_locations=[])
                for i in range(100)
            ]
            
            # Discover optimal batch size
            optimal_size = optimizer.discover_optimal_batch_size(packages[:20])
            assert optimal_size > 0
            assert optimal_size <= 50
            
            # Process all packages with optimal strategy
            results = optimizer.process_packages_parallel(packages)
            
            assert results is not None
            assert 'total_tokens' in results
            assert results['total_tokens'] > 0