"""
Search Optimization Module for Secret Sluth.

This module provides performance optimization features for search operations,
including caching strategies, parallel processing, and memory management.
"""

import time
import threading
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from app.logging_config import get_logger
from app.search_cache import search_cache

logger = get_logger(__name__)


@dataclass
class PerformanceMetrics:
    """Performance metrics for search operations."""
    total_time: float
    cache_hits: int
    cache_misses: int
    parallel_searches: int
    memory_usage_mb: float
    results_count: int
    engines_searched: int


class SearchOptimizer:
    """
    Optimizes search performance through caching, parallel processing, and resource management.
    """
    
    def __init__(self, max_workers: int = 5, cache_ttl: int = 3600):
        """
        Initialize the search optimizer.
        
        Args:
            max_workers: Maximum number of parallel workers
            cache_ttl: Cache time-to-live in seconds
        """
        self.max_workers = max_workers
        self.cache_ttl = cache_ttl
        self.logger = get_logger(__name__)
        self.performance_history: List[PerformanceMetrics] = []
        self.lock = threading.RLock()
        
        # Performance tracking
        self.total_searches = 0
        self.total_cache_hits = 0
        self.total_cache_misses = 0
        self.avg_search_time = 0.0
    
    def optimize_search_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Optimize search configuration for better performance.
        
        Args:
            config: Search configuration dictionary
            
        Returns:
            Optimized configuration
        """
        optimized_config = config.copy()
        
        # Adjust parallel searches based on available resources
        if 'parallel_searches' in optimized_config:
            current_parallel = optimized_config['parallel_searches']
            # Limit to max_workers to prevent resource exhaustion
            optimized_config['parallel_searches'] = min(current_parallel, self.max_workers)
        
        # Optimize max_results for memory usage
        if 'max_results' in optimized_config:
            max_results = optimized_config['max_results']
            # Cap at reasonable limit to prevent memory issues
            optimized_config['max_results'] = min(max_results, 5000)
        
        # Add performance hints
        optimized_config['_optimized'] = True
        optimized_config['_optimization_timestamp'] = time.time()
        
        self.logger.info(f"Optimized search config: parallel_searches={optimized_config.get('parallel_searches')}, max_results={optimized_config.get('max_results')}")
        
        return optimized_config
    
    def execute_parallel_search(self, search_function, search_args: List[Tuple], config: Dict[str, Any]) -> List[Any]:
        """
        Execute search operations in parallel for better performance.
        
        Args:
            search_function: Function to execute for each search
            search_args: List of arguments for each search operation
            config: Search configuration
            
        Returns:
            Combined results from all parallel searches
        """
        start_time = time.time()
        parallel_searches = config.get('parallel_searches', self.max_workers)
        
        self.logger.info(f"Starting parallel search with {parallel_searches} workers for {len(search_args)} operations")
        
        results = []
        cache_hits = 0
        cache_misses = 0
        
        with ThreadPoolExecutor(max_workers=parallel_searches) as executor:
            # Submit all search tasks
            future_to_args = {
                executor.submit(search_function, *args): args 
                for args in search_args
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_args):
                try:
                    result = future.result()
                    if isinstance(result, dict) and 'cache_hit' in result:
                        if result['cache_hit']:
                            cache_hits += 1
                        else:
                            cache_misses += 1
                        results.extend(result.get('results', []))
                    else:
                        results.extend(result if isinstance(result, list) else [result])
                        
                except Exception as e:
                    args = future_to_args[future]
                    self.logger.error(f"Search operation failed for args {args}: {e}")
        
        total_time = time.time() - start_time
        
        # Record performance metrics
        metrics = PerformanceMetrics(
            total_time=total_time,
            cache_hits=cache_hits,
            cache_misses=cache_misses,
            parallel_searches=parallel_searches,
            memory_usage_mb=self._get_memory_usage(),
            results_count=len(results),
            engines_searched=len(search_args)
        )
        
        self._record_performance(metrics)
        
        self.logger.info(f"Parallel search completed in {total_time:.2f}s: {len(results)} results, {cache_hits} cache hits, {cache_misses} cache misses")
        
        return results
    
    def optimize_cache_strategy(self, query: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Optimize caching strategy based on query patterns and configuration.
        
        Args:
            query: Search query
            config: Search configuration
            
        Returns:
            Optimized cache configuration
        """
        cache_config = {
            'enabled': True,
            'ttl': self.cache_ttl,
            'key_pattern': 'optimized'
        }
        
        # Adjust cache TTL based on query type
        if query.startswith('/') and query.endswith('/'):
            # Regex queries are more expensive, cache longer
            cache_config['ttl'] = self.cache_ttl * 2
        elif '*' in query or '?' in query:
            # Wildcard queries are moderately expensive
            cache_config['ttl'] = int(self.cache_ttl * 1.5)
        else:
            # Simple queries, standard TTL
            cache_config['ttl'] = self.cache_ttl
        
        # Disable cache for very specific queries (likely unique)
        if len(query) > 50 or query.count('"') >= 2:
            cache_config['enabled'] = False
            self.logger.info(f"Disabled cache for long/specific query: {query[:50]}...")
        
        return cache_config
    
    def analyze_search_performance(self, search_id: str, metrics: PerformanceMetrics) -> Dict[str, Any]:
        """
        Analyze search performance and provide optimization recommendations.
        
        Args:
            search_id: Unique search identifier
            metrics: Performance metrics
            
        Returns:
            Performance analysis and recommendations
        """
        analysis = {
            'search_id': search_id,
            'performance_score': self._calculate_performance_score(metrics),
            'recommendations': [],
            'metrics': {
                'total_time': metrics.total_time,
                'cache_hit_rate': metrics.cache_hits / max(metrics.cache_hits + metrics.cache_misses, 1),
                'results_per_second': metrics.results_count / max(metrics.total_time, 0.1),
                'memory_efficiency': metrics.results_count / max(metrics.memory_usage_mb, 0.1)
            }
        }
        
        # Generate recommendations
        if metrics.total_time > 10.0:
            analysis['recommendations'].append("Consider reducing search scope or increasing cache TTL")
        
        if metrics.cache_hits / max(metrics.cache_hits + metrics.cache_misses, 1) < 0.1:
            analysis['recommendations'].append("Low cache hit rate - consider adjusting cache strategy")
        
        if metrics.memory_usage_mb > 100:
            analysis['recommendations'].append("High memory usage - consider reducing max_results")
        
        if metrics.parallel_searches < self.max_workers:
            analysis['recommendations'].append("Consider increasing parallel searches for better performance")
        
        self.logger.info(f"Performance analysis for {search_id}: score={analysis['performance_score']:.2f}, recommendations={len(analysis['recommendations'])}")
        
        return analysis
    
    def _calculate_performance_score(self, metrics: PerformanceMetrics) -> float:
        """
        Calculate a performance score (0-100) based on metrics.
        
        Args:
            metrics: Performance metrics
            
        Returns:
            Performance score (0-100, higher is better)
        """
        # Base score starts at 50
        score = 50.0
        
        # Time factor (faster is better)
        if metrics.total_time < 1.0:
            score += 20
        elif metrics.total_time < 5.0:
            score += 10
        elif metrics.total_time > 30.0:
            score -= 20
        
        # Cache efficiency factor
        cache_rate = metrics.cache_hits / max(metrics.cache_hits + metrics.cache_misses, 1)
        score += cache_rate * 15
        
        # Memory efficiency factor
        if metrics.memory_usage_mb < 50:
            score += 10
        elif metrics.memory_usage_mb > 200:
            score -= 15
        
        # Results efficiency factor
        results_per_second = metrics.results_count / max(metrics.total_time, 0.1)
        if results_per_second > 10:
            score += 5
        
        return max(0, min(100, score))
    
    def _record_performance(self, metrics: PerformanceMetrics):
        """Record performance metrics for historical analysis."""
        with self.lock:
            self.performance_history.append(metrics)
            self.total_searches += 1
            self.total_cache_hits += metrics.cache_hits
            self.total_cache_misses += metrics.cache_misses
            
            # Keep only last 100 entries to prevent memory bloat
            if len(self.performance_history) > 100:
                self.performance_history = self.performance_history[-100:]
            
            # Update average search time
            total_time = sum(m.total_time for m in self.performance_history)
            self.avg_search_time = total_time / len(self.performance_history)
    
    def _get_memory_usage(self) -> float:
        """
        Get current memory usage in MB.
        
        Returns:
            Memory usage in MB
        """
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024  # Convert to MB
        except ImportError:
            # psutil not available, return estimated value
            return 50.0  # Conservative estimate
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """
        Get overall performance statistics.
        
        Returns:
            Performance statistics
        """
        with self.lock:
            if not self.performance_history:
                return {
                    'total_searches': 0,
                    'avg_search_time': 0.0,
                    'cache_hit_rate': 0.0,
                    'avg_memory_usage': 0.0
                }
            
            total_cache_ops = self.total_cache_hits + self.total_cache_misses
            cache_hit_rate = self.total_cache_hits / max(total_cache_ops, 1)
            
            avg_memory = sum(m.memory_usage_mb for m in self.performance_history) / len(self.performance_history)
            
            return {
                'total_searches': self.total_searches,
                'avg_search_time': self.avg_search_time,
                'cache_hit_rate': cache_hit_rate,
                'avg_memory_usage': avg_memory,
                'recent_performance': [
                    {
                        'timestamp': time.time(),
                        'score': self._calculate_performance_score(m)
                    }
                    for m in self.performance_history[-10:]  # Last 10 searches
                ]
            }


# Global search optimizer instance
search_optimizer = SearchOptimizer()
