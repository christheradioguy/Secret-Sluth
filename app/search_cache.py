"""
Search Cache Implementation for Secret Sluth.

This module provides caching functionality for search results to improve
performance and reduce redundant Vault API calls.
"""

import hashlib
import json
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import OrderedDict
import threading

from app.logging_config import get_logger
from app.result_collector import SearchResult

logger = get_logger(__name__)


@dataclass
class CacheEntry:
    """Represents a cached search result."""
    query_hash: str
    results: List[Dict[str, Any]]
    config: Dict[str, Any]
    timestamp: float
    expires_at: float
    hit_count: int = 0
    last_accessed: float = 0
    
    def is_expired(self) -> bool:
        """Check if the cache entry has expired."""
        return time.time() > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CacheEntry':
        """Create from dictionary."""
        return cls(**data)


class SearchCache:
    """
    LRU cache for search results with configurable expiration and size limits.
    """
    
    def __init__(self, max_size: int = 100, default_ttl: int = 3600):
        """
        Initialize the search cache.
        
        Args:
            max_size: Maximum number of cache entries
            default_ttl: Default time-to-live in seconds (1 hour)
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.lock = threading.RLock()
        self.logger = get_logger(__name__)
        
        # Statistics
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        
    def _generate_cache_key(self, query: str, config: Dict[str, Any]) -> str:
        """
        Generate a unique cache key for a search query and configuration.
        
        Args:
            query: Search query
            config: Search configuration
            
        Returns:
            Unique cache key
        """
        # Create a hash of the query and relevant config parameters
        cache_data = {
            'query': query,
            'case_sensitive': config.get('case_sensitive', False),
            'search_in_names': config.get('search_in_names', True),
            'search_in_keys': config.get('search_in_keys', True),
            'search_in_values': config.get('search_in_values', True),
            'search_in_metadata': config.get('search_in_metadata', False),
            'max_depth': config.get('max_depth', 10),
            'include_secret_data': config.get('include_secret_data', False)
        }
        
        # Only include engines if they exist in the config
        if 'engines' in config:
            cache_data['engines'] = sorted(config['engines'])
        
        cache_string = json.dumps(cache_data, sort_keys=True)
        return hashlib.sha256(cache_string.encode()).hexdigest()
    
    def get(self, query: str, config: Dict[str, Any]) -> Optional[List[SearchResult]]:
        """
        Retrieve cached results for a search query.
        
        Args:
            query: Search query
            config: Search configuration
            
        Returns:
            List of search results if found and not expired, None otherwise
        """
        cache_key = self._generate_cache_key(query, config)
        
        with self.lock:
            if cache_key in self.cache:
                entry = self.cache[cache_key]
                
                # Check if expired
                if entry.is_expired():
                    self.logger.debug(f"Cache entry expired for query: {query[:50]}...")
                    del self.cache[cache_key]
                    self.misses += 1
                    return None
                
                # Update access statistics
                entry.hit_count += 1
                entry.last_accessed = time.time()
                
                # Move to end (LRU)
                self.cache.move_to_end(cache_key)
                
                self.hits += 1
                self.logger.debug(f"Cache hit for query: {query[:50]}...")
                
                # Convert back to SearchResult objects
                results = []
                for result_dict in entry.results:
                    result = SearchResult(
                        path=result_dict['path'],
                        key=result_dict['key'],
                        value=result_dict['value'],
                        match_type=result_dict['match_type'],
                        match_context=result_dict['match_context'],
                        engine_path=result_dict['engine_path'],
                        timestamp=datetime.fromisoformat(result_dict['timestamp']),
                        confidence=result_dict.get('confidence', 1.0),
                        metadata=result_dict.get('metadata', {})
                    )
                    results.append(result)
                
                return results
            else:
                self.misses += 1
                self.logger.debug(f"Cache miss for query: {query[:50]}...")
                return None
    
    def set(self, query: str, config: Dict[str, Any], results: List[SearchResult], 
            ttl: Optional[int] = None) -> None:
        """
        Store search results in the cache.
        
        Args:
            query: Search query
            config: Search configuration
            results: Search results to cache
            ttl: Time-to-live in seconds (uses default if None)
        """
        if ttl is None:
            ttl = self.default_ttl
        
        cache_key = self._generate_cache_key(query, config)
        current_time = time.time()
        
        with self.lock:
            # Convert SearchResult objects to dictionaries
            results_dict = [result.to_dict() for result in results]
            
            entry = CacheEntry(
                query_hash=cache_key,
                results=results_dict,
                config=config,
                timestamp=current_time,
                expires_at=current_time + ttl,
                hit_count=0,
                last_accessed=current_time
            )
            
            # Remove if already exists
            if cache_key in self.cache:
                del self.cache[cache_key]
            
            # Add new entry
            self.cache[cache_key] = entry
            
            # Enforce size limit
            if len(self.cache) > self.max_size:
                self._evict_lru()
            
            self.logger.debug(f"Cached {len(results)} results for query: {query[:50]}...")
    
    def _evict_lru(self) -> None:
        """Evict the least recently used cache entry."""
        if self.cache:
            # Remove the first (oldest) entry
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
            self.evictions += 1
            self.logger.debug(f"Evicted cache entry: {oldest_key}")
    
    def clear(self) -> None:
        """Clear all cached entries."""
        with self.lock:
            cleared_count = len(self.cache)
            self.cache.clear()
            self.logger.info(f"Cleared {cleared_count} cache entries")
    
    def cleanup_expired(self) -> int:
        """
        Remove expired cache entries.
        
        Returns:
            Number of entries removed
        """
        removed_count = 0
        
        with self.lock:
            expired_keys = [
                key for key, entry in self.cache.items()
                if entry.is_expired()
            ]
            
            for key in expired_keys:
                del self.cache[key]
                removed_count += 1
            
            if removed_count > 0:
                self.logger.info(f"Cleaned up {removed_count} expired cache entries")
        
        return removed_count
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        with self.lock:
            total_requests = self.hits + self.misses
            hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0
            
            return {
                'size': len(self.cache),
                'max_size': self.max_size,
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate': hit_rate,
                'evictions': self.evictions,
                'total_requests': total_requests
            }
    
    def get_cache_info(self) -> List[Dict[str, Any]]:
        """
        Get information about all cache entries.
        
        Returns:
            List of cache entry information
        """
        with self.lock:
            cache_info = []
            current_time = time.time()
            
            for key, entry in self.cache.items():
                info = {
                    'query_hash': key,
                    'timestamp': entry.timestamp,
                    'expires_at': entry.expires_at,
                    'age_seconds': current_time - entry.timestamp,
                    'time_to_expiry': entry.expires_at - current_time,
                    'hit_count': entry.hit_count,
                    'last_accessed': entry.last_accessed,
                    'result_count': len(entry.results),
                    'is_expired': entry.is_expired()
                }
                cache_info.append(info)
            
            return cache_info


# Global cache instance
search_cache = SearchCache()
