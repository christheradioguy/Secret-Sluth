"""
Engine Cache Module

This module provides caching functionality for engine discovery results to improve
performance and reduce API calls to the Vault server.
"""

import logging
import json
import pickle
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
from dataclasses import asdict
import hashlib
import os
from pathlib import Path

from .engine_discovery import EngineMetadata
from .logging_config import get_logger

logger = get_logger(__name__)


class CacheEntry:
    """Represents a cached entry with metadata."""
    
    def __init__(self, data: Any, created_at: datetime, expires_at: datetime):
        self.data = data
        self.created_at = created_at
        self.expires_at = expires_at
    
    def is_expired(self) -> bool:
        """Check if the cache entry has expired."""
        return datetime.now() > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'data': self.data,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CacheEntry':
        """Create from dictionary."""
        return cls(
            data=data['data'],
            created_at=datetime.fromisoformat(data['created_at']),
            expires_at=datetime.fromisoformat(data['expires_at'])
        )


class EngineCacheError(Exception):
    """Base exception for engine cache errors."""
    pass


class EngineCache:
    """
    Cache for engine discovery results to improve performance.
    
    This cache stores engine metadata and discovery results to avoid
    repeated API calls to the Vault server.
    """
    
    def __init__(self, cache_dir: str = None, default_ttl: int = 300):
        """
        Initialize the engine cache.
        
        Args:
            cache_dir: Directory to store cache files (None for memory-only)
            default_ttl: Default time-to-live for cache entries in seconds
        """
        self.default_ttl = default_ttl
        self.memory_cache: Dict[str, CacheEntry] = {}
        
        # File-based cache
        if cache_dir:
            self.cache_dir = Path(cache_dir)
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self.use_file_cache = True
        else:
            self.cache_dir = None
            self.use_file_cache = False
        
        logger.info(f"Initialized engine cache (file_cache: {self.use_file_cache}, ttl: {default_ttl}s)")
    
    def _generate_cache_key(self, vault_url: str, token_hash: str, 
                           recursive: bool, include_inaccessible: bool,
                           engine_types: List[str] = None, 
                           path_filters: List[str] = None) -> str:
        """Generate a unique cache key for the discovery parameters."""
        # Create a hash of the parameters
        params = {
            'vault_url': vault_url,
            'token_hash': token_hash,
            'recursive': recursive,
            'include_inaccessible': include_inaccessible,
            'engine_types': sorted(engine_types) if engine_types else None,
            'path_filters': sorted(path_filters) if path_filters else None
        }
        
        # Convert to JSON string and hash
        params_str = json.dumps(params, sort_keys=True)
        return hashlib.sha256(params_str.encode()).hexdigest()
    
    def _token_to_hash(self, token: str) -> str:
        """Convert token to a hash for caching (doesn't store the actual token)."""
        return hashlib.sha256(token.encode()).hexdigest()
    
    def get(self, vault_url: str, token: str, recursive: bool = True, 
            include_inaccessible: bool = False, engine_types: List[str] = None,
            path_filters: List[str] = None) -> Optional[List[EngineMetadata]]:
        """
        Get cached engine discovery results.
        
        Args:
            vault_url: The Vault server URL
            token: The authentication token
            recursive: Whether recursive discovery was used
            include_inaccessible: Whether inaccessible engines were included
            engine_types: Engine types filter
            path_filters: Path filters
            
        Returns:
            Cached engine metadata list or None if not found/expired
        """
        token_hash = self._token_to_hash(token)
        cache_key = self._generate_cache_key(
            vault_url, token_hash, recursive, include_inaccessible,
            engine_types, path_filters
        )
        
        # Check memory cache first
        if cache_key in self.memory_cache:
            entry = self.memory_cache[cache_key]
            if not entry.is_expired():
                logger.debug(f"Cache hit (memory): {cache_key[:8]}...")
                return self._deserialize_engines(entry.data)
            else:
                # Remove expired entry
                del self.memory_cache[cache_key]
        
        # Check file cache
        if self.use_file_cache:
            file_path = self.cache_dir / f"{cache_key}.cache"
            if file_path.exists():
                try:
                    with open(file_path, 'rb') as f:
                        entry_data = pickle.load(f)
                        entry = CacheEntry.from_dict(entry_data)
                    
                    if not entry.is_expired():
                        logger.debug(f"Cache hit (file): {cache_key[:8]}...")
                        # Also store in memory cache
                        self.memory_cache[cache_key] = entry
                        return self._deserialize_engines(entry.data)
                    else:
                        # Remove expired file
                        file_path.unlink()
                        
                except Exception as e:
                    logger.warning(f"Failed to load cache file {file_path}: {str(e)}")
                    if file_path.exists():
                        file_path.unlink()
        
        logger.debug(f"Cache miss: {cache_key[:8]}...")
        return None
    
    def set(self, vault_url: str, token: str, engines: List[EngineMetadata],
            recursive: bool = True, include_inaccessible: bool = False,
            engine_types: List[str] = None, path_filters: List[str] = None,
            ttl: int = None) -> None:
        """
        Cache engine discovery results.
        
        Args:
            vault_url: The Vault server URL
            token: The authentication token
            engines: List of engine metadata to cache
            recursive: Whether recursive discovery was used
            include_inaccessible: Whether inaccessible engines were included
            engine_types: Engine types filter
            path_filters: Path filters
            ttl: Time-to-live in seconds (None for default)
        """
        if ttl is None:
            ttl = self.default_ttl
        
        token_hash = self._token_to_hash(token)
        cache_key = self._generate_cache_key(
            vault_url, token_hash, recursive, include_inaccessible,
            engine_types, path_filters
        )
        
        # Create cache entry
        created_at = datetime.now()
        expires_at = created_at + timedelta(seconds=ttl)
        
        # Serialize engines
        serialized_data = self._serialize_engines(engines)
        entry = CacheEntry(serialized_data, created_at, expires_at)
        
        # Store in memory cache
        self.memory_cache[cache_key] = entry
        
        # Store in file cache
        if self.use_file_cache:
            try:
                file_path = self.cache_dir / f"{cache_key}.cache"
                with open(file_path, 'wb') as f:
                    pickle.dump(entry.to_dict(), f)
                logger.debug(f"Cached to file: {cache_key[:8]}...")
            except Exception as e:
                logger.warning(f"Failed to write cache file {file_path}: {str(e)}")
        
        logger.debug(f"Cached {len(engines)} engines with key {cache_key[:8]}... (ttl: {ttl}s)")
    
    def _serialize_engines(self, engines: List[EngineMetadata]) -> List[Dict[str, Any]]:
        """Serialize engine metadata for caching."""
        return [engine.to_dict() for engine in engines]
    
    def _deserialize_engines(self, data: List[Dict[str, Any]]) -> List[EngineMetadata]:
        """Deserialize engine metadata from cache."""
        engines = []
        for engine_data in data:
            # Convert datetime strings back to datetime objects
            if 'last_accessed' in engine_data and engine_data['last_accessed']:
                engine_data['last_accessed'] = datetime.fromisoformat(engine_data['last_accessed'])
            if 'created_at' in engine_data and engine_data['created_at']:
                engine_data['created_at'] = datetime.fromisoformat(engine_data['created_at'])
            
            # Create EngineMetadata object
            engine = EngineMetadata(
                path=engine_data['path'],
                type=engine_data['type'],
                description=engine_data['description'],
                accessor=engine_data['accessor'],
                options=engine_data['options'],
                config=engine_data['config'],
                permissions=engine_data['permissions'],
                secret_count=engine_data.get('secret_count'),
                last_accessed=engine_data.get('last_accessed'),
                created_at=engine_data.get('created_at'),
                tags=engine_data.get('tags', [])
            )
            engines.append(engine)
        
        return engines
    
    def invalidate(self, vault_url: str, token: str) -> None:
        """
        Invalidate all cache entries for a specific Vault server and token.
        
        Args:
            vault_url: The Vault server URL
            token: The authentication token
        """
        token_hash = self._token_to_hash(token)
        
        # Remove from memory cache
        keys_to_remove = []
        for key in self.memory_cache.keys():
            # Extract vault_url and token_hash from key (simplified approach)
            # In a real implementation, you might want to store metadata separately
            if vault_url in key or token_hash in key:
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self.memory_cache[key]
        
        # Remove from file cache
        if self.use_file_cache:
            try:
                for file_path in self.cache_dir.glob("*.cache"):
                    # This is a simplified approach - in practice, you'd need to
                    # store metadata separately to properly invalidate by vault_url/token
                    if vault_url in file_path.name or token_hash in file_path.name:
                        file_path.unlink()
                        logger.debug(f"Invalidated cache file: {file_path.name}")
            except Exception as e:
                logger.warning(f"Failed to invalidate cache files: {str(e)}")
        
        logger.info(f"Invalidated cache for {vault_url}")
    
    def clear(self) -> None:
        """Clear all cache entries."""
        self.memory_cache.clear()
        
        if self.use_file_cache:
            try:
                for file_path in self.cache_dir.glob("*.cache"):
                    file_path.unlink()
                logger.info("Cleared all cache files")
            except Exception as e:
                logger.warning(f"Failed to clear cache files: {str(e)}")
        
        logger.info("Cache cleared")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        stats = {
            'memory_entries': len(self.memory_cache),
            'memory_size_mb': 0,
            'file_entries': 0,
            'file_size_mb': 0,
            'expired_entries': 0
        }
        
        # Calculate memory cache size
        try:
            import sys
            stats['memory_size_mb'] = sys.getsizeof(self.memory_cache) / (1024 * 1024)
        except:
            pass
        
        # Count expired entries
        for entry in self.memory_cache.values():
            if entry.is_expired():
                stats['expired_entries'] += 1
        
        # File cache stats
        if self.use_file_cache:
            try:
                cache_files = list(self.cache_dir.glob("*.cache"))
                stats['file_entries'] = len(cache_files)
                
                total_size = sum(f.stat().st_size for f in cache_files)
                stats['file_size_mb'] = total_size / (1024 * 1024)
            except Exception as e:
                logger.warning(f"Failed to get file cache stats: {str(e)}")
        
        return stats
    
    def cleanup_expired(self) -> int:
        """
        Remove expired cache entries.
        
        Returns:
            Number of entries removed
        """
        removed_count = 0
        
        # Clean memory cache
        keys_to_remove = []
        for key, entry in self.memory_cache.items():
            if entry.is_expired():
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self.memory_cache[key]
            removed_count += 1
        
        # Clean file cache
        if self.use_file_cache:
            try:
                for file_path in self.cache_dir.glob("*.cache"):
                    try:
                        with open(file_path, 'rb') as f:
                            entry_data = pickle.load(f)
                            entry = CacheEntry.from_dict(entry_data)
                        
                        if entry.is_expired():
                            file_path.unlink()
                            removed_count += 1
                    except Exception:
                        # Remove corrupted cache files
                        file_path.unlink()
                        removed_count += 1
            except Exception as e:
                logger.warning(f"Failed to cleanup file cache: {str(e)}")
        
        if removed_count > 0:
            logger.info(f"Cleaned up {removed_count} expired cache entries")
        
        return removed_count
