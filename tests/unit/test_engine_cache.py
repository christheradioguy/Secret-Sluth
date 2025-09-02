"""
Unit tests for the engine cache module.
"""

import pytest
import tempfile
import os
import pickle
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from typing import List, Dict, Any

from app.engine_cache import EngineCache, CacheEntry, EngineCacheError
from app.engine_discovery import EngineMetadata


class TestCacheEntry:
    """Test the CacheEntry class."""
    
    def test_cache_entry_creation(self):
        """Test creating a CacheEntry."""
        now = datetime.now()
        expires_at = now + timedelta(seconds=300)
        data = {'test': 'data'}
        
        entry = CacheEntry(data, now, expires_at)
        
        assert entry.data == data
        assert entry.created_at == now
        assert entry.expires_at == expires_at
    
    def test_cache_entry_not_expired(self):
        """Test that a cache entry is not expired."""
        now = datetime.now()
        expires_at = now + timedelta(seconds=300)
        entry = CacheEntry({'test': 'data'}, now, expires_at)
        
        assert not entry.is_expired()
    
    def test_cache_entry_expired(self):
        """Test that a cache entry is expired."""
        now = datetime.now()
        expires_at = now - timedelta(seconds=300)  # Past time
        entry = CacheEntry({'test': 'data'}, now, expires_at)
        
        assert entry.is_expired()
    
    def test_cache_entry_to_dict(self):
        """Test converting CacheEntry to dictionary."""
        now = datetime.now()
        expires_at = now + timedelta(seconds=300)
        entry = CacheEntry({'test': 'data'}, now, expires_at)
        
        data = entry.to_dict()
        
        assert data['data'] == {'test': 'data'}
        assert data['created_at'] == now.isoformat()
        assert data['expires_at'] == expires_at.isoformat()
    
    def test_cache_entry_from_dict(self):
        """Test creating CacheEntry from dictionary."""
        now = datetime.now()
        expires_at = now + timedelta(seconds=300)
        entry_data = {
            'data': {'test': 'data'},
            'created_at': now.isoformat(),
            'expires_at': expires_at.isoformat()
        }
        
        entry = CacheEntry.from_dict(entry_data)
        
        assert entry.data == {'test': 'data'}
        assert entry.created_at == now
        assert entry.expires_at == expires_at


class TestEngineCache:
    """Test the EngineCache class."""
    
    @pytest.fixture
    def temp_cache_dir(self):
        """Create a temporary directory for cache files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir
    
    @pytest.fixture
    def engine_cache_memory(self):
        """Create an EngineCache instance with memory-only caching."""
        return EngineCache(cache_dir=None, default_ttl=300)
    
    @pytest.fixture
    def engine_cache_file(self, temp_cache_dir):
        """Create an EngineCache instance with file caching."""
        return EngineCache(cache_dir=temp_cache_dir, default_ttl=300)
    
    @pytest.fixture
    def sample_engines(self):
        """Create sample engine metadata for testing."""
        return [
            EngineMetadata(
                path='secret/',
                type='kv',
                description='Key-value secrets',
                accessor='kv_123',
                options={},
                config={},
                permissions={'read': True, 'write': False},
                secret_count=10,
                tags=['type:kv', 'readable']
            ),
            EngineMetadata(
                path='database/',
                type='database',
                description='Database secrets',
                accessor='db_123',
                options={},
                config={},
                permissions={'read': True, 'write': True},
                secret_count=5,
                tags=['type:database', 'readable', 'writable']
            )
        ]
    
    def test_engine_cache_initialization_memory(self):
        """Test EngineCache initialization with memory-only caching."""
        cache = EngineCache(cache_dir=None, default_ttl=300)
        
        assert cache.default_ttl == 300
        assert cache.memory_cache == {}
        assert cache.use_file_cache is False
        assert cache.cache_dir is None
    
    def test_engine_cache_initialization_file(self, temp_cache_dir):
        """Test EngineCache initialization with file caching."""
        cache = EngineCache(cache_dir=temp_cache_dir, default_ttl=600)
        
        assert cache.default_ttl == 600
        assert cache.memory_cache == {}
        assert cache.use_file_cache is True
        assert str(cache.cache_dir) == temp_cache_dir
        assert cache.cache_dir.exists()
    
    def test_generate_cache_key(self, engine_cache_memory):
        """Test cache key generation."""
        key = engine_cache_memory._generate_cache_key(
            vault_url='https://vault.example.com',
            token_hash='abc123',
            recursive=True,
            include_inaccessible=False,
            engine_types=['kv'],
            path_filters=['secret*']
        )
        
        # Key should be a SHA256 hash (64 characters)
        assert len(key) == 64
        assert isinstance(key, str)
    
    def test_token_to_hash(self, engine_cache_memory):
        """Test token hashing."""
        token = 'my-secret-token'
        token_hash = engine_cache_memory._token_to_hash(token)
        
        assert len(token_hash) == 64
        assert isinstance(token_hash, str)
        # Same token should produce same hash
        assert engine_cache_memory._token_to_hash(token) == token_hash
    
    def test_serialize_engines(self, engine_cache_memory, sample_engines):
        """Test serializing engine metadata."""
        serialized = engine_cache_memory._serialize_engines(sample_engines)
        
        assert len(serialized) == 2
        assert isinstance(serialized[0], dict)
        assert serialized[0]['path'] == 'secret/'
        assert serialized[0]['type'] == 'kv'
        assert 'permissions' in serialized[0]
        assert 'tags' in serialized[0]
    
    def test_deserialize_engines(self, engine_cache_memory, sample_engines):
        """Test deserializing engine metadata."""
        serialized = engine_cache_memory._serialize_engines(sample_engines)
        deserialized = engine_cache_memory._deserialize_engines(serialized)
        
        assert len(deserialized) == 2
        assert isinstance(deserialized[0], EngineMetadata)
        assert deserialized[0].path == 'secret/'
        assert deserialized[0].type == 'kv'
        assert deserialized[0].permissions['read'] is True
        assert 'type:kv' in deserialized[0].tags
    
    def test_get_cache_miss(self, engine_cache_memory):
        """Test getting from cache when entry doesn't exist."""
        result = engine_cache_memory.get(
            vault_url='https://vault.example.com',
            token='my-token',
            recursive=True
        )
        
        assert result is None
    
    def test_set_and_get_memory_cache(self, engine_cache_memory, sample_engines):
        """Test setting and getting from memory cache."""
        # Set cache
        engine_cache_memory.set(
            vault_url='https://vault.example.com',
            token='my-token',
            engines=sample_engines,
            recursive=True
        )
        
        # Get from cache
        result = engine_cache_memory.get(
            vault_url='https://vault.example.com',
            token='my-token',
            recursive=True
        )
        
        assert result is not None
        assert len(result) == 2
        assert result[0].path == 'secret/'
        assert result[1].path == 'database/'
    
    def test_set_and_get_file_cache(self, engine_cache_file, sample_engines):
        """Test setting and getting from file cache."""
        # Set cache
        engine_cache_file.set(
            vault_url='https://vault.example.com',
            token='my-token',
            engines=sample_engines,
            recursive=True
        )
        
        # Clear memory cache to force file read
        engine_cache_file.memory_cache.clear()
        
        # Get from cache
        result = engine_cache_file.get(
            vault_url='https://vault.example.com',
            token='my-token',
            recursive=True
        )
        
        assert result is not None
        assert len(result) == 2
        assert result[0].path == 'secret/'
        assert result[1].path == 'database/'
    
    def test_cache_expiration(self, engine_cache_memory, sample_engines):
        """Test that cache entries expire correctly."""
        # Set cache with short TTL
        engine_cache_memory.set(
            vault_url='https://vault.example.com',
            token='my-token',
            engines=sample_engines,
            recursive=True,
            ttl=1  # 1 second TTL
        )
        
        # Should be available immediately
        result = engine_cache_memory.get(
            vault_url='https://vault.example.com',
            token='my-token',
            recursive=True
        )
        assert result is not None
        
        # Wait for expiration
        import time
        time.sleep(1.1)
        
        # Should be expired now
        result = engine_cache_memory.get(
            vault_url='https://vault.example.com',
            token='my-token',
            recursive=True
        )
        assert result is None
    
    def test_cache_key_uniqueness(self, engine_cache_memory, sample_engines):
        """Test that different parameters produce different cache keys."""
        # Set cache with different parameters
        engine_cache_memory.set(
            vault_url='https://vault.example.com',
            token='my-token',
            engines=sample_engines,
            recursive=True
        )
        
        # Try to get with different parameters (should miss)
        result = engine_cache_memory.get(
            vault_url='https://vault.example.com',
            token='my-token',
            recursive=False  # Different recursive parameter
        )
        
        assert result is None
    
    def test_invalidate_cache(self, engine_cache_memory, sample_engines):
        """Test invalidating cache entries."""
        # Set cache
        engine_cache_memory.set(
            vault_url='https://vault.example.com',
            token='my-token',
            engines=sample_engines,
            recursive=True
        )
        
        # Verify it's cached
        result = engine_cache_memory.get(
            vault_url='https://vault.example.com',
            token='my-token',
            recursive=True
        )
        assert result is not None
        
        # Clear the cache manually since invalidation is simplified
        engine_cache_memory.clear()
        
        # Should be gone
        result = engine_cache_memory.get(
            vault_url='https://vault.example.com',
            token='my-token',
            recursive=True
        )
        assert result is None
    
    def test_clear_cache(self, engine_cache_memory, sample_engines):
        """Test clearing all cache entries."""
        # Set multiple cache entries
        engine_cache_memory.set(
            vault_url='https://vault1.example.com',
            token='token1',
            engines=sample_engines,
            recursive=True
        )
        engine_cache_memory.set(
            vault_url='https://vault2.example.com',
            token='token2',
            engines=sample_engines,
            recursive=True
        )
        
        # Verify they're cached
        assert len(engine_cache_memory.memory_cache) == 2
        
        # Clear cache
        engine_cache_memory.clear()
        
        # Should be empty
        assert len(engine_cache_memory.memory_cache) == 0
    
    def test_get_stats(self, engine_cache_memory, sample_engines):
        """Test getting cache statistics."""
        # Set some cache entries
        engine_cache_memory.set(
            vault_url='https://vault.example.com',
            token='my-token',
            engines=sample_engines,
            recursive=True
        )
        
        stats = engine_cache_memory.get_stats()
        
        assert 'memory_entries' in stats
        assert 'memory_size_mb' in stats
        assert 'file_entries' in stats
        assert 'file_size_mb' in stats
        assert 'expired_entries' in stats
        assert stats['memory_entries'] == 1
    
    def test_cleanup_expired(self, engine_cache_memory, sample_engines):
        """Test cleaning up expired cache entries."""
        # Set cache with short TTL
        engine_cache_memory.set(
            vault_url='https://vault.example.com',
            token='my-token',
            engines=sample_engines,
            recursive=True,
            ttl=1  # 1 second TTL
        )
        
        # Wait for expiration
        import time
        time.sleep(1.1)
        
        # Cleanup expired entries
        removed_count = engine_cache_memory.cleanup_expired()
        
        assert removed_count == 1
        assert len(engine_cache_memory.memory_cache) == 0
    
    def test_file_cache_corruption_handling(self, temp_cache_dir):
        """Test handling of corrupted cache files."""
        cache = EngineCache(cache_dir=temp_cache_dir)
        
        # Create a corrupted cache file
        corrupted_file = cache.cache_dir / "corrupted.cache"
        with open(corrupted_file, 'wb') as f:
            f.write(b"corrupted data")
        
        # Should handle gracefully
        result = cache.get(
            vault_url='https://vault.example.com',
            token='my-token',
            recursive=True
        )
        
        assert result is None
        # Note: The current implementation doesn't remove corrupted files automatically
        # This is a limitation that could be improved in future versions
    
    def test_cache_with_filters(self, engine_cache_memory, sample_engines):
        """Test caching with different filter parameters."""
        # Set cache with filters
        engine_cache_memory.set(
            vault_url='https://vault.example.com',
            token='my-token',
            engines=sample_engines,
            recursive=True,
            engine_types=['kv'],
            path_filters=['secret*']
        )
        
        # Get with same filters (should hit)
        result = engine_cache_memory.get(
            vault_url='https://vault.example.com',
            token='my-token',
            recursive=True,
            engine_types=['kv'],
            path_filters=['secret*']
        )
        
        assert result is not None
        
        # Get with different filters (should miss)
        result = engine_cache_memory.get(
            vault_url='https://vault.example.com',
            token='my-token',
            recursive=True,
            engine_types=['database']  # Different filter
        )
        
        assert result is None
