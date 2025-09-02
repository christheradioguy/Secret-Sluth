"""
Unit tests for the engine discovery module.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from typing import List, Dict, Any

from app.engine_discovery import (
    EngineDiscovery, EngineMetadata, EngineDiscoveryError
)
from app.vault_client import VaultClient, VaultPermissionError


class TestEngineMetadata:
    """Test the EngineMetadata dataclass."""
    
    def test_engine_metadata_creation(self):
        """Test creating an EngineMetadata object."""
        metadata = EngineMetadata(
            path="secret/",
            type="kv",
            description="Key-value secrets",
            accessor="kv_123",
            options={},
            config={},
            permissions={'read': True, 'write': False},
            secret_count=10,
            tags=['type:kv', 'readable']
        )
        
        assert metadata.path == "secret/"
        assert metadata.type == "kv"
        assert metadata.description == "Key-value secrets"
        assert metadata.accessor == "kv_123"
        assert metadata.permissions['read'] is True
        assert metadata.permissions['write'] is False
        assert metadata.secret_count == 10
        assert 'type:kv' in metadata.tags
        assert 'readable' in metadata.tags
    
    def test_engine_metadata_to_dict(self):
        """Test converting EngineMetadata to dictionary."""
        now = datetime.now()
        metadata = EngineMetadata(
            path="secret/",
            type="kv",
            description="Test",
            accessor="kv_123",
            options={},
            config={},
            permissions={'read': True},
            last_accessed=now,
            tags=[]
        )
        
        data = metadata.to_dict()
        
        assert data['path'] == "secret/"
        assert data['type'] == "kv"
        assert data['last_accessed'] == now.isoformat()
        assert 'permissions' in data
        assert 'tags' in data


class TestEngineDiscovery:
    """Test the EngineDiscovery class."""
    
    @pytest.fixture
    def mock_vault_client(self):
        """Create a mock Vault client."""
        client = Mock(spec=VaultClient)
        client.is_connected.return_value = True
        return client
    
    @pytest.fixture
    def engine_discovery(self, mock_vault_client):
        """Create an EngineDiscovery instance with mock client."""
        return EngineDiscovery(mock_vault_client, max_workers=2, timeout=10)
    
    def test_engine_discovery_initialization(self, mock_vault_client):
        """Test EngineDiscovery initialization."""
        discovery = EngineDiscovery(mock_vault_client, max_workers=5, timeout=30)
        
        assert discovery.vault_client == mock_vault_client
        assert discovery.max_workers == 5
        assert discovery.timeout == 30
        assert discovery._discovered_engines == {}
        assert discovery._permission_cache == {}
    
    def test_create_engine_metadata(self, engine_discovery):
        """Test creating engine metadata from basic engine data."""
        engine_data = {
            'path': 'secret/',
            'type': 'kv',
            'description': 'Key-value secrets',
            'accessor': 'kv_123',
            'options': {'version': '2'},
            'config': {'max_lease_ttl': 3600}
        }
        
        metadata = engine_discovery._create_engine_metadata(engine_data)
        
        assert metadata.path == 'secret/'
        assert metadata.type == 'kv'
        assert metadata.description == 'Key-value secrets'
        assert metadata.accessor == 'kv_123'
        assert metadata.options == {'version': '2'}
        assert metadata.config == {'max_lease_ttl': 3600}
        assert metadata.permissions == {}
        assert metadata.tags == []
    
    def test_apply_filters_engine_types(self, engine_discovery):
        """Test filtering engines by type."""
        engines = [
            EngineMetadata('secret/', 'kv', '', '', {}, {}, {}),
            EngineMetadata('database/', 'database', '', '', {}, {}, {}),
            EngineMetadata('ssh/', 'ssh', '', '', {}, {}, {})
        ]
        
        filtered = engine_discovery._apply_filters(engines, engine_types=['kv', 'ssh'])
        
        assert len(filtered) == 2
        assert any(e.type == 'kv' for e in filtered)
        assert any(e.type == 'ssh' for e in filtered)
        assert not any(e.type == 'database' for e in filtered)
    
    def test_apply_filters_path_patterns(self, engine_discovery):
        """Test filtering engines by path patterns."""
        engines = [
            EngineMetadata('secret/', 'kv', '', '', {}, {}, {}),
            EngineMetadata('database/', 'database', '', '', {}, {}, {}),
            EngineMetadata('ssh/', 'ssh', '', '', {}, {}, {})
        ]
        
        filtered = engine_discovery._apply_filters(engines, path_filters=['secret*', 'ssh*'])
        
        assert len(filtered) == 2
        assert any(e.path == 'secret/' for e in filtered)
        assert any(e.path == 'ssh/' for e in filtered)
        assert not any(e.path == 'database/' for e in filtered)
    
    def test_check_engine_permissions_success(self, engine_discovery, mock_vault_client):
        """Test checking engine permissions successfully."""
        mock_vault_client.list_secrets_in_engine.return_value = ['secret1', 'secret2']
        
        permissions = engine_discovery._check_engine_permissions('secret/')
        
        assert permissions['read'] is True
        assert permissions['list'] is True
        mock_vault_client.list_secrets_in_engine.assert_called_once_with('secret/', recursive=False)
    
    def test_check_engine_permissions_failure(self, engine_discovery, mock_vault_client):
        """Test checking engine permissions when access is denied."""
        mock_vault_client.list_secrets_in_engine.side_effect = VaultPermissionError("Access denied")
        
        permissions = engine_discovery._check_engine_permissions('secret/')
        
        assert permissions['read'] is False
        assert permissions['list'] is False
        assert permissions['write'] is False
        assert permissions['delete'] is False
    
    def test_check_engine_permissions_cache(self, engine_discovery, mock_vault_client):
        """Test that permissions are cached."""
        mock_vault_client.list_secrets_in_engine.return_value = ['secret1']
        
        # First call
        permissions1 = engine_discovery._check_engine_permissions('secret/')
        
        # Second call should use cache
        permissions2 = engine_discovery._check_engine_permissions('secret/')
        
        assert permissions1 == permissions2
        # Should only be called once due to caching
        mock_vault_client.list_secrets_in_engine.assert_called_once()
    
    def test_count_secrets_in_engine(self, engine_discovery, mock_vault_client):
        """Test counting secrets in an engine."""
        mock_vault_client.list_secrets_in_engine.return_value = ['secret1', 'secret2', 'secret3']
        
        count = engine_discovery._count_secrets_in_engine('secret/')
        
        assert count == 3
        mock_vault_client.list_secrets_in_engine.assert_called_once_with('secret/', recursive=True)
    
    def test_count_secrets_in_engine_error(self, engine_discovery, mock_vault_client):
        """Test counting secrets when an error occurs."""
        mock_vault_client.list_secrets_in_engine.side_effect = Exception("Error")
        
        count = engine_discovery._count_secrets_in_engine('secret/')
        
        assert count == 0
    
    def test_generate_engine_tags(self, engine_discovery):
        """Test generating tags for an engine."""
        engine = EngineMetadata(
            'secret/', 'kv', '', '', {}, {}, 
            {'read': True, 'write': False}, 
            secret_count=15, 
            tags=[]
        )
        
        tags = engine_discovery._generate_engine_tags(engine)
        
        assert 'type:kv' in tags
        assert 'readable' in tags
        assert 'writable' not in tags
        assert 'medium' in tags  # 15 secrets = medium
        assert 'key-value' in tags
    
    def test_generate_engine_tags_empty(self, engine_discovery):
        """Test generating tags for an empty engine."""
        engine = EngineMetadata(
            'secret/', 'kv', '', '', {}, {}, 
            {'read': True, 'write': False}, 
            secret_count=0, 
            tags=[]
        )
        
        tags = engine_discovery._generate_engine_tags(engine)
        
        assert 'empty' in tags
        assert 'small' not in tags
        assert 'medium' not in tags
        assert 'large' not in tags
    
    def test_discover_engines_basic(self, engine_discovery, mock_vault_client):
        """Test basic engine discovery."""
        mock_vault_client.list_secret_engines.return_value = [
            {'path': 'secret/', 'type': 'kv', 'description': 'Test', 'accessor': 'kv_123', 'options': {}, 'config': {}}
        ]
        
        engines = engine_discovery.discover_engines(recursive=False)
        
        assert len(engines) == 1
        assert engines[0].path == 'secret/'
        assert engines[0].type == 'kv'
        mock_vault_client.list_secret_engines.assert_called_once()
    
    def test_discover_engines_recursive(self, engine_discovery, mock_vault_client):
        """Test recursive engine discovery."""
        mock_vault_client.list_secret_engines.return_value = [
            {'path': 'secret/', 'type': 'kv', 'description': 'Test', 'accessor': 'kv_123', 'options': {}, 'config': {}}
        ]
        mock_vault_client.list_secrets_in_engine.return_value = ['secret1', 'secret2']
        
        engines = engine_discovery.discover_engines(recursive=True)
        
        assert len(engines) == 1
        assert engines[0].secret_count == 2
        assert engines[0].permissions['read'] is True
    
    def test_discover_engines_with_filters(self, engine_discovery, mock_vault_client):
        """Test engine discovery with filters."""
        mock_vault_client.list_secret_engines.return_value = [
            {'path': 'secret/', 'type': 'kv', 'description': 'Test', 'accessor': 'kv_123', 'options': {}, 'config': {}},
            {'path': 'database/', 'type': 'database', 'description': 'Test', 'accessor': 'db_123', 'options': {}, 'config': {}}
        ]
        
        engines = engine_discovery.discover_engines(
            recursive=False, 
            engine_types=['kv'], 
            path_filters=['secret*']
        )
        
        assert len(engines) == 1
        assert engines[0].type == 'kv'
        assert engines[0].path == 'secret/'
    
    def test_discover_engines_error(self, engine_discovery, mock_vault_client):
        """Test engine discovery when an error occurs."""
        mock_vault_client.list_secret_engines.side_effect = Exception("Connection failed")
        
        with pytest.raises(EngineDiscoveryError, match="Engine discovery failed"):
            engine_discovery.discover_engines()
    
    def test_get_engine_by_path(self, engine_discovery):
        """Test getting an engine by path."""
        engine = EngineMetadata('secret/', 'kv', '', '', {}, {}, {})
        engine_discovery._discovered_engines['secret/'] = engine
        
        result = engine_discovery.get_engine_by_path('secret/')
        
        assert result == engine
    
    def test_get_engine_by_path_not_found(self, engine_discovery):
        """Test getting an engine by path when not found."""
        result = engine_discovery.get_engine_by_path('nonexistent/')
        
        assert result is None
    
    def test_get_engines_by_type(self, engine_discovery):
        """Test getting engines by type."""
        kv_engine = EngineMetadata('secret/', 'kv', '', '', {}, {}, {})
        db_engine = EngineMetadata('database/', 'database', '', '', {}, {}, {})
        engine_discovery._discovered_engines = {
            'secret/': kv_engine,
            'database/': db_engine
        }
        
        kv_engines = engine_discovery.get_engines_by_type('kv')
        
        assert len(kv_engines) == 1
        assert kv_engines[0].type == 'kv'
    
    def test_get_engines_by_tag(self, engine_discovery):
        """Test getting engines by tag."""
        engine = EngineMetadata('secret/', 'kv', '', '', {}, {}, {}, tags=['type:kv', 'readable'])
        engine_discovery._discovered_engines['secret/'] = engine
        
        readable_engines = engine_discovery.get_engines_by_tag('readable')
        
        assert len(readable_engines) == 1
        assert 'readable' in readable_engines[0].tags
    
    def test_get_accessible_engines(self, engine_discovery):
        """Test getting accessible engines."""
        accessible_engine = EngineMetadata('secret/', 'kv', '', '', {}, {}, {'read': True})
        inaccessible_engine = EngineMetadata('database/', 'database', '', '', {}, {}, {'read': False})
        engine_discovery._discovered_engines = {
            'secret/': accessible_engine,
            'database/': inaccessible_engine
        }
        
        accessible = engine_discovery.get_accessible_engines()
        
        assert len(accessible) == 1
        assert accessible[0].path == 'secret/'
    
    def test_clear_cache(self, engine_discovery):
        """Test clearing the permission cache."""
        engine_discovery._permission_cache['test'] = {'read': True}
        
        engine_discovery.clear_cache()
        
        assert len(engine_discovery._permission_cache) == 0
    
    def test_get_discovery_stats(self, engine_discovery):
        """Test getting discovery statistics."""
        accessible_engine = EngineMetadata('secret/', 'kv', '', '', {}, {}, {'read': True})
        inaccessible_engine = EngineMetadata('database/', 'database', '', '', {}, {}, {'read': False})
        engine_discovery._discovered_engines = {
            'secret/': accessible_engine,
            'database/': inaccessible_engine
        }
        engine_discovery._permission_cache['test'] = {'read': True}
        
        stats = engine_discovery.get_discovery_stats()
        
        assert stats['total_engines'] == 2
        assert stats['accessible_engines'] == 1
        assert stats['inaccessible_engines'] == 1
        assert stats['engine_types']['kv'] == 1
        assert stats['engine_types']['database'] == 1
        assert stats['cache_size'] == 1
