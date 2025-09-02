"""
Unit tests for the search engine module.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from app.search_engine import SearchEngine, SearchConfig, SearchProgress
from app.result_collector import SearchResult
from app.engine_manager import EngineSelection


class TestSearchConfig:
    """Test SearchConfig dataclass."""
    
    def test_search_config_defaults(self):
        """Test SearchConfig with default values."""
        config = SearchConfig(query="test")
        
        assert config.query == "test"
        assert config.case_sensitive is False
        assert config.search_in_keys is True
        assert config.search_in_values is True
        assert config.search_in_metadata is False
        assert config.max_results == 1000
        assert config.timeout == 300
        assert config.max_depth == 10
        assert config.include_secret_data is False
        assert config.parallel_searches == 5
    
    def test_search_config_custom_values(self):
        """Test SearchConfig with custom values."""
        config = SearchConfig(
            query="test",
            case_sensitive=True,
            search_in_keys=False,
            search_in_values=True,
            max_results=500,
            max_depth=5
        )
        
        assert config.query == "test"
        assert config.case_sensitive is True
        assert config.search_in_keys is False
        assert config.search_in_values is True
        assert config.max_results == 500
        assert config.max_depth == 5


class TestSearchProgress:
    """Test SearchProgress dataclass."""
    
    def test_search_progress_defaults(self):
        """Test SearchProgress with default values."""
        progress = SearchProgress(total_engines=5)
        
        assert progress.total_engines == 5
        assert progress.completed_engines == 0
        assert progress.current_engine == ""
        assert progress.total_paths_searched == 0
        assert progress.total_secrets_found == 0
        assert progress.errors == []
        assert progress.warnings == []
    
    def test_progress_percentage(self):
        """Test progress percentage calculation."""
        progress = SearchProgress(total_engines=10)
        
        # 0% when no engines completed
        assert progress.progress_percentage == 0.0
        
        # 50% when half completed
        progress.completed_engines = 5
        assert progress.progress_percentage == 50.0
        
        # 100% when all completed
        progress.completed_engines = 10
        assert progress.progress_percentage == 100.0
    
    def test_elapsed_time(self):
        """Test elapsed time calculation."""
        progress = SearchProgress(total_engines=5)
        
        # Should be a positive number
        assert progress.elapsed_time >= 0


class TestSearchEngine:
    """Test SearchEngine class."""
    
    @pytest.fixture
    def mock_vault_client(self):
        """Create a mock Vault client."""
        client = Mock()
        client.client = Mock()
        return client
    
    @pytest.fixture
    def mock_engine_manager(self):
        """Create a mock engine manager."""
        manager = Mock()
        return manager
    
    @pytest.fixture
    def search_engine(self, mock_vault_client, mock_engine_manager):
        """Create a SearchEngine instance with mocked dependencies."""
        return SearchEngine(mock_vault_client, mock_engine_manager)
    
    @pytest.fixture
    def mock_session(self):
        """Create a mock session."""
        return {
            'selected_engines': ['/secret', '/kv'],
            'engine_selection_state': {
                'selected_engines': [
                    {
                        'path': '/secret',
                        'type': 'kv',
                        'selected_at': datetime.now().isoformat(),
                        'selected_by': 'test_user',
                        'priority': 0,
                        'notes': ''
                    },
                    {
                        'path': '/kv',
                        'type': 'kv',
                        'selected_at': datetime.now().isoformat(),
                        'selected_by': 'test_user',
                        'priority': 0,
                        'notes': ''
                    }
                ],
                'last_updated': datetime.now().isoformat(),
                'version': '1.0',
                'metadata': {}
            }
        }
    
    def test_search_engine_initialization(self, search_engine):
        """Test SearchEngine initialization."""
        assert search_engine.vault_client is not None
        assert search_engine.engine_manager is not None
        assert search_engine.search_algorithms is not None
        assert search_engine.result_collector is not None
    
    def test_search_no_engines_selected(self, search_engine, mock_session):
        """Test search with no engines selected."""
        # Mock engine manager to return no selected engines
        search_engine.engine_manager.get_selected_paths.return_value = []
        
        config = SearchConfig(query="test")
        
        with pytest.raises(ValueError, match="No engines selected for search"):
            search_engine.search(config, mock_session)
    
    def test_search_with_engines(self, search_engine, mock_session):
        """Test search with engines selected."""
        # Mock engine manager to return selected engines
        search_engine.engine_manager.get_selected_paths.return_value = ['/secret']
        search_engine.engine_manager.load_selection_state.return_value = Mock(
            selected_engines=[
                EngineSelection(
                    path='/secret',
                    type='kv',
                    selected_at=datetime.now(),
                    selected_by='test_user'
                )
            ]
        )
        
        # Mock the search methods
        search_engine._search_engines = Mock(return_value=[])
        
        config = SearchConfig(query="test")
        results = search_engine.search(config, mock_session)
        
        assert results == []
        search_engine._search_engines.assert_called_once()
    
    def test_discover_paths(self, search_engine):
        """Test path discovery."""
        # Mock the Vault client response
        search_engine.vault_client.client.secrets.kv.v2.list_secrets.return_value = {
            'data': {'keys': ['path1', 'path2']}
        }
        
        paths = search_engine._discover_paths('/secret', max_depth=2)
        
        # Should include the base path and sub-paths
        assert '/secret' in paths
        assert '/secret/path1' in paths
        assert '/secret/path2' in paths
    
    def test_discover_paths_no_sub_paths(self, search_engine):
        """Test path discovery when no sub-paths exist."""
        # Mock the Vault client to return no sub-paths
        search_engine.vault_client.client.secrets.kv.v2.list_secrets.return_value = None
        
        paths = search_engine._discover_paths('/secret', max_depth=2)
        
        # Should only include the base path
        assert paths == ['/secret']
    
    def test_read_secret(self, search_engine):
        """Test reading a secret from Vault."""
        # Mock the Vault client response
        search_engine.vault_client.client.secrets.kv.v2.read_secret_version.return_value = {
            'data': {
                'data': {
                    'key1': 'value1',
                    'key2': 'value2'
                }
            }
        }
        
        secret_data = search_engine._read_secret('/secret/test')
        
        assert secret_data == {'key1': 'value1', 'key2': 'value2'}
    
    def test_read_secret_not_found(self, search_engine):
        """Test reading a secret that doesn't exist."""
        # Mock the Vault client to return None
        search_engine.vault_client.client.secrets.kv.v2.read_secret_version.return_value = None
        
        secret_data = search_engine._read_secret('/secret/test')
        
        assert secret_data is None
    
    def test_search_secret_data_key_match(self, search_engine):
        """Test searching secret data for key matches."""
        secret_data = {'test_key': 'test_value', 'other_key': 'other_value'}
        config = SearchConfig(query="test", search_in_keys=True, search_in_values=False)
        
        results = search_engine._search_secret_data('/secret/test', secret_data, config, 'kv')
        
        assert len(results) == 1
        assert results[0].key == 'test_key'
        assert results[0].match_type == 'key'
    
    def test_search_secret_data_value_match(self, search_engine):
        """Test searching secret data for value matches."""
        secret_data = {'key1': 'test_value', 'key2': 'other_value'}
        config = SearchConfig(query="test", search_in_keys=False, search_in_values=True)
        
        results = search_engine._search_secret_data('/secret/test', secret_data, config, 'kv')
        
        assert len(results) == 1
        assert results[0].key == 'key1'
        assert results[0].match_type == 'value'
    
    def test_search_secret_data_no_matches(self, search_engine):
        """Test searching secret data with no matches."""
        secret_data = {'key1': 'value1', 'key2': 'value2'}
        config = SearchConfig(query="nonexistent", search_in_keys=True, search_in_values=True)
        
        results = search_engine._search_secret_data('/secret/test', secret_data, config, 'kv')
        
        assert len(results) == 0
    
    def test_get_engine_path(self, search_engine):
        """Test extracting engine path from secret path."""
        # Test with simple path
        engine_path = search_engine._get_engine_path('/secret/test/path')
        assert engine_path == '/secret'
        
        # Test with root path
        engine_path = search_engine._get_engine_path('/secret')
        assert engine_path == '/secret'
        
        # Test with empty path
        engine_path = search_engine._get_engine_path('')
        assert engine_path == '/'
    
    def test_search_single_engine_success(self, search_engine):
        """Test searching a single engine successfully."""
        engine = EngineSelection(
            path='/secret',
            type='kv',
            selected_at=datetime.now(),
            selected_by='test_user'
        )
        config = SearchConfig(query="test")
        
        # Mock the path discovery and search methods
        search_engine._discover_paths = Mock(return_value=['/secret/path1'])
        search_engine._search_path = Mock(return_value=[])
        
        results = search_engine._search_single_engine(engine, config)
        
        assert results == []
        search_engine._discover_paths.assert_called_once_with('/secret', max_depth=10)
        search_engine._search_path.assert_called_once_with('/secret/path1', config, 'kv')
    
    def test_search_single_engine_exception(self, search_engine):
        """Test searching a single engine with exception."""
        engine = EngineSelection(
            path='/secret',
            type='kv',
            selected_at=datetime.now(),
            selected_by='test_user'
        )
        config = SearchConfig(query="test")
        
        # Mock the path discovery to raise an exception
        search_engine._discover_paths = Mock(side_effect=Exception("Test error"))
        
        with pytest.raises(Exception, match="Test error"):
            search_engine._search_single_engine(engine, config)
