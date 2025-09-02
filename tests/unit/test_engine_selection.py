"""
Unit tests for engine selection functionality.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from flask import session
from app.routes.engines import engines


@pytest.fixture
def app():
    """Create a test Flask app."""
    from app import create_app
    from app.config import TestingConfig
    return create_app(TestingConfig)

@pytest.fixture
def client(app):
    """Create a test client for the engines blueprint."""
    return app.test_client()


@pytest.fixture
def mock_session_manager():
    """Mock session manager."""
    with patch('app.routes.engines.session_manager') as mock, \
         patch('app.middleware.auth_middleware.session_manager') as auth_mock:
        # Create a mock vault client with context manager methods
        mock_vault_client = Mock()
        mock_vault_client.__enter__ = Mock(return_value=mock_vault_client)
        mock_vault_client.__exit__ = Mock(return_value=None)
        
        mock.get_vault_client.return_value = mock_vault_client
        mock.get_session_info.return_value = {
            'vault_url': 'https://vault.example.com'
        }
        mock.is_authenticated.return_value = True
        mock.validate_session.return_value = True
        
        auth_mock.is_authenticated.return_value = True
        auth_mock.validate_session.return_value = True
        
        yield mock


@pytest.fixture
def mock_engine_discovery():
    """Mock engine discovery."""
    with patch('app.routes.engines.EngineDiscovery') as mock:
        instance = Mock()
        instance.discover_engines.return_value = [
            Mock(path='secret/', type='kv', description='KV Store', 
                 permissions={'read': True, 'write': False, 'delete': False, 'list': True},
                 secret_count=10, tags=['type:kv', 'readable']),
            Mock(path='database/', type='database', description='Database', 
                 permissions={'read': True, 'write': True, 'delete': False, 'list': True},
                 secret_count=None, tags=['type:database', 'readable', 'writable'])
        ]
        mock.return_value = instance
        yield mock


@pytest.fixture
def mock_engine_cache():
    """Mock engine cache."""
    with patch('app.routes.engines.EngineCache') as mock:
        instance = Mock()
        instance.get.return_value = None  # No cached data
        mock.return_value = instance
        yield mock


@pytest.fixture
def mock_security_manager():
    """Mock security manager."""
    with patch('app.security.security_manager') as mock:
        mock.decrypt_token.return_value = 'decrypted-token'
        yield mock


class TestEngineSelection:
    """Test engine selection routes."""

    def test_select_engines_page_loads(self, client, mock_session_manager, 
                                     mock_engine_discovery, mock_engine_cache, 
                                     mock_security_manager):
        """Test that the engine selection page loads correctly."""
        with client.session_transaction() as sess:
            sess['vault_token'] = 'encrypted-token'
        
        response = client.get('/engines/select')
        assert response.status_code == 200
        assert b'Select Secret Engines' in response.data

    def test_select_engines_with_cached_data(self, client, mock_session_manager, 
                                           mock_engine_discovery, mock_engine_cache, 
                                           mock_security_manager):
        """Test that cached engine data is used when available."""
        # Mock cached data
        cached_engines = [
            Mock(path='secret/', type='kv', description='KV Store', 
                 permissions={'read': True, 'write': False, 'delete': False, 'list': True},
                 secret_count=10, tags=['type:kv', 'readable'])
        ]
        mock_engine_cache.return_value.get.return_value = cached_engines
        
        with client.session_transaction() as sess:
            sess['vault_token'] = 'encrypted-token'
        
        response = client.get('/engines/select')
        assert response.status_code == 200
        
        # Verify cache was used
        mock_engine_cache.return_value.get.assert_called_once()

    def test_update_selection_success(self, client, mock_session_manager, 
                                    mock_engine_discovery, mock_security_manager):
        """Test successful engine selection update."""
        with client.session_transaction() as sess:
            sess['vault_token'] = 'encrypted-token'
        
        response = client.post('/engines/select', data={
            'selected_engines[]': ['secret/', 'database/']
        })
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'success'
        assert data['selected_count'] == 2

    def test_update_selection_invalid_engine(self, client, mock_session_manager, 
                                           mock_engine_discovery, mock_security_manager):
        """Test that invalid engine selection is rejected."""
        with client.session_transaction() as sess:
            sess['vault_token'] = 'encrypted-token'
        
        response = client.post('/engines/select', data={
            'selected_engines[]': ['invalid-engine/']
        })
        
        assert response.status_code == 400
        data = response.get_json()
        assert data['status'] == 'error'
        assert 'Validation failed' in data['message']

    def test_get_selection_status(self, client, mock_session_manager, 
                                mock_engine_discovery, mock_security_manager):
        """Test getting selection status."""
        with client.session_transaction() as sess:
            sess['vault_token'] = 'encrypted-token'
            sess['selected_engines'] = ['secret/']
        
        response = client.get('/engines/selection/status')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'success'
        assert data['selected_count'] == 1
        assert len(data['selected_engines']) == 1

    def test_select_engines_no_token(self, client):
        """Test that engine selection requires authentication."""
        response = client.get('/engines/select')
        assert response.status_code == 302  # Redirect to login

    def test_update_selection_no_token(self, client):
        """Test that selection update requires authentication."""
        response = client.post('/engines/select', data={
            'selected_engines[]': ['secret/']
        })
        assert response.status_code == 302  # Redirect to login

    def test_get_status_no_token(self, client):
        """Test that status check requires authentication."""
        response = client.get('/engines/selection/status')
        assert response.status_code == 302  # Redirect to login

    def test_engine_discovery_error(self, client, mock_session_manager, 
                                  mock_engine_discovery, mock_engine_cache, 
                                  mock_security_manager):
        """Test handling of engine discovery errors."""
        from app.engine_discovery import EngineDiscoveryError
        
        mock_engine_discovery.return_value.discover_engines.side_effect = EngineDiscoveryError("Discovery failed")
        
        with client.session_transaction() as sess:
            sess['vault_token'] = 'encrypted-token'
        
        response = client.get('/engines/select')
        assert response.status_code == 400
        # The error is handled by the template, so we check for the error page
        assert response.status_code == 400

    def test_vault_client_error(self, client, mock_session_manager, 
                              mock_engine_discovery, mock_engine_cache, 
                              mock_security_manager):
        """Test handling of Vault client errors."""
        mock_session_manager.get_vault_client.return_value = None
        
        with client.session_transaction() as sess:
            sess['vault_token'] = 'encrypted-token'
        
        response = client.get('/engines/select')
        assert response.status_code == 400
        # The error is handled by the template, so we check for the error page
        assert response.status_code == 400
