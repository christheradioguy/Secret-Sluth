"""
Unit tests for authentication routes.

This module tests the authentication flow, session management, and logout functionality.
"""

import pytest
from unittest.mock import patch, MagicMock
from flask import session
from app import create_app
from app.session_manager import session_manager


@pytest.fixture
def app():
    """Create a test Flask application."""
    app = create_app()
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    return app


@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """Create a test runner."""
    return app.test_cli_runner()


class TestAuthRoutes:
    """Test authentication routes functionality."""
    
    def test_login_get_not_authenticated(self, client):
        """Test GET /auth/login when not authenticated."""
        response = client.get('/auth/login')
        assert response.status_code == 200
        assert b'Vault Authentication' in response.data
        assert b'Vault Server URL' in response.data
        assert b'Vault Token' in response.data
    
    def test_login_get_already_authenticated(self, client):
        """Test GET /auth/login when already authenticated."""
        with client.session_transaction() as sess:
            sess['connected'] = True
            sess['vault_url'] = 'https://vault.example.com'
        
        response = client.get('/auth/login', follow_redirects=True)
        assert response.status_code == 200
        # Should redirect to dashboard
        assert b'Dashboard' in response.data
    
    def test_login_post_missing_url(self, client):
        """Test POST /auth/login with missing Vault URL."""
        response = client.post('/auth/login', data={'vault_token': 'test-token'})
        assert response.status_code == 200
        assert b'Vault URL is required' in response.data
    
    def test_login_post_missing_token(self, client):
        """Test POST /auth/login with missing Vault token."""
        response = client.post('/auth/login', data={'vault_url': 'https://vault.example.com'})
        assert response.status_code == 200
        assert b'Vault token is required' in response.data
    
    @patch('app.routes.auth.VaultClient')
    def test_login_post_success(self, mock_vault_client, client):
        """Test successful POST /auth/login."""
        # Mock Vault client
        mock_client = MagicMock()
        mock_client.validate_token.return_value = {
            'id': 'test-token-id',
            'policies': ['default', 'admin'],
            'ttl': 3600,
            'creation_time': 1234567890
        }
        mock_vault_client.return_value.__enter__.return_value = mock_client
        
        response = client.post('/auth/login', data={
            'vault_url': 'https://vault.example.com',
            'vault_token': 'test-token'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Successfully authenticated' in response.data
        
        # Check session was created
        with client.session_transaction() as sess:
            assert sess['connected'] is True
            assert sess['vault_url'] == 'https://vault.example.com'
            assert 'vault_token' in sess  # Token is now encrypted
            assert 'token_info' in sess
    
    @patch('app.routes.auth.VaultClient')
    def test_login_post_authentication_error(self, mock_vault_client, client):
        """Test POST /auth/login with authentication error."""
        from app.vault_client import VaultAuthenticationError
        
        # Mock Vault client to raise authentication error
        mock_client = MagicMock()
        mock_client.validate_token.side_effect = VaultAuthenticationError("Invalid token")
        mock_vault_client.return_value.__enter__.return_value = mock_client
        
        response = client.post('/auth/login', data={
            'vault_url': 'https://vault.example.com',
            'vault_token': 'invalid-token'
        })
        
        assert response.status_code == 200
        assert b'Authentication failed' in response.data
    
    def test_logout_not_authenticated(self, client):
        """Test logout when not authenticated."""
        response = client.get('/auth/logout', follow_redirects=True)
        assert response.status_code == 200
        assert b'No active session' in response.data
    
    def test_logout_authenticated(self, client):
        """Test logout when authenticated."""
        with client.session_transaction() as sess:
            sess['connected'] = True
            sess['vault_url'] = 'https://vault.example.com'
            sess['vault_token'] = 'test-token'
        
        response = client.get('/auth/logout', follow_redirects=True)
        assert response.status_code == 200
        assert b'Successfully logged out' in response.data
        
        # Check session was cleared
        with client.session_transaction() as sess:
            assert 'connected' not in sess
            assert 'vault_url' not in sess
            assert 'vault_token' not in sess
    
    def test_status_not_authenticated(self, client):
        """Test /auth/status when not authenticated."""
        response = client.get('/auth/status')
        assert response.status_code == 200
        data = response.get_json()
        assert data['authenticated'] is False
        assert data['message'] == 'Not authenticated'
    
    def test_status_authenticated(self, client):
        """Test /auth/status when authenticated."""
        with client.session_transaction() as sess:
            sess['connected'] = True
            sess['vault_url'] = 'https://vault.example.com'
            sess['token_info'] = {'id': 'test-token-id', 'policies': ['default']}
            sess['authenticated_at'] = 1234567890
        
        response = client.get('/auth/status')
        assert response.status_code == 200
        data = response.get_json()
        assert data['authenticated'] is True
        assert data['vault_url'] == 'https://vault.example.com'
        assert 'token_info' in data
    
    @patch('app.routes.auth.VaultClient')
    def test_validate_session_success(self, mock_vault_client, client):
        """Test successful session validation."""
        # Mock Vault client
        mock_client = MagicMock()
        mock_client.validate_token.return_value = {
            'id': 'test-token-id',
            'policies': ['default'],
            'ttl': 3600
        }
        mock_vault_client.return_value.__enter__.return_value = mock_client
        
        with client.session_transaction() as sess:
            sess['connected'] = True
            sess['vault_url'] = 'https://vault.example.com'
            sess['vault_token'] = 'test-token'
        
        response = client.get('/auth/validate')
        assert response.status_code == 200
        data = response.get_json()
        assert data['valid'] is True
        assert data['message'] == 'Session is valid'
    
    @patch('app.routes.auth.VaultClient')
    def test_validate_session_failure(self, mock_vault_client, client):
        """Test failed session validation."""
        from app.vault_client import VaultAuthenticationError
        
        # Mock Vault client to raise authentication error
        mock_client = MagicMock()
        mock_client.validate_token.side_effect = VaultAuthenticationError("Token expired")
        mock_vault_client.return_value.__enter__.return_value = mock_client
        
        with client.session_transaction() as sess:
            sess['connected'] = True
            sess['vault_url'] = 'https://vault.example.com'
            sess['vault_token'] = 'expired-token'
        
        response = client.get('/auth/validate')
        assert response.status_code == 401
        data = response.get_json()
        assert data['valid'] is False
        assert 'Session invalid' in data['message']


class TestSessionManager:
    """Test session manager functionality."""
    
    def test_create_session(self, app):
        """Test session creation."""
        with app.test_request_context():
            token_info = {
                'id': 'test-token-id',
                'policies': ['default'],
                'ttl': 3600
            }
            
            success = session_manager.create_session(
                'https://vault.example.com',
                'test-token',
                token_info
            )
            
            assert success is True
            assert session['connected'] is True
            assert session['vault_url'] == 'https://vault.example.com'
            assert 'vault_token' in session  # Token is now encrypted
            assert session['token_info'] == token_info
    
    def test_is_authenticated(self, app):
        """Test authentication status check."""
        with app.test_request_context():
            # Not authenticated
            assert session_manager.is_authenticated() is False
            
            # Authenticated
            session['connected'] = True
            assert session_manager.is_authenticated() is True
    
    def test_get_session_info(self, app):
        """Test getting session information."""
        with app.test_request_context():
            # Not authenticated
            assert session_manager.get_session_info() is None
            
            # Authenticated
            session['connected'] = True
            session['vault_url'] = 'https://vault.example.com'
            session['token_info'] = {'id': 'test-token-id'}
            session['authenticated_at'] = 1234567890
            session['last_activity'] = 1234567890
            
            info = session_manager.get_session_info()
            assert info is not None
            assert info['vault_url'] == 'https://vault.example.com'
            assert info['token_info']['id'] == 'test-token-id'
    
    def test_clear_session(self, app):
        """Test session clearing."""
        with app.test_request_context():
            session['connected'] = True
            session['vault_url'] = 'https://vault.example.com'
            session['vault_token'] = 'test-token'
            
            session_manager.clear_session()
            
            assert 'connected' not in session
            assert 'vault_url' not in session
            assert 'vault_token' not in session
