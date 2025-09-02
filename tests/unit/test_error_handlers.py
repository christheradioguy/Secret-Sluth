"""
Unit tests for error handlers module.

This module tests error handling, user-friendly error messages, and structured logging.
"""

import pytest
from unittest.mock import patch, MagicMock
from app import create_app
from app.error_handlers import (
    SecretSluthError, VaultError, AuthenticationError, 
    ValidationError, SearchError, get_user_friendly_message
)
from app.vault_client import VaultAuthenticationError, VaultConnectionError


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


class TestErrorClasses:
    """Test custom error classes."""
    
    def test_secret_sluth_error(self):
        """Test base SecretSluthError class."""
        error = SecretSluthError("Test error message", "TEST_ERROR", {"detail": "test"})
        
        assert str(error) == "Test error message"
        assert error.message == "Test error message"
        assert error.error_code == "TEST_ERROR"
        assert error.details == {"detail": "test"}
        
        # Test to_dict method
        error_dict = error.to_dict()
        assert error_dict['error'] is True
        assert error_dict['message'] == "Test error message"
        assert error_dict['error_code'] == "TEST_ERROR"
        assert error_dict['details'] == {"detail": "test"}
    
    def test_vault_error(self):
        """Test VaultError class."""
        error = VaultError("Vault connection failed")
        assert isinstance(error, SecretSluthError)
        assert error.message == "Vault connection failed"
    
    def test_authentication_error(self):
        """Test AuthenticationError class."""
        error = AuthenticationError("Authentication required")
        assert isinstance(error, SecretSluthError)
        assert error.message == "Authentication required"
    
    def test_validation_error(self):
        """Test ValidationError class."""
        error = ValidationError("Invalid input")
        assert isinstance(error, SecretSluthError)
        assert error.message == "Invalid input"
    
    def test_search_error(self):
        """Test SearchError class."""
        error = SearchError("Search failed")
        assert isinstance(error, SecretSluthError)
        assert error.message == "Search failed"


class TestUserFriendlyMessages:
    """Test user-friendly error message generation."""
    
    def test_vault_authentication_error(self):
        """Test VaultAuthenticationError message."""
        error = VaultAuthenticationError("Invalid token")
        message = get_user_friendly_message(error)
        assert "Authentication failed" in message
        assert "check your Vault token" in message
    
    def test_vault_connection_error(self):
        """Test VaultConnectionError message."""
        error = VaultConnectionError("Connection failed")
        message = get_user_friendly_message(error)
        assert "Unable to connect" in message
        assert "check the server URL" in message
    
    def test_vault_client_error(self):
        """Test VaultClientError message."""
        from app.vault_client import VaultClientError
        error = VaultClientError("Server error")
        message = get_user_friendly_message(error)
        assert "Vault server error" in message
    
    def test_authentication_error(self):
        """Test AuthenticationError message."""
        error = AuthenticationError("Not authenticated")
        message = get_user_friendly_message(error)
        assert "Authentication required" in message
    
    def test_validation_error(self):
        """Test ValidationError message."""
        error = ValidationError("Invalid data")
        message = get_user_friendly_message(error)
        assert "Invalid input" in message
    
    def test_search_error(self):
        """Test SearchError message."""
        error = SearchError("Search failed")
        message = get_user_friendly_message(error)
        assert "Search operation failed" in message
    
    def test_http_404_error(self):
        """Test HTTP 404 error message."""
        from werkzeug.exceptions import NotFound
        error = NotFound()
        message = get_user_friendly_message(error)
        assert "page was not found" in message
    
    def test_http_403_error(self):
        """Test HTTP 403 error message."""
        from werkzeug.exceptions import Forbidden
        error = Forbidden()
        message = get_user_friendly_message(error)
        assert "Access denied" in message
    
    def test_http_500_error(self):
        """Test HTTP 500 error message."""
        from werkzeug.exceptions import InternalServerError
        error = InternalServerError()
        message = get_user_friendly_message(error)
        assert "internal server error" in message
    
    def test_unexpected_error(self):
        """Test unexpected error message."""
        error = Exception("Unexpected error")
        message = get_user_friendly_message(error)
        assert "unexpected error" in message


class TestErrorHandlers:
    """Test error handler routes."""
    
    def test_404_error_handler(self, client):
        """Test 404 error handler."""
        response = client.get('/nonexistent-page')
        assert response.status_code == 404
        assert b'Page Not Found' in response.data
    
    def test_404_api_error_handler(self, client):
        """Test 404 error handler for API routes."""
        response = client.get('/api/nonexistent')
        assert response.status_code == 404
        data = response.get_json()
        assert data['error'] is True
        assert data['error_code'] == 'NOT_FOUND'
    
    def test_403_error_handler(self, client):
        """Test 403 error handler."""
        # Create a route that raises 403
        @client.application.route('/test-403')
        def test_403():
            from werkzeug.exceptions import Forbidden
            raise Forbidden()
        
        response = client.get('/test-403')
        assert response.status_code == 403
        assert b'Access Denied' in response.data
    
    def test_500_error_handler(self, client):
        """Test 500 error handler."""
        # Create a route that raises 500
        @client.application.route('/test-500')
        def test_500():
            raise Exception("Test error")
        
        response = client.get('/test-500')
        assert response.status_code == 500
        assert b'Internal Server Error' in response.data
    
    def test_vault_error_handler(self, client):
        """Test Vault error handler."""
        # Create a route that raises VaultAuthenticationError
        @client.application.route('/test-vault-error')
        def test_vault_error():
            raise VaultAuthenticationError("Invalid token")
        
        response = client.get('/test-vault-error')
        assert response.status_code == 401
        assert b'Vault Connection Error' in response.data
    
    def test_application_error_handler(self, client):
        """Test application error handler."""
        # Create a route that raises SecretSluthError
        @client.application.route('/test-app-error')
        def test_app_error():
            raise ValidationError("Invalid input")
        
        response = client.get('/test-app-error')
        assert response.status_code == 400
        assert b'Application Error' in response.data
