"""
Unit tests for Vault Client implementation.

This module contains comprehensive tests for the VaultClient class,
covering connection management, authentication, and secret operations.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any

from app.vault_client import (
    VaultClient, 
    VaultClientError, 
    VaultConnectionError, 
    VaultAuthenticationError, 
    VaultPermissionError
)


class TestVaultClientInitialization:
    """Test VaultClient initialization and URL normalization."""
    
    def test_init_with_https_url(self):
        """Test initialization with HTTPS URL."""
        client = VaultClient("https://vault.example.com", "test-token")
        assert client.vault_url == "https://vault.example.com"
        assert client.token == "test-token"
        assert client.timeout == 30
    
    def test_init_with_http_url(self):
        """Test initialization with HTTP URL."""
        client = VaultClient("http://vault.example.com", "test-token")
        assert client.vault_url == "http://vault.example.com"
    
    def test_init_without_protocol(self):
        """Test initialization without protocol (should default to HTTPS)."""
        client = VaultClient("vault.example.com", "test-token")
        assert client.vault_url == "https://vault.example.com"
    
    def test_init_with_trailing_slash(self):
        """Test initialization with trailing slash (should be removed)."""
        client = VaultClient("https://vault.example.com/", "test-token")
        assert client.vault_url == "https://vault.example.com"
    
    def test_init_with_custom_timeout(self):
        """Test initialization with custom timeout."""
        client = VaultClient("https://vault.example.com", "test-token", timeout=60)
        assert client.timeout == 60


@pytest.fixture
def mock_hvac_client():
    """Create a mock hvac client."""
    mock_client = Mock()
    mock_client.is_authenticated.return_value = True
    mock_client.sys.read_health_status.return_value = {"initialized": True}
    return mock_client


class TestVaultClientConnection:
    """Test VaultClient connection management."""
    
    @patch('app.vault_client.hvac.Client')
    def test_connect_success(self, mock_hvac_class, mock_hvac_client):
        """Test successful connection to Vault."""
        mock_hvac_class.return_value = mock_hvac_client
        
        client = VaultClient("https://vault.example.com", "test-token")
        result = client.connect()
        
        assert result is True
        assert client._connection_established is True
        assert client.client == mock_hvac_client
        
        # Verify hvac client was initialized correctly
        mock_hvac_class.assert_called_once_with(
            url="https://vault.example.com",
            token="test-token",
            timeout=30
        )
    
    @patch('app.vault_client.hvac.Client')
    def test_connect_authentication_failure(self, mock_hvac_class, mock_hvac_client):
        """Test connection failure due to authentication."""
        mock_hvac_client.is_authenticated.return_value = False
        mock_hvac_class.return_value = mock_hvac_client
        
        client = VaultClient("https://vault.example.com", "test-token")
        
        with pytest.raises(VaultAuthenticationError, match="Invalid token or authentication failed"):
            client.connect()
        
        assert client._connection_established is False
    
    @patch('app.vault_client.hvac.Client')
    def test_connect_health_check_failure(self, mock_hvac_class, mock_hvac_client):
        """Test connection failure due to health check failure."""
        mock_hvac_client.sys.read_health_status.side_effect = Exception("Health check failed")
        mock_hvac_class.return_value = mock_hvac_client
        
        client = VaultClient("https://vault.example.com", "test-token")
        
        with pytest.raises(VaultConnectionError, match="Connection test failed"):
            client.connect()
    
    @patch('app.vault_client.hvac.Client')
    def test_connect_network_error(self, mock_hvac_class):
        """Test connection failure due to network error."""
        mock_hvac_class.side_effect = Exception("Network error")
        
        client = VaultClient("https://vault.example.com", "test-token")
        
        with pytest.raises(VaultConnectionError, match="Connection failed"):
            client.connect()
    
    def test_is_connected_when_not_connected(self):
        """Test is_connected when not connected."""
        client = VaultClient("https://vault.example.com", "test-token")
        assert client.is_connected() is False
    
    @patch('app.vault_client.hvac.Client')
    def test_is_connected_when_connected(self, mock_hvac_class, mock_hvac_client):
        """Test is_connected when connected."""
        mock_hvac_class.return_value = mock_hvac_client
        
        client = VaultClient("https://vault.example.com", "test-token")
        client.connect()
        
        assert client.is_connected() is True
    
    def test_disconnect(self):
        """Test disconnecting from Vault."""
        client = VaultClient("https://vault.example.com", "test-token")
        client.client = Mock()  # Simulate connected state
        
        client.disconnect()
        
        assert client.client is None
        assert client._connection_established is False


class TestVaultClientTokenValidation:
    """Test VaultClient token validation."""
    
    @pytest.fixture
    def connected_client(self, mock_hvac_client):
        """Create a connected Vault client."""
        with patch('app.vault_client.hvac.Client') as mock_hvac_class:
            mock_hvac_class.return_value = mock_hvac_client
            
            client = VaultClient("https://vault.example.com", "test-token")
            client.connect()
            return client
    
    def test_validate_token_success(self, connected_client, mock_hvac_client):
        """Test successful token validation."""
        mock_token_info = {
            'data': {
                'id': 'test-token-id',
                'policies': ['default', 'admin'],
                'ttl': 3600,
                'creation_time': 1234567890,
                'expire_time': 1234567890 + 3600,
                'num_uses': 0,
                'orphan': False,
                'renewable': True
            }
        }
        mock_hvac_client.auth.token.lookup_self.return_value = mock_token_info
        
        result = connected_client.validate_token()
        
        expected_result = {
            'id': 'test-token-id',
            'policies': ['default', 'admin'],
            'ttl': 3600,
            'creation_time': 1234567890,
            'expire_time': 1234567890 + 3600,
            'num_uses': 0,
            'orphan': False,
            'renewable': True
        }
        
        assert result == expected_result
        mock_hvac_client.auth.token.lookup_self.assert_called_once()
    
    def test_validate_token_unauthorized(self, connected_client, mock_hvac_client):
        """Test token validation with unauthorized error."""
        from hvac.exceptions import Unauthorized
        mock_hvac_client.auth.token.lookup_self.side_effect = Unauthorized("Invalid token")
        
        with pytest.raises(VaultAuthenticationError, match="Invalid or expired token"):
            connected_client.validate_token()
    
    def test_validate_token_not_connected(self):
        """Test token validation when not connected."""
        client = VaultClient("https://vault.example.com", "test-token")
        
        with pytest.raises(VaultConnectionError, match="Not connected to Vault server"):
            client.validate_token()


class TestVaultClientSecretEngines:
    """Test VaultClient secret engine operations."""
    
    @pytest.fixture
    def connected_client(self, mock_hvac_client):
        """Create a connected Vault client."""
        with patch('app.vault_client.hvac.Client') as mock_hvac_class:
            mock_hvac_class.return_value = mock_hvac_client
            
            client = VaultClient("https://vault.example.com", "test-token")
            client.connect()
            return client
    
    def test_list_secret_engines_success(self, connected_client, mock_hvac_client):
        """Test successful listing of secret engines."""
        mock_mounts = {
            'data': {
                'secret/': {
                    'type': 'kv',
                    'description': 'KV Version 2 secret engine',
                    'options': {'version': '2'},
                    'config': {'default_lease_ttl': 0},
                    'accessor': 'kv_123456'
                },
                'database/': {
                    'type': 'database',
                    'description': 'Database secret engine',
                    'options': {},
                    'config': {'default_lease_ttl': 3600},
                    'accessor': 'database_123456'
                }
            }
        }
        mock_hvac_client.sys.list_mounted_secrets_engines.return_value = mock_mounts
        
        result = connected_client.list_secret_engines()
        
        expected_result = [
            {
                'path': 'secret/',
                'type': 'kv',
                'description': 'KV Version 2 secret engine',
                'options': {'version': '2'},
                'config': {'default_lease_ttl': 0},
                'accessor': 'kv_123456'
            },
            {
                'path': 'database/',
                'type': 'database',
                'description': 'Database secret engine',
                'options': {},
                'config': {'default_lease_ttl': 3600},
                'accessor': 'database_123456'
            }
        ]
        
        assert result == expected_result
        mock_hvac_client.sys.list_mounted_secrets_engines.assert_called_once()
    
    def test_list_secret_engines_forbidden(self, connected_client, mock_hvac_client):
        """Test listing secret engines with forbidden error."""
        from hvac.exceptions import Forbidden
        mock_hvac_client.sys.list_mounted_secrets_engines.side_effect = Forbidden("Permission denied")
        
        with pytest.raises(VaultPermissionError, match="Token lacks permission to list secret engines"):
            connected_client.list_secret_engines()
    
    def test_list_secret_engines_not_connected(self):
        """Test listing secret engines when not connected."""
        client = VaultClient("https://vault.example.com", "test-token")
        
        with pytest.raises(VaultConnectionError, match="Not connected to Vault server"):
            client.list_secret_engines()


class TestVaultClientSecretOperations:
    """Test VaultClient secret operations."""
    
    @pytest.fixture
    def connected_client(self, mock_hvac_client):
        """Create a connected Vault client."""
        with patch('app.vault_client.hvac.Client') as mock_hvac_class:
            mock_hvac_class.return_value = mock_hvac_client
            
            client = VaultClient("https://vault.example.com", "test-token")
            client.connect()
            return client
    
    def test_get_secret_success(self, connected_client, mock_hvac_client):
        """Test successful secret retrieval."""
        mock_secret_response = {
            'data': {
                'data': {
                    'username': 'admin',
                    'password': 'secret123'
                }
            }
        }
        mock_hvac_client.secrets.kv.v2.read_secret_version.return_value = mock_secret_response
        
        result = connected_client.get_secret("my-secret")
        
        expected_result = {
            'username': 'admin',
            'password': 'secret123'
        }
        
        assert result == expected_result
        mock_hvac_client.secrets.kv.v2.read_secret_version.assert_called_once_with(path="my-secret")
    
    def test_get_secret_with_engine_path(self, connected_client, mock_hvac_client):
        """Test secret retrieval with specific engine path."""
        mock_secret_response = {
            'data': {
                'data': {
                    'api_key': 'abc123'
                }
            }
        }
        mock_hvac_client.secrets.kv.v2.read_secret_version.return_value = mock_secret_response
        
        result = connected_client.get_secret("my-secret", "custom-engine")
        
        expected_result = {
            'api_key': 'abc123'
        }
        
        assert result == expected_result
        mock_hvac_client.secrets.kv.v2.read_secret_version.assert_called_once_with(
            path="my-secret",
            mount_point="custom-engine"
        )
    
    def test_get_secret_forbidden(self, connected_client, mock_hvac_client):
        """Test secret retrieval with forbidden error."""
        from hvac.exceptions import Forbidden
        mock_hvac_client.secrets.kv.v2.read_secret_version.side_effect = Forbidden("Permission denied")
        
        with pytest.raises(VaultPermissionError, match="Token lacks permission to access secret"):
            connected_client.get_secret("my-secret")
    
    def test_get_secret_not_found(self, connected_client, mock_hvac_client):
        """Test secret retrieval when secret not found."""
        mock_hvac_client.secrets.kv.v2.read_secret_version.return_value = None
        
        result = connected_client.get_secret("non-existent-secret")
        
        assert result == {}


class TestVaultClientSearch:
    """Test VaultClient search functionality."""
    
    @pytest.fixture
    def connected_client(self, mock_hvac_client):
        """Create a connected Vault client."""
        with patch('app.vault_client.hvac.Client') as mock_hvac_class:
            mock_hvac_class.return_value = mock_hvac_client
            
            client = VaultClient("https://vault.example.com", "test-token")
            client.connect()
            return client
    
    def test_search_secrets_success(self, connected_client, mock_hvac_client):
        """Test successful secret search."""
        # Mock list_secret_engines
        mock_engines = {
            'data': {
                'secret/': {
                    'type': 'kv',
                    'description': 'KV Version 2 secret engine',
                    'options': {'version': '2'},
                    'config': {'default_lease_ttl': 0},
                    'accessor': 'kv_123456'
                }
            }
        }
        mock_hvac_client.sys.list_mounted_secrets_engines.return_value = mock_engines
        
        # Mock list_secrets_in_engine
        mock_list_response = {
            'data': {
                'keys': ['secret1', 'secret2']
            }
        }
        mock_hvac_client.secrets.kv.v2.list_secrets.return_value = mock_list_response
        
        # Mock get_secret responses
        mock_secret_responses = [
            {
                'data': {
                    'data': {
                        'username': 'admin',
                        'password': 'secret123'
                    }
                }
            },
            {
                'data': {
                    'data': {
                        'api_key': 'abc123',
                        'database_url': 'postgresql://localhost/db'
                    }
                }
            }
        ]
        mock_hvac_client.secrets.kv.v2.read_secret_version.side_effect = mock_secret_responses
        
        result = connected_client.search_secrets("admin")
        
        assert len(result) == 1
        assert result[0]['secret_path'] == 'secret1'
        assert result[0]['data']['username'] == 'admin'
    
    def test_search_secrets_case_insensitive(self, connected_client, mock_hvac_client):
        """Test case-insensitive secret search."""
        # Mock list_secret_engines
        mock_engines = {
            'data': {
                'secret/': {
                    'type': 'kv',
                    'description': 'KV Version 2 secret engine',
                    'options': {'version': '2'},
                    'config': {'default_lease_ttl': 0},
                    'accessor': 'kv_123456'
                }
            }
        }
        mock_hvac_client.sys.list_mounted_secrets_engines.return_value = mock_engines
        
        # Mock list_secrets_in_engine
        mock_list_response = {
            'data': {
                'keys': ['secret1']
            }
        }
        mock_hvac_client.secrets.kv.v2.list_secrets.return_value = mock_list_response
        
        # Mock get_secret response
        mock_secret_response = {
            'data': {
                'data': {
                    'USERNAME': 'ADMIN',
                    'password': 'secret123'
                }
            }
        }
        mock_hvac_client.secrets.kv.v2.read_secret_version.return_value = mock_secret_response
        
        result = connected_client.search_secrets("admin", case_sensitive=False)
        
        assert len(result) == 1
        assert result[0]['data']['USERNAME'] == 'ADMIN'
    
    def test_search_secrets_not_connected(self):
        """Test secret search when not connected."""
        client = VaultClient("https://vault.example.com", "test-token")
        
        with pytest.raises(VaultConnectionError, match="Not connected to Vault server"):
            client.search_secrets("test")


class TestVaultClientContextManager:
    """Test VaultClient context manager functionality."""
    
    @patch('app.vault_client.hvac.Client')
    def test_context_manager_success(self, mock_hvac_class, mock_hvac_client):
        """Test successful context manager usage."""
        mock_hvac_class.return_value = mock_hvac_client
        
        with VaultClient("https://vault.example.com", "test-token") as client:
            assert client.is_connected() is True
        
        # Should be disconnected after context exit
        assert client.is_connected() is False
    
    @patch('app.vault_client.hvac.Client')
    def test_context_manager_exception(self, mock_hvac_class, mock_hvac_client):
        """Test context manager with exception."""
        mock_hvac_class.return_value = mock_hvac_client
        
        with pytest.raises(ValueError):
            with VaultClient("https://vault.example.com", "test-token") as client:
                raise ValueError("Test exception")
        
        # Should still be disconnected after exception
        assert client.is_connected() is False


class TestVaultClientErrorHandling:
    """Test VaultClient error handling."""
    
    def test_vault_client_error_inheritance(self):
        """Test that custom exceptions inherit correctly."""
        assert issubclass(VaultConnectionError, VaultClientError)
        assert issubclass(VaultAuthenticationError, VaultClientError)
        assert issubclass(VaultPermissionError, VaultClientError)
    
    def test_exception_messages(self):
        """Test exception message formatting."""
        conn_error = VaultConnectionError("Connection failed")
        auth_error = VaultAuthenticationError("Invalid token")
        perm_error = VaultPermissionError("No permission")
        
        assert str(conn_error) == "Connection failed"
        assert str(auth_error) == "Invalid token"
        assert str(perm_error) == "No permission"
