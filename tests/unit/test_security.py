"""
Unit tests for security module.

This module tests the security utilities including encryption, validation, and security functions.
"""

import pytest
from unittest.mock import patch, MagicMock
from app import create_app
from app.security import security_manager


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


class TestSecurityManager:
    """Test security manager functionality."""
    
    def test_encrypt_decrypt_token(self, app):
        """Test token encryption and decryption."""
        with app.app_context():
            original_token = "test-vault-token-12345"
            
            # Encrypt the token
            encrypted = security_manager.encrypt_token(original_token)
            assert encrypted != original_token
            assert isinstance(encrypted, str)
            assert len(encrypted) > 0
            
            # Decrypt the token
            decrypted = security_manager.decrypt_token(encrypted)
            assert decrypted == original_token
    
    def test_encrypt_decrypt_token_with_special_chars(self, app):
        """Test token encryption with special characters."""
        with app.app_context():
            original_token = "test-token-with-special-chars!@#$%^&*()"
            
            encrypted = security_manager.encrypt_token(original_token)
            decrypted = security_manager.decrypt_token(encrypted)
            
            assert decrypted == original_token
    
    def test_encrypt_token_error_handling(self, app):
        """Test error handling in token encryption."""
        with app.app_context():
            with patch('app.security.security_manager._get_fernet') as mock_fernet:
                mock_fernet.return_value.encrypt.side_effect = Exception("Encryption failed")
                
                with pytest.raises(Exception):
                    security_manager.encrypt_token("test-token")
    
    def test_decrypt_token_error_handling(self, app):
        """Test error handling in token decryption."""
        with app.app_context():
            with pytest.raises(Exception):
                security_manager.decrypt_token("invalid-encrypted-token")
    
    def test_hash_password(self, app):
        """Test password hashing."""
        with app.app_context():
            password = "test-password-123"
            
            # Hash password without salt
            result = security_manager.hash_password(password)
            assert 'hash' in result
            assert 'salt' in result
            assert result['hash'] != password
            assert len(result['salt']) > 0
            
            # Hash password with custom salt
            custom_salt = "custom-salt-123"
            result2 = security_manager.hash_password(password, custom_salt)
            assert result2['salt'] == custom_salt
            assert result2['hash'] != result['hash']  # Different salts = different hashes
    
    def test_verify_password(self, app):
        """Test password verification."""
        with app.app_context():
            password = "test-password-123"
            
            # Hash the password
            hashed = security_manager.hash_password(password)
            
            # Verify correct password
            assert security_manager.verify_password(password, hashed['hash'], hashed['salt']) is True
            
            # Verify incorrect password
            assert security_manager.verify_password("wrong-password", hashed['hash'], hashed['salt']) is False
    
    def test_verify_password_error_handling(self, app):
        """Test password verification error handling."""
        with app.app_context():
            # Test with invalid hash/salt
            assert security_manager.verify_password("test", "invalid-hash", "invalid-salt") is False
    
    def test_generate_csrf_token(self, app):
        """Test CSRF token generation."""
        with app.app_context():
            with app.test_request_context('/test'):
                token = security_manager.generate_csrf_token()
                assert isinstance(token, str)
                assert len(token) == 64  # SHA256 hash length
                assert token.isalnum()
    
    def test_verify_csrf_token(self, app):
        """Test CSRF token verification."""
        with app.app_context():
            # Valid token
            valid_token = "a" * 64
            assert security_manager.verify_csrf_token(valid_token) is True
            
            # Invalid tokens
            assert security_manager.verify_csrf_token("short") is False
            assert security_manager.verify_csrf_token("a" * 63) is False
            assert security_manager.verify_csrf_token("a" * 64 + "!") is False
    
    def test_sanitize_input(self, app):
        """Test input sanitization."""
        with app.app_context():
            # Test basic sanitization
            dangerous_input = "<script>alert('xss')</script>"
            sanitized = security_manager.sanitize_input(dangerous_input)
            assert "<script>" not in sanitized
            assert "alert" in sanitized  # Content should remain
            
            # Test length limiting
            long_input = "a" * 2000
            sanitized = security_manager.sanitize_input(long_input)
            assert len(sanitized) <= 1000  # Default max length
            
            # Test empty input
            assert security_manager.sanitize_input("") == ""
            assert security_manager.sanitize_input(None) == ""
    
    def test_validate_url(self, app):
        """Test URL validation."""
        with app.app_context():
            # Valid URLs
            assert security_manager.validate_url("https://vault.example.com") is True
            assert security_manager.validate_url("http://vault.example.com:8200") is True
            assert security_manager.validate_url("https://vault.example.com/path") is True
            
            # Invalid URLs
            assert security_manager.validate_url("") is False
            assert security_manager.validate_url("not-a-url") is False
            assert security_manager.validate_url("ftp://vault.example.com") is False
            assert security_manager.validate_url("javascript:alert('xss')") is False
            assert security_manager.validate_url("data:text/html,<script>alert('xss')</script>") is False
    
    def test_get_secure_cookie_config(self, app):
        """Test secure cookie configuration."""
        with app.app_context():
            config = security_manager.get_secure_cookie_config()
            
            assert 'secure' in config
            assert 'httponly' in config
            assert 'samesite' in config
            assert 'max_age' in config
            
            assert config['httponly'] is True
            assert config['samesite'] == 'Lax'
            assert config['max_age'] == 3600
    
    def test_get_secure_cookie_config_development(self, app):
        """Test secure cookie configuration in development mode."""
        app.config['DEBUG'] = True
        
        with app.app_context():
            config = security_manager.get_secure_cookie_config()
            assert config['secure'] is False
    
    def test_rate_limit_key(self, app):
        """Test rate limiting key generation."""
        with app.app_context():
            with app.test_request_context('/test'):
                key = security_manager.rate_limit_key("test-identifier")
                assert "rate_limit:" in key
                assert "test-identifier" in key
                assert "test" in key  # endpoint name
