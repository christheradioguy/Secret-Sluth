"""
Unit tests for validators module.

This module tests input validation and sanitization functions.
"""

import pytest
from app import create_app
from app.validators import input_validator


@pytest.fixture
def app():
    """Create a test Flask application."""
    app = create_app()
    app.config['TESTING'] = True
    return app


class TestInputValidator:
    """Test input validator functionality."""
    
    def test_validate_vault_url_valid(self):
        """Test valid Vault URL validation."""
        # Valid URLs
        assert input_validator.validate_vault_url("https://vault.example.com")[0] is True
        assert input_validator.validate_vault_url("http://vault.example.com:8200")[0] is True
        assert input_validator.validate_vault_url("https://vault.example.com/path")[0] is True
    
    def test_validate_vault_url_invalid(self):
        """Test invalid Vault URL validation."""
        # Invalid URLs
        assert input_validator.validate_vault_url("")[0] is False
        assert input_validator.validate_vault_url("not-a-url")[0] is False
        assert input_validator.validate_vault_url("ftp://vault.example.com")[0] is False
        assert input_validator.validate_vault_url("localhost")[0] is False
        assert input_validator.validate_vault_url("127.0.0.1")[0] is False
    
    def test_validate_vault_token_valid(self):
        """Test valid Vault token validation."""
        # Valid tokens
        assert input_validator.validate_vault_token("hvs.1234567890abcdef")[0] is True
        assert input_validator.validate_vault_token("test-token-123")[0] is True
        assert input_validator.validate_vault_token("token_with_underscores")[0] is True
    
    def test_validate_vault_token_invalid(self):
        """Test invalid Vault token validation."""
        # Invalid tokens
        assert input_validator.validate_vault_token("")[0] is False
        assert input_validator.validate_vault_token("short")[0] is False
        assert input_validator.validate_vault_token("test")[0] is False  # placeholder
        assert input_validator.validate_vault_token("a" * 1001)[0] is False  # too long
    
    def test_validate_search_term_valid(self):
        """Test valid search term validation."""
        # Valid search terms
        assert input_validator.validate_search_term("password")[0] is True
        assert input_validator.validate_search_term("api_key")[0] is True
        assert input_validator.validate_search_term("secret value")[0] is True
    
    def test_validate_search_term_invalid(self):
        """Test invalid search term validation."""
        # Invalid search terms
        assert input_validator.validate_search_term("")[0] is False
        assert input_validator.validate_search_term("a")[0] is False  # too short
        assert input_validator.validate_search_term("a" * 101)[0] is False  # too long
        assert input_validator.validate_search_term("..")[0] is False  # dangerous pattern
        assert input_validator.validate_search_term("script")[0] is False  # dangerous pattern
    
    def test_sanitize_input(self):
        """Test input sanitization."""
        # Test XSS prevention
        dangerous = "<script>alert('xss')</script>"
        sanitized = input_validator.sanitize_input(dangerous)
        assert "<script>" not in sanitized
        assert "alert('xss')" in sanitized
        
        # Test length limiting
        long_input = "a" * 2000
        sanitized = input_validator.sanitize_input(long_input)
        assert len(sanitized) <= 1000
        
        # Test empty input
        assert input_validator.sanitize_input("") == ""
        assert input_validator.sanitize_input(None) == ""
    
    def test_validate_form_data(self):
        """Test form data validation."""
        # Valid form data
        valid_data = {
            'vault_url': 'https://vault.example.com',
            'vault_token': 'hvs.1234567890abcdef'
        }
        is_valid, errors = input_validator.validate_form_data(valid_data)
        assert is_valid is True
        assert len(errors) == 0
        
        # Invalid form data
        invalid_data = {
            'vault_url': 'invalid-url',
            'vault_token': 'short'
        }
        is_valid, errors = input_validator.validate_form_data(invalid_data)
        assert is_valid is False
        assert len(errors) > 0
        assert 'vault_url' in errors
        assert 'vault_token' in errors
