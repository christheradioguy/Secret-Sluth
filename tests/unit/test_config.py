"""
Unit tests for configuration module.
"""

import os
import pytest
from app.config import Config, DevelopmentConfig, TestingConfig, ProductionConfig, get_bool_env


class TestGetBoolEnv:
    """Test cases for get_bool_env function."""

    def test_get_bool_env_true_values(self):
        """Test get_bool_env with true values."""
        assert get_bool_env("TEST_VAR", default=False) is False
        
        # Test various true values
        os.environ["TEST_VAR"] = "true"
        assert get_bool_env("TEST_VAR", default=False) is True
        
        os.environ["TEST_VAR"] = "1"
        assert get_bool_env("TEST_VAR", default=False) is True
        
        os.environ["TEST_VAR"] = "yes"
        assert get_bool_env("TEST_VAR", default=False) is True
        
        os.environ["TEST_VAR"] = "on"
        assert get_bool_env("TEST_VAR", default=False) is True

    def test_get_bool_env_false_values(self):
        """Test get_bool_env with false values."""
        # Test various false values
        os.environ["TEST_VAR"] = "false"
        assert get_bool_env("TEST_VAR", default=True) is False
        
        os.environ["TEST_VAR"] = "0"
        assert get_bool_env("TEST_VAR", default=True) is False
        
        os.environ["TEST_VAR"] = "no"
        assert get_bool_env("TEST_VAR", default=True) is False
        
        os.environ["TEST_VAR"] = "off"
        assert get_bool_env("TEST_VAR", default=True) is False

    def test_get_bool_env_default(self):
        """Test get_bool_env with default values."""
        # Remove environment variable if it exists
        os.environ.pop("TEST_VAR", None)
        
        assert get_bool_env("TEST_VAR", default=True) is True
        assert get_bool_env("TEST_VAR", default=False) is False

    def test_get_bool_env_case_insensitive(self):
        """Test get_bool_env is case insensitive."""
        os.environ["TEST_VAR"] = "TRUE"
        assert get_bool_env("TEST_VAR", default=False) is True
        
        os.environ["TEST_VAR"] = "True"
        assert get_bool_env("TEST_VAR", default=False) is True
        
        os.environ["TEST_VAR"] = "FALSE"
        assert get_bool_env("TEST_VAR", default=True) is False


class TestConfig:
    """Test cases for base configuration class."""

    def test_default_config(self):
        """Test default configuration values."""
        # Clear any existing environment variables
        os.environ.pop("DEBUG", None)
        os.environ.pop("TESTING", None)
        
        config = Config()

        assert config.DEBUG is False
        assert config.TESTING is False
        assert config.SECRET_KEY is not None
        assert config.VAULT_DEFAULT_TIMEOUT == 30
        assert config.VAULT_MAX_RETRIES == 3
        assert config.SEARCH_TIMEOUT == 300
        assert config.MAX_SEARCH_RESULTS == 1000
        assert config.CSRF_ENABLED is True
        assert config.RATE_LIMIT_ENABLED is True
        assert config.RATE_LIMIT_REQUESTS == 100
        assert config.RATE_LIMIT_WINDOW == 3600
        assert config.LOG_LEVEL == "INFO"
        assert config.LOG_FORMAT == "json"
        assert config.CACHE_ENABLED is True
        assert config.CACHE_TIMEOUT == 300

    def test_config_with_environment_variables(self):
        """Test configuration with environment variables set."""
        # Set environment variables
        os.environ["DEBUG"] = "true"
        os.environ["TESTING"] = "true"
        
        config = Config()
        
        assert config.DEBUG is True
        assert config.TESTING is True
        
        # Clean up
        os.environ.pop("DEBUG", None)
        os.environ.pop("TESTING", None)


class TestDevelopmentConfig:
    """Test cases for development configuration."""

    def test_development_config(self):
        """Test development configuration overrides."""
        # Clear any existing environment variables
        os.environ.pop("DEBUG", None)
        
        config = DevelopmentConfig()

        assert config.DEBUG is True
        assert config.SESSION_COOKIE_SECURE is False
        assert config.LOG_LEVEL == "DEBUG"

    def test_development_config_with_env_override(self):
        """Test development config respects environment variable override."""
        # Set environment variable to override default
        os.environ["DEBUG"] = "false"
        
        config = DevelopmentConfig()
        
        assert config.DEBUG is False
        
        # Clean up
        os.environ.pop("DEBUG", None)


class TestTestingConfig:
    """Test cases for testing configuration."""

    def test_testing_config(self):
        """Test testing configuration overrides."""
        # Clear any existing environment variables
        os.environ.pop("TESTING", None)
        
        config = TestingConfig()

        assert config.TESTING is True
        assert config.WTF_CSRF_ENABLED is False
        assert config.SESSION_COOKIE_SECURE is False
        assert config.LOG_LEVEL == "DEBUG"

    def test_testing_config_with_env_override(self):
        """Test testing config respects environment variable override."""
        # Set environment variable to override default
        os.environ["TESTING"] = "false"
        
        config = TestingConfig()
        
        assert config.TESTING is False
        
        # Clean up
        os.environ.pop("TESTING", None)


class TestProductionConfig:
    """Test cases for production configuration."""

    def test_production_config(self):
        """Test production configuration overrides."""
        # Clear any existing environment variables
        os.environ.pop("DEBUG", None)
        
        config = ProductionConfig()

        assert config.DEBUG is False
        assert config.SESSION_COOKIE_SECURE is True
        assert config.SESSION_COOKIE_HTTPONLY is True
        assert config.SESSION_COOKIE_SAMESITE == "Strict"
        assert config.LOG_LEVEL == "WARNING"

    def test_production_config_with_env_override(self):
        """Test production config respects environment variable override."""
        # Set environment variable to override default
        os.environ["DEBUG"] = "true"
        
        config = ProductionConfig()
        
        assert config.DEBUG is True
        
        # Clean up
        os.environ.pop("DEBUG", None)
