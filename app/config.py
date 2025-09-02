"""
Configuration management for Secret Sluth application.

This module handles all configuration settings including environment variables,
default values, and different configuration classes for various deployment
environments.
"""

import os
from typing import Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


def get_bool_env(key: str, default: bool = False) -> bool:
    """Get boolean value from environment variable.
    
    Args:
        key: Environment variable name
        default: Default value if environment variable is not set
        
    Returns:
        Boolean value from environment variable
    """
    value = os.environ.get(key, str(default)).lower()
    return value in ('true', '1', 'yes', 'on')


class Config:
    """Base configuration class with common settings."""

    def __init__(self):
        """Initialize configuration with environment variable support."""
        # Flask Configuration
        self.SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-secret-key-change-in-production"
        self.DEBUG = get_bool_env("DEBUG", False)
        self.TESTING = get_bool_env("TESTING", False)

        # Session Configuration
        self.SESSION_COOKIE_SECURE = True
        self.SESSION_COOKIE_HTTPONLY = True
        self.SESSION_COOKIE_SAMESITE = "Lax"
        self.PERMANENT_SESSION_LIFETIME = 3600  # 1 hour

        # Vault Configuration
        self.VAULT_DEFAULT_TIMEOUT = int(os.environ.get("VAULT_DEFAULT_TIMEOUT", "30"))
        self.VAULT_MAX_RETRIES = int(os.environ.get("VAULT_MAX_RETRIES", "3"))

        # Search Configuration
        self.SEARCH_TIMEOUT = int(os.environ.get("SEARCH_TIMEOUT", "300"))  # 5 minutes
        self.MAX_SEARCH_RESULTS = int(os.environ.get("MAX_SEARCH_RESULTS", "1000"))

        # Security Configuration
        self.CSRF_ENABLED = True
        self.RATE_LIMIT_ENABLED = True
        self.RATE_LIMIT_REQUESTS = int(os.environ.get("RATE_LIMIT_REQUESTS", "100"))
        self.RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "3600"))  # 1 hour
        self.MAX_INPUT_LENGTH = int(os.environ.get("MAX_INPUT_LENGTH", "1000"))

        # Logging Configuration
        self.LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
        self.LOG_FORMAT = os.environ.get("LOG_FORMAT", "json")

        # Cache Configuration
        self.CACHE_ENABLED = os.environ.get("CACHE_ENABLED", "true").lower() == "true"
        self.CACHE_TIMEOUT = int(os.environ.get("CACHE_TIMEOUT", "300"))  # 5 minutes


class DevelopmentConfig(Config):
    """Development configuration with debug settings."""

    def __init__(self):
        super().__init__()
        self.DEBUG = get_bool_env("DEBUG", True)
        self.SESSION_COOKIE_SECURE = False  # Allow HTTP in development
        self.LOG_LEVEL = "DEBUG"


class TestingConfig(Config):
    """Testing configuration with test-specific settings."""

    def __init__(self):
        super().__init__()
        self.TESTING = get_bool_env("TESTING", True)
        self.WTF_CSRF_ENABLED = False
        self.SESSION_COOKIE_SECURE = False
        self.LOG_LEVEL = "DEBUG"


class ProductionConfig(Config):
    """Production configuration with security-focused settings."""

    def __init__(self):
        super().__init__()
        self.DEBUG = get_bool_env("DEBUG", False)
        # Ensure secure settings in production
        self.SESSION_COOKIE_SECURE = True
        self.SESSION_COOKIE_HTTPONLY = True
        self.SESSION_COOKIE_SAMESITE = "Strict"
        # Production logging
        self.LOG_LEVEL = "WARNING"


# Configuration mapping
config = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
