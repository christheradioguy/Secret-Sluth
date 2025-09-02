"""
Unit tests for Flask application factory.
"""

import pytest
from flask import Flask
from app import create_app
from app.config import Config


class TestAppFactory:
    """Test cases for Flask application factory."""

    def test_create_app(self):
        """Test creating Flask application with default config."""
        app = create_app()

        assert isinstance(app, Flask)
        assert app.name == "app"
        assert app.config["SECRET_KEY"] is not None

    def test_create_app_with_config(self):
        """Test creating Flask application with custom config."""

        class TestConfig(Config):
            def __init__(self):
                super().__init__()
                self.TESTING = True
                self.SECRET_KEY = "test-secret-key"

        app = create_app(TestConfig)

        assert isinstance(app, Flask)
        assert app.config["TESTING"] is True
        assert app.config["SECRET_KEY"] == "test-secret-key"

    def test_app_config_loaded(self):
        """Test that configuration is properly loaded."""
        app = create_app()

        # Check that key configuration values are set
        assert "SECRET_KEY" in app.config
        assert "VAULT_DEFAULT_TIMEOUT" in app.config
        assert "SEARCH_TIMEOUT" in app.config
        assert "LOG_LEVEL" in app.config
