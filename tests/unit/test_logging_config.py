"""
Unit tests for logging configuration module.
"""

import pytest
import structlog
from flask import Flask
from app.logging_config import (
    setup_logging,
    get_logger,
    log_request_info,
    log_security_event,
    log_audit_event,
)


class TestLoggingConfig:
    """Test cases for logging configuration."""

    def test_setup_logging(self):
        """Test logging setup with Flask app."""
        app = Flask(__name__)
        app.config["LOG_LEVEL"] = "INFO"
        app.config["LOG_FORMAT"] = "json"

        # Should not raise any exceptions
        setup_logging(app)

        assert app.logger.level == 20  # INFO level

    def test_get_logger(self):
        """Test getting a structured logger."""
        logger = get_logger("test_logger")

        # structlog returns a proxy initially, but it should be callable
        assert hasattr(logger, "info")
        assert hasattr(logger, "warning")
        assert hasattr(logger, "error")

    def test_log_request_info(self):
        """Test logging request information."""
        logger = get_logger("test_request")
        request_data = {
            "method": "GET",
            "path": "/test",
            "status_code": 200,
            "response_time": 0.1,
            "user_agent": "test-agent",
            "remote_addr": "127.0.0.1",
        }

        # Should not raise any exceptions
        log_request_info(logger, request_data)

    def test_log_security_event(self):
        """Test logging security events."""
        logger = get_logger("test_security")
        details = {
            "ip_address": "192.168.1.1",
            "user_agent": "malicious-agent",
            "event_description": "Failed login attempt",
        }

        # Should not raise any exceptions
        log_security_event(logger, "failed_login", details)

    def test_log_audit_event(self):
        """Test logging audit events."""
        logger = get_logger("test_audit")
        details = {
            "resource": "/secrets",
            "action_type": "read",
            "timestamp": "2023-01-01T00:00:00Z",
        }

        # Should not raise any exceptions
        log_audit_event(logger, "secret_access", "test_user", details)
