"""
Logging configuration for Secret Sluth application.

This module sets up structured logging with appropriate formatting and
output destinations for different environments.
"""

import logging
import sys
from typing import Dict, Any
from flask import Flask
import structlog


def setup_logging(app: Flask) -> None:
    """Configure logging for the Flask application.

    Args:
        app: Flask application instance
    """
    log_level = getattr(logging, app.config.get("LOG_LEVEL", "INFO").upper())
    log_format = app.config.get("LOG_FORMAT", "json")

    # Configure structlog
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if log_format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )

    # Set Flask logger level
    app.logger.setLevel(log_level)

    # Add custom loggers
    setup_custom_loggers(app)


def setup_custom_loggers(app: Flask) -> None:
    """Setup custom loggers for different components.

    Args:
        app: Flask application instance
    """
    # Vault client logger
    vault_logger = structlog.get_logger("vault_client")
    vault_logger.setLevel(logging.INFO)

    # Search engine logger
    search_logger = structlog.get_logger("search_engine")
    search_logger.setLevel(logging.INFO)

    # Security logger
    security_logger = structlog.get_logger("security")
    security_logger.setLevel(logging.WARNING)

    # Audit logger
    audit_logger = structlog.get_logger("audit")
    audit_logger.setLevel(logging.INFO)
    



def get_logger(name: str) -> structlog.BoundLogger:
    """Get a structured logger instance.

    Args:
        name: Logger name

    Returns:
        Structured logger instance
    """
    return structlog.get_logger(name)


def log_request_info(
    logger: structlog.BoundLogger, request_data: Dict[str, Any]
) -> None:
    """Log request information in a structured format.

    Args:
        logger: Logger instance
        request_data: Request data dictionary
    """
    logger.info(
        "Request processed",
        method=request_data.get("method"),
        path=request_data.get("path"),
        status_code=request_data.get("status_code"),
        response_time=request_data.get("response_time"),
        user_agent=request_data.get("user_agent"),
        remote_addr=request_data.get("remote_addr"),
    )


def log_security_event(
    logger: structlog.BoundLogger, event_type: str, details: Dict[str, Any]
) -> None:
    """Log security-related events.

    Args:
        logger: Logger instance
        event_type: Type of security event
        details: Event details
    """
    logger.warning("Security event", event_type=event_type, **details)


def log_audit_event(
    logger: structlog.BoundLogger, action: str, user: str, details: Dict[str, Any]
) -> None:
    """Log audit events for compliance and monitoring.

    Args:
        logger: Logger instance
        action: Action performed
        user: User performing the action
        details: Additional details about the action
    """
    logger.info("Audit event", action=action, user=user, **details)
