"""
Error handling for the Secret Sluth application.

This module provides comprehensive error handling, user-friendly error messages,
and structured logging for debugging and monitoring.
"""

import traceback
from typing import Dict, Any, Optional, Tuple
from flask import Blueprint, render_template, request, jsonify, current_app
from werkzeug.exceptions import HTTPException
from app.logging_config import get_logger
from app.vault_client import VaultClientError, VaultAuthenticationError, VaultConnectionError

logger = get_logger(__name__)

# Create error handlers blueprint
error_handlers = Blueprint('error_handlers', __name__)


class SecretSluthError(Exception):
    """Base exception class for Secret Sluth application."""
    
    def __init__(self, message: str, error_code: str = None, details: Dict[str, Any] = None):
        """Initialize the error.
        
        Args:
            message: User-friendly error message
            error_code: Internal error code for logging
            details: Additional error details
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.details = details or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary for JSON responses.
        
        Returns:
            Dictionary representation of the error
        """
        return {
            'error': True,
            'message': self.message,
            'error_code': self.error_code,
            'details': self.details
        }


class VaultError(SecretSluthError):
    """Exception for Vault-related errors."""
    pass


class AuthenticationError(SecretSluthError):
    """Exception for authentication errors."""
    pass


class ValidationError(SecretSluthError):
    """Exception for validation errors."""
    pass


class SearchError(SecretSluthError):
    """Exception for search-related errors."""
    pass


def log_error(error: Exception, context: Dict[str, Any] = None) -> None:
    """Log an error with structured information.
    
    Args:
        error: The exception that occurred
        context: Additional context information
    """
    context = context or {}
    
    # Get request information
    request_info = {
        'method': request.method,
        'url': request.url,
        'endpoint': request.endpoint,
        'remote_addr': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', 'Unknown')
    }
    
    # Get error information
    error_info = {
        'type': type(error).__name__,
        'message': str(error),
        'traceback': traceback.format_exc()
    }
    
    # Combine all information
    log_data = {
        'error': error_info,
        'request': request_info,
        'context': context
    }
    
    # Log based on error type
    if isinstance(error, (VaultAuthenticationError, AuthenticationError)):
        logger.warning("Authentication error occurred", extra=log_data)
    elif isinstance(error, (VaultConnectionError, VaultClientError)):
        logger.error("Vault connection error occurred", extra=log_data)
    elif isinstance(error, ValidationError):
        logger.warning("Validation error occurred", extra=log_data)
    elif isinstance(error, SearchError):
        logger.error("Search error occurred", extra=log_data)
    else:
        logger.error("Unexpected error occurred", extra=log_data)


def get_user_friendly_message(error: Exception) -> str:
    """Get a user-friendly error message for an exception.
    
    Args:
        error: The exception that occurred
        
    Returns:
        User-friendly error message
    """
    if isinstance(error, VaultAuthenticationError):
        return "Authentication failed. Please check your Vault token and try again."
    
    elif isinstance(error, VaultConnectionError):
        return "Unable to connect to Vault server. Please check the server URL and try again."
    
    elif isinstance(error, VaultClientError):
        return "Vault server error occurred. Please try again later."
    
    elif isinstance(error, AuthenticationError):
        return "Authentication required. Please login to continue."
    
    elif isinstance(error, ValidationError):
        return "Invalid input provided. Please check your data and try again."
    
    elif isinstance(error, SearchError):
        return "Search operation failed. Please try again with different parameters."
    
    elif isinstance(error, HTTPException):
        if error.code == 404:
            return "The requested page was not found."
        elif error.code == 403:
            return "Access denied. You don't have permission to access this resource."
        elif error.code == 500:
            return "An internal server error occurred. Please try again later."
        else:
            return f"HTTP error {error.code}: {error.description}"
    
    else:
        return "An unexpected error occurred. Please try again later."


def handle_vault_error(error: VaultClientError) -> Tuple[str, int]:
    """Handle Vault-related errors.
    
    Args:
        error: The Vault error that occurred
        
    Returns:
        Tuple of (message, status_code)
    """
    if isinstance(error, VaultAuthenticationError):
        return "Authentication failed. Please check your Vault token.", 401
    
    elif isinstance(error, VaultConnectionError):
        return "Unable to connect to Vault server. Please check the server URL.", 503
    
    else:
        return "Vault server error occurred. Please try again later.", 500


@error_handlers.app_errorhandler(404)
def not_found_error(error):
    """Handle 404 Not Found errors."""
    log_error(error, {'error_type': 'not_found'})
    
    if request.path.startswith('/api/'):
        return jsonify({
            'error': True,
            'message': 'Resource not found',
            'error_code': 'NOT_FOUND'
        }), 404
    
    return render_template('errors/404.html'), 404


@error_handlers.app_errorhandler(403)
def forbidden_error(error):
    """Handle 403 Forbidden errors."""
    log_error(error, {'error_type': 'forbidden'})
    
    if request.path.startswith('/api/'):
        return jsonify({
            'error': True,
            'message': 'Access denied',
            'error_code': 'FORBIDDEN'
        }), 403
    
    return render_template('errors/403.html'), 403


@error_handlers.app_errorhandler(500)
def internal_error(error):
    """Handle 500 Internal Server Error."""
    log_error(error, {'error_type': 'internal_error'})
    
    if request.path.startswith('/api/'):
        return jsonify({
            'error': True,
            'message': 'Internal server error',
            'error_code': 'INTERNAL_ERROR'
        }), 500
    
    return render_template('errors/500.html'), 500


@error_handlers.app_errorhandler(VaultClientError)
def vault_error(error):
    """Handle Vault client errors."""
    log_error(error, {'error_type': 'vault_error'})
    message, status_code = handle_vault_error(error)
    
    if request.path.startswith('/api/'):
        return jsonify({
            'error': True,
            'message': message,
            'error_code': 'VAULT_ERROR'
        }), status_code
    
    return render_template('errors/vault_error.html', 
                         message=message, 
                         status_code=status_code), status_code


@error_handlers.app_errorhandler(SecretSluthError)
def application_error(error):
    """Handle application-specific errors."""
    log_error(error, {'error_type': 'application_error'})
    
    if request.path.startswith('/api/'):
        return jsonify(error.to_dict()), 400
    
    return render_template('errors/application_error.html', 
                         error=error), 400


@error_handlers.app_errorhandler(Exception)
def unexpected_error(error):
    """Handle unexpected errors."""
    log_error(error, {'error_type': 'unexpected_error'})
    
    if request.path.startswith('/api/'):
        return jsonify({
            'error': True,
            'message': 'An unexpected error occurred',
            'error_code': 'UNEXPECTED_ERROR'
        }), 500
    
    return render_template('errors/500.html'), 500


def register_error_handlers(app):
    """Register error handlers with the Flask application.
    
    Args:
        app: Flask application instance
    """
    app.register_blueprint(error_handlers)
    
    # Register custom error handlers
    app.register_error_handler(404, not_found_error)
    app.register_error_handler(403, forbidden_error)
    app.register_error_handler(500, internal_error)
    app.register_error_handler(VaultClientError, vault_error)
    app.register_error_handler(SecretSluthError, application_error)
    app.register_error_handler(Exception, unexpected_error)
