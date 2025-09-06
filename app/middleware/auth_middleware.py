"""
Authentication middleware for the Secret Sluth application.

This module provides middleware for protecting routes and validating sessions.
"""

from functools import wraps
import time
from flask import request, redirect, url_for, flash, session
from app.session_manager import session_manager
from app.logging_config import get_logger

logger = get_logger(__name__)


def require_auth(f):
    """Decorator to require authentication for a route.
    
    Args:
        f: The route function to protect
        
    Returns:
        Wrapped function that checks authentication
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session_manager.is_authenticated():
            logger.info(f"Unauthenticated access attempt to {request.endpoint}")
            flash('Please authenticate with Vault first', 'error')
            return redirect(url_for('auth.login', next=request.url))
        
        # Validate session
        if not session_manager.validate_session():
            logger.info(f"Expired session for {request.endpoint}")
            flash('Your session has expired. Please login again.', 'error')
            return redirect(url_for('auth.login', next=request.url))
        
        # Update activity timestamp
        session_manager.update_activity()
        
        return f(*args, **kwargs)
    return decorated_function


def optional_auth(f):
    """Decorator to make authentication optional for a route.
    
    Args:
        f: The route function to optionally protect
        
    Returns:
        Wrapped function that checks authentication if available
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session_manager.is_authenticated():
            # Validate session if authenticated
            if not session_manager.validate_session():
                logger.info(f"Expired session for {request.endpoint}")
                session_manager.clear_session()
                flash('Your session has expired.', 'info')
            else:
                # Update activity timestamp
                session_manager.update_activity()
        
        return f(*args, **kwargs)
    return decorated_function


class AuthMiddleware:
    """Middleware class for handling authentication across the application."""
    
    def __init__(self, app=None):
        """Initialize the middleware.
        
        Args:
            app: Flask application instance
        """
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the middleware with the Flask app.
        
        Args:
            app: Flask application instance
        """
        self.app = app
        
        # Register before_request handler
        app.before_request(self.before_request)
        
        # Register after_request handler
        app.after_request(self.after_request)
    
    def before_request(self):
        """Handle requests before they are processed."""
        # Skip authentication for static files, auth routes, and main routes that don't require auth
        if (request.endpoint and 
            (request.endpoint.startswith('static') or 
             request.endpoint.startswith('auth.') or
             request.endpoint in ['main.index', 'main.connect'])):
            return
        
        # Check if user is authenticated for protected routes
        if session_manager.is_authenticated():
            # Skip session validation in testing mode
            if not self.app.config.get('TESTING', False):
                # Validate session
                if not session_manager.validate_session():
                    logger.info(f"Expired session detected for {request.endpoint}")
                    session_manager.clear_session()
                    flash('Your session has expired. Please login again.', 'error')
                    return redirect(url_for('auth.login', next=request.url))
            
            # Update activity timestamp
            session_manager.update_activity()
    
    def after_request(self, response):
        """Handle responses after they are processed."""
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Add session timeout header if authenticated
        if session_manager.is_authenticated():
            session_info = session_manager.get_session_info()
            if session_info and session_info.get('last_activity'):
                last_activity = session_info.get('last_activity', 0)
                timeout = session_manager.session_timeout
                # Ensure we have proper numeric values
                if isinstance(last_activity, (int, float)) and isinstance(timeout, (int, float)):
                    remaining = timeout - (int(time.time()) - last_activity)
                    if remaining > 0:
                        response.headers['X-Session-Timeout'] = str(remaining)
        
        return response
