"""
Rate Limiting Middleware for Secret Sluth.

This module provides middleware to integrate rate limiting with Flask requests.
"""

from flask import request, jsonify, current_app
from functools import wraps
from app.rate_limiter import rate_limiter
from app.logging_config import get_logger

logger = get_logger(__name__)


def rate_limit(endpoint: str = None):
    """
    Decorator to apply rate limiting to Flask routes.
    
    Args:
        endpoint: Endpoint name for rate limiting (defaults to route name)
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Determine endpoint name
            endpoint_name = endpoint or request.endpoint or 'default'
            
            # Get client identifier
            identifier = rate_limiter.get_identifier(request)
            
            # Check rate limit
            is_allowed, rate_info = rate_limiter.is_allowed(identifier, endpoint_name)
            
            if not is_allowed:
                # Log the rate limit violation
                logger.warning(f"Rate limit exceeded: {identifier} -> {endpoint_name}")
                
                # Return rate limit error response
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({
                        'error': 'Rate limit exceeded',
                        'message': rate_info.get('message', 'Too many requests'),
                        'retry_after': rate_info.get('block_remaining', 60)
                    }), 429
                else:
                    # For regular requests, return a simple error page
                    return f"""
                    <html>
                        <head><title>Rate Limit Exceeded</title></head>
                        <body>
                            <h1>Rate Limit Exceeded</h1>
                            <p>{rate_info.get('message', 'Too many requests')}</p>
                            <p>Please try again later.</p>
                        </body>
                    </html>
                    """, 429
            
            # Add rate limit headers to response
            if rate_info:
                # Store rate limit info in request context for later use
                request.rate_limit_info = rate_info
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def add_rate_limit_headers(response):
    """
    Add rate limit headers to response.
    
    Args:
        response: Flask response object
        
    Returns:
        Response with rate limit headers
    """
    if hasattr(request, 'rate_limit_info') and request.rate_limit_info:
        info = request.rate_limit_info
        
        response.headers['X-RateLimit-Limit'] = str(info.get('limit', 0))
        response.headers['X-RateLimit-Remaining'] = str(info.get('remaining', 0))
        response.headers['X-RateLimit-Reset'] = str(int(info.get('reset_time', 0)))
        
        if info.get('blocked'):
            response.headers['X-RateLimit-Blocked'] = 'true'
            response.headers['Retry-After'] = str(info.get('block_remaining', 60))
    
    return response


class RateLimitMiddleware:
    """
    Middleware class for rate limiting.
    """
    
    def __init__(self, app=None):
        """Initialize the middleware."""
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the middleware with Flask app."""
        # Register after_request handler to add rate limit headers
        app.after_request(add_rate_limit_headers)
        
        # Add rate limiter to app context
        app.rate_limiter = rate_limiter
        
        logger.info("Rate limiting middleware initialized")


# Convenience function to apply rate limiting to specific endpoints
def apply_rate_limits(app):
    """
    Apply rate limiting to specific endpoints.
    
    Args:
        app: Flask application instance
    """
    # This function can be used to apply rate limits to specific routes
    # For now, we'll use the decorator approach
    pass
