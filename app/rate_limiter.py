"""
Rate Limiter Implementation for Secret Sluth.

This module provides rate limiting functionality to protect against abuse,
brute force attacks, and excessive resource consumption.
"""

import time
from typing import Dict, Optional, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
import threading

from app.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    max_requests: int  # Maximum requests allowed
    window_seconds: int  # Time window in seconds
    burst_size: int = 0  # Allow burst of requests (0 = no burst)
    block_duration: int = 300  # Block duration in seconds when limit exceeded


class RateLimiter:
    """
    Rate limiter implementation using sliding window with burst support.
    """
    
    def __init__(self):
        """Initialize the rate limiter."""
        self.limits: Dict[str, RateLimitConfig] = {}
        self.request_history: Dict[str, deque] = defaultdict(deque)
        self.blocked_ips: Dict[str, float] = {}
        self.lock = threading.RLock()
        self.logger = get_logger(__name__)
        
        # Default rate limits
        self._setup_default_limits()
    
    def _setup_default_limits(self):
        """Setup default rate limits for different endpoints."""
        self.add_limit('auth', RateLimitConfig(max_requests=5, window_seconds=300))  # 5 login attempts per 5 minutes
        self.add_limit('search', RateLimitConfig(max_requests=20, window_seconds=60))  # 20 searches per minute
        self.add_limit('api', RateLimitConfig(max_requests=100, window_seconds=60))  # 100 API calls per minute
        self.add_limit('export', RateLimitConfig(max_requests=10, window_seconds=300))  # 10 exports per 5 minutes
    
    def add_limit(self, endpoint: str, config: RateLimitConfig):
        """
        Add a rate limit configuration for an endpoint.
        
        Args:
            endpoint: Endpoint name (e.g., 'auth', 'search', 'api')
            config: Rate limit configuration
        """
        with self.lock:
            self.limits[endpoint] = config
            self.logger.info(f"Added rate limit for {endpoint}: {config.max_requests} requests per {config.window_seconds}s")
    
    def is_allowed(self, identifier: str, endpoint: str) -> Tuple[bool, Optional[Dict]]:
        """
        Check if a request is allowed based on rate limits.
        
        Args:
            identifier: Unique identifier (usually IP address or user ID)
            endpoint: Endpoint being accessed
            
        Returns:
            Tuple of (is_allowed, rate_limit_info)
        """
        with self.lock:
            # Check if IP is blocked
            if identifier in self.blocked_ips:
                block_until = self.blocked_ips[identifier]
                if time.time() < block_until:
                    remaining = int(block_until - time.time())
                    self.logger.warning(f"Blocked request from {identifier} to {endpoint} (blocked for {remaining}s)")
                    return False, {
                        'blocked': True,
                        'block_remaining': remaining,
                        'message': f'Too many requests. Try again in {remaining} seconds.'
                    }
                else:
                    # Unblock expired IP
                    del self.blocked_ips[identifier]
            
            # Get rate limit config for endpoint
            config = self.limits.get(endpoint)
            if not config:
                return True, None  # No rate limit configured
            
            # Get request history for this identifier and endpoint
            key = f"{identifier}:{endpoint}"
            history = self.request_history[key]
            current_time = time.time()
            
            # Remove old requests outside the window
            while history and current_time - history[0] > config.window_seconds:
                history.popleft()
            
            # Check if request is allowed
            if len(history) >= config.max_requests:
                # Rate limit exceeded
                if config.block_duration > 0:
                    self.blocked_ips[identifier] = current_time + config.block_duration
                    self.logger.warning(f"Rate limit exceeded for {identifier} on {endpoint}, blocked for {config.block_duration}s")
                
                return False, {
                    'blocked': False,
                    'rate_limited': True,
                    'limit': config.max_requests,
                    'window': config.window_seconds,
                    'message': f'Rate limit exceeded. Maximum {config.max_requests} requests per {config.window_seconds} seconds.'
                }
            
            # Add current request to history
            history.append(current_time)
            
            # Return rate limit info
            return True, {
                'remaining': config.max_requests - len(history),
                'limit': config.max_requests,
                'window': config.window_seconds,
                'reset_time': current_time + config.window_seconds
            }
    
    def get_identifier(self, request) -> str:
        """
        Extract identifier from request (IP address or user ID).
        
        Args:
            request: Flask request object
            
        Returns:
            Identifier string
        """
        # Try to get real IP address (handles proxies)
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        else:
            return request.remote_addr
    
    def cleanup_expired_blocks(self):
        """Clean up expired IP blocks."""
        with self.lock:
            current_time = time.time()
            expired_ips = [ip for ip, block_until in self.blocked_ips.items() 
                          if current_time >= block_until]
            
            for ip in expired_ips:
                del self.blocked_ips[ip]
            
            if expired_ips:
                self.logger.info(f"Cleaned up {len(expired_ips)} expired IP blocks")
    
    def clear_block(self, identifier: str):
        """Clear rate limit block for a specific identifier.
        
        Args:
            identifier: IP address or user identifier to unblock
        """
        with self.lock:
            if identifier in self.blocked_ips:
                del self.blocked_ips[identifier]
                self.logger.info(f"Cleared rate limit block for {identifier}")
            
            # Also clear request history for this identifier
            keys_to_remove = [key for key in self.request_history.keys() if key.startswith(f"{identifier}:")]
            for key in keys_to_remove:
                del self.request_history[key]
                self.logger.info(f"Cleared request history for {key}")
    
    def get_stats(self) -> Dict:
        """Get rate limiter statistics."""
        with self.lock:
            return {
                'blocked_ips': len(self.blocked_ips),
                'active_limits': len(self.limits),
                'total_history_entries': sum(len(history) for history in self.request_history.values())
            }


# Global rate limiter instance
rate_limiter = RateLimiter()
