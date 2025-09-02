"""
Security utilities for the Secret Sluth application.

This module provides security functions including token encryption,
secure cookie configuration, and security validation.
"""

import os
import base64
import hashlib
import hmac
import time
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import current_app, request
from app.logging_config import get_logger

logger = get_logger(__name__)


class SecurityManager:
    """Manages security operations including encryption and validation."""
    
    def __init__(self):
        """Initialize the security manager."""
        self._fernet = None
        self._secret_key = None
    
    def _get_secret_key(self) -> bytes:
        """Get or generate the secret key for encryption.
        
        Returns:
            Secret key bytes for encryption
        """
        if self._secret_key is None:
            # Get secret key from config or generate one
            secret_key = current_app.config.get('SECRET_KEY', 'dev-secret-key')
            if secret_key == 'dev-secret-key':
                logger.warning("Using development secret key - not secure for production")
            
            # Derive a proper key from the secret
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'secret-sluth-salt',  # In production, use a random salt
                iterations=100000,
            )
            self._secret_key = base64.urlsafe_b64encode(kdf.derive(secret_key.encode()))
        
        return self._secret_key
    
    def _get_fernet(self) -> Fernet:
        """Get or create the Fernet cipher for encryption.
        
        Returns:
            Fernet cipher instance
        """
        if self._fernet is None:
            secret_key = self._get_secret_key()
            self._fernet = Fernet(secret_key)
        
        return self._fernet
    
    def encrypt_token(self, token: str) -> str:
        """Encrypt a Vault token for secure storage.
        
        Args:
            token: The Vault token to encrypt
            
        Returns:
            Encrypted token string
        """
        try:
            fernet = self._get_fernet()
            encrypted_data = fernet.encrypt(token.encode())
            return base64.urlsafe_b64encode(encrypted_data).decode()
        except Exception as e:
            logger.error(f"Failed to encrypt token: {e}")
            raise
    
    def decrypt_token(self, encrypted_token: str) -> str:
        """Decrypt a Vault token from secure storage.
        
        Args:
            encrypted_token: The encrypted token string
            
        Returns:
            Decrypted token string
        """
        try:
            fernet = self._get_fernet()
            encrypted_data = base64.urlsafe_b64decode(encrypted_token.encode())
            decrypted_data = fernet.decrypt(encrypted_data)
            return decrypted_data.decode()
        except Exception as e:
            logger.error(f"Failed to decrypt token: {e}")
            raise
    
    def hash_password(self, password: str, salt: Optional[str] = None) -> Dict[str, str]:
        """Hash a password with salt for secure storage.
        
        Args:
            password: The password to hash
            salt: Optional salt (will generate if not provided)
            
        Returns:
            Dictionary with hash and salt
        """
        if salt is None:
            salt = base64.b64encode(os.urandom(16)).decode()
        
        # Use PBKDF2 for password hashing
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode(),
            iterations=100000,
        )
        
        hash_bytes = kdf.derive(password.encode())
        hash_str = base64.b64encode(hash_bytes).decode()
        
        return {
            'hash': hash_str,
            'salt': salt
        }
    
    def verify_password(self, password: str, stored_hash: str, salt: str) -> bool:
        """Verify a password against a stored hash.
        
        Args:
            password: The password to verify
            stored_hash: The stored hash to compare against
            salt: The salt used for the hash
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt.encode(),
                iterations=100000,
            )
            
            hash_bytes = kdf.derive(password.encode())
            hash_str = base64.b64encode(hash_bytes).decode()
            
            return hmac.compare_digest(hash_str, stored_hash)
        except Exception as e:
            logger.error(f"Failed to verify password: {e}")
            return False
    
    def generate_csrf_token(self) -> str:
        """Generate a CSRF token for form protection.
        
        Returns:
            CSRF token string
        """
        # Use a combination of session data and timestamp
        session_id = getattr(request, 'session', {}).get('_id', '')
        timestamp = str(int(time.time()))
        secret = current_app.config.get('SECRET_KEY', 'dev-secret-key')
        
        # Create a hash-based token
        data = f"{session_id}:{timestamp}:{secret}"
        token = hashlib.sha256(data.encode()).hexdigest()
        
        return token
    
    def verify_csrf_token(self, token: str) -> bool:
        """Verify a CSRF token.
        
        Args:
            token: The CSRF token to verify
            
        Returns:
            True if token is valid, False otherwise
        """
        # For now, we'll use a simple verification
        # In a real implementation, you'd want to store and verify against session
        return len(token) == 64 and token.isalnum()
    
    def sanitize_input(self, input_str: str) -> str:
        """Sanitize user input to prevent XSS and injection attacks.
        
        Args:
            input_str: The input string to sanitize
            
        Returns:
            Sanitized string
        """
        if not input_str:
            return ""
        
        # Remove potentially dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&', ';', '(', ')', '{', '}']
        sanitized = input_str
        
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        # Limit length
        max_length = current_app.config.get('MAX_INPUT_LENGTH', 1000)
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized.strip()
    
    def validate_url(self, url: str) -> bool:
        """Validate that a URL is safe and properly formatted.
        
        Args:
            url: The URL to validate
            
        Returns:
            True if URL is valid, False otherwise
        """
        if not url:
            return False
        
        # Basic URL validation
        if not url.startswith(('http://', 'https://')):
            return False
        
        # Check for potentially dangerous URLs
        dangerous_patterns = [
            'javascript:', 'data:', 'vbscript:', 'file:', 'ftp:'
        ]
        
        url_lower = url.lower()
        for pattern in dangerous_patterns:
            if pattern in url_lower:
                return False
        
        # Validate URL structure
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return bool(parsed.netloc and parsed.scheme in ['http', 'https'])
        except Exception:
            return False
    
    def get_secure_cookie_config(self) -> Dict[str, Any]:
        """Get secure cookie configuration for the application.
        
        Returns:
            Dictionary with secure cookie settings
        """
        config = {
            'secure': True,
            'httponly': True,
            'samesite': 'Lax',
            'max_age': 3600,  # 1 hour
        }
        
        # In development, allow HTTP cookies
        if current_app.config.get('DEBUG', False):
            config['secure'] = False
        
        return config
    
    def rate_limit_key(self, identifier: str) -> str:
        """Generate a rate limiting key for an identifier.
        
        Args:
            identifier: The identifier (IP, user ID, etc.)
            
        Returns:
            Rate limiting key string
        """
        # Use IP address and endpoint for rate limiting
        ip = request.remote_addr
        endpoint = request.endpoint or 'unknown'
        return f"rate_limit:{ip}:{endpoint}:{identifier}"


# Global security manager instance
security_manager = SecurityManager()
