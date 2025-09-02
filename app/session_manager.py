"""
Session management for the Secret Sluth application.

This module handles session creation, validation, and management for Vault authentication.
"""

import time
import uuid
from typing import Dict, Any, Optional
from flask import session
from app.vault_client import VaultClient, VaultClientError, VaultAuthenticationError
from app.security import security_manager
from app.audit_logger import audit_logger
from app.logging_config import get_logger

logger = get_logger(__name__)


class SessionManager:
    """Manages user sessions and Vault authentication state."""
    
    def __init__(self):
        """Initialize the session manager."""
        self.session_timeout = 3600  # 1 hour default
    
    def create_session(self, vault_url: str, vault_token: str, token_info: Dict[str, Any]) -> bool:
        """Create a new authenticated session.
        
        Args:
            vault_url: The Vault server URL
            vault_token: The Vault authentication token
            token_info: Token information from Vault
            
        Returns:
            True if session was created successfully, False otherwise
        """
        try:
            # Encrypt the token before storing
            encrypted_token = security_manager.encrypt_token(vault_token)
            
            # Store session data
            session['vault_url'] = vault_url
            session['vault_token'] = encrypted_token
            session['token_info'] = token_info
            session['connected'] = True
            session['authenticated_at'] = int(time.time())
            session['last_activity'] = int(time.time())
            session['_id'] = str(uuid.uuid4())  # Unique session ID for tracking
            
            # Don't log the full URL as it may contain sensitive information
            logger.info(f"Created session for Vault")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            return False
    
    def is_authenticated(self) -> bool:
        """Check if user is currently authenticated.
        
        Returns:
            True if user is authenticated, False otherwise
        """
        return session.get('connected', False)
    
    def get_session_info(self) -> Dict[str, Any]:
        """
        Get current session information.
        
        Returns:
            Dictionary with session information
        """
        return {
            'vault_url': session.get('vault_url'),
            'token_info': session.get('token_info'),
            'authenticated': session.get('connected', False),
            'session_id': session.get('_id'),
            'created_at': session.get('authenticated_at'),
            'last_activity': session.get('last_activity')
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get session statistics for monitoring.
        
        Returns:
            Dictionary with session statistics
        """
        try:
            # Get current session info
            session_info = self.get_session_info()
            
            # Calculate session age
            created_at = session_info.get('created_at')
            session_age = 0
            if created_at:
                session_age = time.time() - created_at
            
            # Calculate last activity age
            last_activity = session_info.get('last_activity')
            activity_age = 0
            if last_activity:
                activity_age = time.time() - last_activity
            
            return {
                'authenticated': session_info.get('authenticated', False),
                'session_age_seconds': session_age,
                'last_activity_seconds': activity_age,
                'has_vault_url': bool(session_info.get('vault_url')),
                'has_token_info': bool(session_info.get('token_info')),
                'session_id': session_info.get('session_id')
            }
        except Exception as e:
            logger.error(f"Error getting session stats: {e}")
            return {
                'error': str(e),
                'authenticated': False
            }
    
    def update_activity(self) -> None:
        """Update the last activity timestamp for the current session."""
        if self.is_authenticated():
            session['last_activity'] = int(time.time())
    
    def is_session_expired(self) -> bool:
        """Check if the current session has expired.
        
        Returns:
            True if session is expired, False otherwise
        """
        if not self.is_authenticated():
            return True
        
        last_activity = session.get('last_activity')
        if last_activity is None:
            # If no last_activity, use authenticated_at or current time
            last_activity = session.get('authenticated_at', int(time.time()))
            # Update the session with current activity
            session['last_activity'] = last_activity
        
        current_time = int(time.time())
        
        return (current_time - last_activity) > self.session_timeout
    
    def validate_session(self) -> bool:
        """Validate the current session by testing the Vault connection.
        
        Returns:
            True if session is valid, False otherwise
        """
        if not self.is_authenticated():
            return False
        
        if self.is_session_expired():
            logger.info("Session expired, clearing session data")
            vault_url = session.get('vault_url')
            if vault_url:
                # Don't log the full URL as it may contain sensitive information
                audit_logger.log_session_timeout("[REDACTED]")
            self.clear_session()
            return False
        
        # Skip validation in testing mode
        from flask import current_app
        if current_app.config.get('TESTING', False):
            logger.debug("Skipping session validation in testing mode")
            return True
        
        try:
            vault_url = session.get('vault_url')
            encrypted_token = session.get('vault_token')
            
            # Decrypt the token
            vault_token = security_manager.decrypt_token(encrypted_token)
            
            # Test connection by validating token
            with VaultClient(vault_url, vault_token) as client:
                token_info = client.validate_token()
                
                # Update session with fresh token info
                session['token_info'] = token_info
                self.update_activity()
                
                logger.debug("Session validation successful")
                return True
                
        except (VaultAuthenticationError, VaultClientError) as e:
            logger.warning(f"Session validation failed: {e}")
            self.clear_session()
            return False
            
        except Exception as e:
            logger.error(f"Unexpected error during session validation: {e}")
            return False
    
    def clear_session(self) -> None:
        """Clear all session data."""
        vault_url = session.get('vault_url')
        user_session_id = session.get('_id')
        if vault_url:
            # Don't log the full URL as it may contain sensitive information
            logger.info(f"Clearing session for Vault")
        
        # Clear search results for this user session
        try:
            from app.routes.search import clear_user_search_results
            cleared_count = clear_user_search_results(user_session_id)
            if cleared_count > 0:
                logger.info(f"Cleared {cleared_count} search results during session clear")
        except Exception as e:
            logger.error(f"Failed to clear search results during session clear: {e}")
        
        session.clear()
    
    def get_vault_client(self) -> Optional[VaultClient]:
        """Get a Vault client for the current session.
        
        Returns:
            VaultClient instance or None if not authenticated
        """
        if not self.is_authenticated():
            return None
        
        vault_url = session.get('vault_url')
        encrypted_token = session.get('vault_token')
        
        if not vault_url or not encrypted_token:
            return None
        
        # Decrypt the token
        vault_token = security_manager.decrypt_token(encrypted_token)
        
        # Create and connect the client
        client = VaultClient(vault_url, vault_token)
        try:
            client.connect()
            return client
        except Exception as e:
            logger.error(f"Failed to connect Vault client: {e}")
            return None
    
    def refresh_session(self) -> bool:
        """Refresh the current session by re-validating with Vault.
        
        Returns:
            True if session was refreshed successfully, False otherwise
        """
        if not self.is_authenticated():
            return False
        
        try:
            vault_url = session.get('vault_url')
            encrypted_token = session.get('vault_token')
            
            # Decrypt the token
            vault_token = security_manager.decrypt_token(encrypted_token)
            
            with VaultClient(vault_url, vault_token) as client:
                token_info = client.validate_token()
                
                # Update session with fresh data
                session['token_info'] = token_info
                session['authenticated_at'] = int(time.time())
                self.update_activity()
                
                logger.info(f"Session refreshed for Vault at {vault_url}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to refresh session: {e}")
            self.clear_session()
            return False

    def authenticate(self, vault_url: str, vault_token: str, token_info: Dict[str, Any]) -> None:
        """
        Authenticate user and create session.
        
        Args:
            vault_url: Vault server URL
            vault_token: Vault authentication token
            token_info: Token information from Vault
        """
        try:
            # Encrypt the token for secure storage
            from app.security import security_manager
            encrypted_token = security_manager.encrypt_token(vault_token)
            
            # Store session data
            session['vault_url'] = vault_url
            session['vault_token'] = encrypted_token
            session['token_info'] = token_info
            session['connected'] = True
            session['authenticated_at'] = time.time()
            session['last_activity'] = time.time()
            session['_id'] = str(uuid.uuid4())  # Use _id to match what search code expects
            
            logger.info(f"User authenticated successfully with Vault at {vault_url}")
            
        except Exception as e:
            logger.error(f"Failed to create authentication session: {e}")
            raise
    
    def logout(self) -> None:
        """Clear session and logout user."""
        try:
            # Clear all session data
            session.clear()
            logger.info("User session cleared successfully")
        except Exception as e:
            logger.error(f"Error during logout: {e}")
            raise


# Global session manager instance
session_manager = SessionManager()
