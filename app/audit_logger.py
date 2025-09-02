"""
Audit logging for the Secret Sluth application.

This module provides comprehensive audit logging for security events,
user actions, and system activities for compliance and monitoring.
"""

import time
import json
from typing import Dict, Any, Optional, List
from datetime import datetime
from flask import request, session, current_app
from app.logging_config import get_logger

logger = get_logger(__name__)


class AuditLogger:
    """Audit logger for tracking security events and user actions."""
    
    def __init__(self):
        """Initialize the audit logger."""
        self.audit_logger = get_logger('audit')
    
    def _get_user_info(self) -> Dict[str, Any]:
        """Get current user information for audit logs.
        
        Returns:
            Dictionary with user information
        """
        user_info = {
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'session_id': session.get('_id', 'unknown'),
            'authenticated': session.get('connected', False)
        }
        
        if session.get('connected'):
            user_info.update({
                'vault_url': session.get('vault_url'),
                'token_id': session.get('token_info', {}).get('id', 'unknown'),
                'policies': session.get('token_info', {}).get('policies', [])
            })
        
        return user_info
    
    def _get_request_info(self) -> Dict[str, Any]:
        """Get request information for audit logs.
        
        Returns:
            Dictionary with request information
        """
        return {
            'method': request.method,
            'url': request.url,
            'endpoint': request.endpoint,
            'headers': dict(request.headers),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def _log_audit_event(self, event_type: str, event_data: Dict[str, Any], 
                        severity: str = 'INFO') -> None:
        """Log an audit event with structured data.
        
        Args:
            event_type: Type of audit event
            event_data: Event-specific data
            severity: Log severity level
        """
        audit_data = {
            'event_type': event_type,
            'event_data': event_data,
            'user_info': self._get_user_info(),
            'request_info': self._get_request_info(),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Log based on severity
        if severity == 'CRITICAL':
            self.audit_logger.critical("Audit event", extra=audit_data)
        elif severity == 'ERROR':
            self.audit_logger.error("Audit event", extra=audit_data)
        elif severity == 'WARNING':
            self.audit_logger.warning("Audit event", extra=audit_data)
        else:
            self.audit_logger.info("Audit event", extra=audit_data)
    
    def log_authentication_success(self, vault_url: str, token_info: Dict[str, Any]) -> None:
        """Log successful authentication.
        
        Args:
            vault_url: The Vault server URL
            token_info: Token information from Vault
        """
        event_data = {
            'action': 'authentication_success',
            'vault_url': vault_url,
            'token_id': token_info.get('id'),
            'policies': token_info.get('policies', []),
            'ttl': token_info.get('ttl')
        }
        
        self._log_audit_event('AUTHENTICATION_SUCCESS', event_data, 'INFO')
    
    def log_authentication_failure(self, vault_url: str, error_message: str) -> None:
        """Log failed authentication attempt.
        
        Args:
            vault_url: The Vault server URL
            error_message: Error message from authentication failure
        """
        event_data = {
            'action': 'authentication_failure',
            'vault_url': vault_url,
            'error_message': error_message
        }
        
        self._log_audit_event('AUTHENTICATION_FAILURE', event_data, 'WARNING')
    
    def log_logout(self, vault_url: str) -> None:
        """Log user logout.
        
        Args:
            vault_url: The Vault server URL
        """
        event_data = {
            'action': 'logout',
            'vault_url': vault_url
        }
        
        self._log_audit_event('LOGOUT', event_data, 'INFO')
    
    def log_session_timeout(self, vault_url: str) -> None:
        """Log session timeout.
        
        Args:
            vault_url: The Vault server URL
        """
        event_data = {
            'action': 'session_timeout',
            'vault_url': vault_url
        }
        
        self._log_audit_event('SESSION_TIMEOUT', event_data, 'WARNING')
    
    def log_vault_operation(self, operation: str, path: str, 
                           success: bool, error_message: str = None) -> None:
        """Log Vault operations.
        
        Args:
            operation: Type of Vault operation (read, write, list, etc.)
            path: Vault path being accessed
            success: Whether the operation was successful
            error_message: Error message if operation failed
        """
        event_data = {
            'action': 'vault_operation',
            'operation': operation,
            'path': path,
            'success': success
        }
        
        if error_message:
            event_data['error_message'] = error_message
        
        severity = 'ERROR' if not success else 'INFO'
        self._log_audit_event('VAULT_OPERATION', event_data, severity)
    
    def log_search_operation(self, search_term: str, engines: List[str], 
                           results_count: int, success: bool = True, 
                           error_message: str = None, duration: float = None) -> None:
        """Log search operations.
        
        Args:
            search_term: The search term used
            engines: List of engines searched
            results_count: Number of results found
            success: Whether the search was successful
            error_message: Error message if search failed
            duration: Search duration in seconds
        """
        event_data = {
            'action': 'search_operation',
            'search_term': search_term,
            'engines': engines,
            'results_count': results_count,
            'success': success
        }
        
        if duration is not None:
            event_data['duration'] = duration
            
        if error_message:
            event_data['error_message'] = error_message
        
        severity = 'ERROR' if not success else 'INFO'
        self._log_audit_event('SEARCH_OPERATION', event_data, severity)
    
    def log_security_event(self, event_type: str, details: Dict[str, Any], 
                          severity: str = 'WARNING') -> None:
        """Log security-related events.
        
        Args:
            event_type: Type of security event
            details: Event details
            severity: Log severity level
        """
        event_data = {
            'action': 'security_event',
            'security_event_type': event_type,
            'details': details
        }
        
        self._log_audit_event('SECURITY_EVENT', event_data, severity)
    
    def log_access_denied(self, resource: str, reason: str) -> None:
        """Log access denied events.
        
        Args:
            resource: Resource that access was denied to
            reason: Reason for access denial
        """
        event_data = {
            'action': 'access_denied',
            'resource': resource,
            'reason': reason
        }
        
        self._log_audit_event('ACCESS_DENIED', event_data, 'WARNING')
    
    def log_configuration_change(self, setting: str, old_value: Any, 
                                new_value: Any) -> None:
        """Log configuration changes.
        
        Args:
            setting: Configuration setting that changed
            old_value: Previous value
            new_value: New value
        """
        event_data = {
            'action': 'configuration_change',
            'setting': setting,
            'old_value': str(old_value),
            'new_value': str(new_value)
        }
        
        self._log_audit_event('CONFIGURATION_CHANGE', event_data, 'INFO')
    
    def log_system_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """Log system-level events.
        
        Args:
            event_type: Type of system event
            details: Event details
        """
        event_data = {
            'action': 'system_event',
            'system_event_type': event_type,
            'details': details
        }
        
        self._log_audit_event('SYSTEM_EVENT', event_data, 'INFO')
    
    def log_performance_event(self, operation: str, duration: float, 
                             success: bool) -> None:
        """Log performance-related events.
        
        Args:
            operation: Operation being measured
            duration: Duration in seconds
            success: Whether the operation was successful
        """
        event_data = {
            'action': 'performance_event',
            'operation': operation,
            'duration': duration,
            'success': success
        }
        
        self._log_audit_event('PERFORMANCE_EVENT', event_data, 'INFO')
    
    def log_data_access(self, data_type: str, action: str, 
                       identifier: str = None) -> None:
        """Log data access events.
        
        Args:
            data_type: Type of data being accessed
            action: Action performed (read, write, delete, etc.)
            identifier: Data identifier if applicable
        """
        event_data = {
            'action': 'data_access',
            'data_type': data_type,
            'access_action': action
        }
        
        if identifier:
            event_data['identifier'] = identifier
        
        self._log_audit_event('DATA_ACCESS', event_data, 'INFO')


# Global audit logger instance
audit_logger = AuditLogger()
