"""
Unit tests for audit logger module.

This module tests audit logging functionality for security events and user actions.
"""

import pytest
from unittest.mock import patch, MagicMock
from app import create_app
from app.audit_logger import audit_logger


@pytest.fixture
def app():
    """Create a test Flask application."""
    app = create_app()
    app.config['TESTING'] = True
    return app


@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()


class TestAuditLogger:
    """Test audit logger functionality."""
    
    def test_log_authentication_success(self, app):
        """Test logging successful authentication."""
        with app.test_request_context('/test'):
            with patch.object(audit_logger.audit_logger, 'info') as mock_log:
                token_info = {
                    'id': 'test-token-id',
                    'policies': ['default', 'admin'],
                    'ttl': 3600
                }
                
                audit_logger.log_authentication_success('https://vault.example.com', token_info)
                
                mock_log.assert_called_once()
                call_args = mock_log.call_args
                assert 'Audit event' in call_args[0]
                assert call_args[1]['extra']['event_type'] == 'AUTHENTICATION_SUCCESS'
                assert call_args[1]['extra']['event_data']['vault_url'] == 'https://vault.example.com'
                assert call_args[1]['extra']['event_data']['token_id'] == 'test-token-id'
    
    def test_log_authentication_failure(self, app):
        """Test logging failed authentication."""
        with app.test_request_context('/test'):
            with patch.object(audit_logger.audit_logger, 'warning') as mock_log:
                audit_logger.log_authentication_failure('https://vault.example.com', 'Invalid token')
                
                mock_log.assert_called_once()
                call_args = mock_log.call_args
                assert 'Audit event' in call_args[0]
                assert call_args[1]['extra']['event_type'] == 'AUTHENTICATION_FAILURE'
                assert call_args[1]['extra']['event_data']['vault_url'] == 'https://vault.example.com'
                assert call_args[1]['extra']['event_data']['error_message'] == 'Invalid token'
    
    def test_log_logout(self, app):
        """Test logging logout."""
        with app.test_request_context('/test'):
            with patch.object(audit_logger.audit_logger, 'info') as mock_log:
                audit_logger.log_logout('https://vault.example.com')
                
                mock_log.assert_called_once()
                call_args = mock_log.call_args
                assert 'Audit event' in call_args[0]
                assert call_args[1]['extra']['event_type'] == 'LOGOUT'
                assert call_args[1]['extra']['event_data']['vault_url'] == 'https://vault.example.com'
    
    def test_log_session_timeout(self, app):
        """Test logging session timeout."""
        with app.test_request_context('/test'):
            with patch.object(audit_logger.audit_logger, 'warning') as mock_log:
                audit_logger.log_session_timeout('https://vault.example.com')
                
                mock_log.assert_called_once()
                call_args = mock_log.call_args
                assert 'Audit event' in call_args[0]
                assert call_args[1]['extra']['event_type'] == 'SESSION_TIMEOUT'
                assert call_args[1]['extra']['event_data']['vault_url'] == 'https://vault.example.com'
    
    def test_log_vault_operation_success(self, app):
        """Test logging successful Vault operation."""
        with app.test_request_context('/test'):
            with patch.object(audit_logger.audit_logger, 'info') as mock_log:
                audit_logger.log_vault_operation('read', 'secret/data/test', True)
                
                mock_log.assert_called_once()
                call_args = mock_log.call_args
                assert 'Audit event' in call_args[0]
                assert call_args[1]['extra']['event_type'] == 'VAULT_OPERATION'
                assert call_args[1]['extra']['event_data']['operation'] == 'read'
                assert call_args[1]['extra']['event_data']['path'] == 'secret/data/test'
                assert call_args[1]['extra']['event_data']['success'] is True
    
    def test_log_vault_operation_failure(self, app):
        """Test logging failed Vault operation."""
        with app.test_request_context('/test'):
            with patch.object(audit_logger.audit_logger, 'error') as mock_log:
                audit_logger.log_vault_operation('read', 'secret/data/test', False, 'Permission denied')
                
                mock_log.assert_called_once()
                call_args = mock_log.call_args
                assert 'Audit event' in call_args[0]
                assert call_args[1]['extra']['event_type'] == 'VAULT_OPERATION'
                assert call_args[1]['extra']['event_data']['operation'] == 'read'
                assert call_args[1]['extra']['event_data']['path'] == 'secret/data/test'
                assert call_args[1]['extra']['event_data']['success'] is False
                assert call_args[1]['extra']['event_data']['error_message'] == 'Permission denied'
    
    def test_log_search_operation_success(self, app):
        """Test logging successful search operation."""
        with app.test_request_context('/test'):
            with patch.object(audit_logger.audit_logger, 'info') as mock_log:
                audit_logger.log_search_operation('password', ['secret/', 'kv/'], 5, True)
                
                mock_log.assert_called_once()
                call_args = mock_log.call_args
                assert 'Audit event' in call_args[0]
                assert call_args[1]['extra']['event_type'] == 'SEARCH_OPERATION'
                assert call_args[1]['extra']['event_data']['search_term'] == 'password'
                assert call_args[1]['extra']['event_data']['engines'] == ['secret/', 'kv/']
                assert call_args[1]['extra']['event_data']['results_count'] == 5
                assert call_args[1]['extra']['event_data']['success'] is True
    
    def test_log_search_operation_failure(self, app):
        """Test logging failed search operation."""
        with app.test_request_context('/test'):
            with patch.object(audit_logger.audit_logger, 'error') as mock_log:
                audit_logger.log_search_operation('password', ['secret/'], 0, False, 'Timeout')
                
                mock_log.assert_called_once()
                call_args = mock_log.call_args
                assert 'Audit event' in call_args[0]
                assert call_args[1]['extra']['event_type'] == 'SEARCH_OPERATION'
                assert call_args[1]['extra']['event_data']['search_term'] == 'password'
                assert call_args[1]['extra']['event_data']['engines'] == ['secret/']
                assert call_args[1]['extra']['event_data']['results_count'] == 0
                assert call_args[1]['extra']['event_data']['success'] is False
                assert call_args[1]['extra']['event_data']['error_message'] == 'Timeout'
    
    def test_log_security_event(self, app):
        """Test logging security event."""
        with app.test_request_context('/test'):
            with patch.object(audit_logger.audit_logger, 'warning') as mock_log:
                details = {'ip': '192.168.1.1', 'attempts': 5}
                audit_logger.log_security_event('brute_force_attempt', details)
                
                mock_log.assert_called_once()
                call_args = mock_log.call_args
                assert 'Audit event' in call_args[0]
                assert call_args[1]['extra']['event_type'] == 'SECURITY_EVENT'
                assert call_args[1]['extra']['event_data']['security_event_type'] == 'brute_force_attempt'
                assert call_args[1]['extra']['event_data']['details'] == details
    
    def test_log_access_denied(self, app):
        """Test logging access denied event."""
        with app.test_request_context('/test'):
            with patch.object(audit_logger.audit_logger, 'warning') as mock_log:
                audit_logger.log_access_denied('/admin', 'Insufficient permissions')
                
                mock_log.assert_called_once()
                call_args = mock_log.call_args
                assert 'Audit event' in call_args[0]
                assert call_args[1]['extra']['event_type'] == 'ACCESS_DENIED'
                assert call_args[1]['extra']['event_data']['resource'] == '/admin'
                assert call_args[1]['extra']['event_data']['reason'] == 'Insufficient permissions'
    
    def test_log_configuration_change(self, app):
        """Test logging configuration change."""
        with app.test_request_context('/test'):
            with patch.object(audit_logger.audit_logger, 'info') as mock_log:
                audit_logger.log_configuration_change('DEBUG', False, True)
                
                mock_log.assert_called_once()
                call_args = mock_log.call_args
                assert 'Audit event' in call_args[0]
                assert call_args[1]['extra']['event_type'] == 'CONFIGURATION_CHANGE'
                assert call_args[1]['extra']['event_data']['setting'] == 'DEBUG'
                assert call_args[1]['extra']['event_data']['old_value'] == 'False'
                assert call_args[1]['extra']['event_data']['new_value'] == 'True'
    
    def test_log_system_event(self, app):
        """Test logging system event."""
        with app.test_request_context('/test'):
            with patch.object(audit_logger.audit_logger, 'info') as mock_log:
                details = {'component': 'database', 'status': 'connected'}
                audit_logger.log_system_event('service_start', details)
                
                mock_log.assert_called_once()
                call_args = mock_log.call_args
                assert 'Audit event' in call_args[0]
                assert call_args[1]['extra']['event_type'] == 'SYSTEM_EVENT'
                assert call_args[1]['extra']['event_data']['system_event_type'] == 'service_start'
                assert call_args[1]['extra']['event_data']['details'] == details
    
    def test_log_performance_event(self, app):
        """Test logging performance event."""
        with app.test_request_context('/test'):
            with patch.object(audit_logger.audit_logger, 'info') as mock_log:
                audit_logger.log_performance_event('search', 2.5, True)
                
                mock_log.assert_called_once()
                call_args = mock_log.call_args
                assert 'Audit event' in call_args[0]
                assert call_args[1]['extra']['event_type'] == 'PERFORMANCE_EVENT'
                assert call_args[1]['extra']['event_data']['operation'] == 'search'
                assert call_args[1]['extra']['event_data']['duration'] == 2.5
                assert call_args[1]['extra']['event_data']['success'] is True
    
    def test_log_data_access(self, app):
        """Test logging data access event."""
        with app.test_request_context('/test'):
            with patch.object(audit_logger.audit_logger, 'info') as mock_log:
                audit_logger.log_data_access('secrets', 'read', 'secret/data/test')
                
                mock_log.assert_called_once()
                call_args = mock_log.call_args
                assert 'Audit event' in call_args[0]
                assert call_args[1]['extra']['event_type'] == 'DATA_ACCESS'
                assert call_args[1]['extra']['event_data']['data_type'] == 'secrets'
                assert call_args[1]['extra']['event_data']['access_action'] == 'read'
                assert call_args[1]['extra']['event_data']['identifier'] == 'secret/data/test'
    
    def test_get_user_info_authenticated(self, app):
        """Test getting user info when authenticated."""
        with app.test_request_context('/test'):
            # Set session data directly
            from flask import session
            session['connected'] = True
            session['vault_url'] = 'https://vault.example.com'
            session['token_info'] = {'id': 'test-token', 'policies': ['default']}
            
            user_info = audit_logger._get_user_info()
            assert user_info['authenticated'] is True
            assert user_info['vault_url'] == 'https://vault.example.com'
            assert user_info['token_id'] == 'test-token'
            assert user_info['policies'] == ['default']
    
    def test_get_user_info_not_authenticated(self, app):
        """Test getting user info when not authenticated."""
        with app.test_request_context('/test'):
            user_info = audit_logger._get_user_info()
            assert user_info['authenticated'] is False
            assert 'vault_url' not in user_info
            assert 'token_id' not in user_info
    
    def test_get_request_info(self, app):
        """Test getting request info."""
        with app.test_request_context('/test'):
            request_info = audit_logger._get_request_info()
            assert request_info['method'] == 'GET'
            assert request_info['url'] == 'http://localhost/test'
            # endpoint might be None in test context
            assert 'timestamp' in request_info
