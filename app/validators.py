"""
Input validation and sanitization for the Secret Sluth application.

This module provides comprehensive input validation and sanitization
functions to prevent security vulnerabilities.
"""

import re
from typing import Optional, List, Dict, Any, Tuple
from urllib.parse import urlparse
from app.logging_config import get_logger

logger = get_logger(__name__)


class InputValidator:
    """Validates and sanitizes user input to prevent security issues."""
    
    def __init__(self):
        """Initialize the validator with common patterns."""
        # Common patterns for validation
        self.url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        self.token_pattern = re.compile(r'^[a-zA-Z0-9\-_\.]+$')
        self.path_pattern = re.compile(r'^[a-zA-Z0-9\-_/]+$')
        self.search_pattern = re.compile(r'^[a-zA-Z0-9\-_\.\s]+$')
    
    def validate_vault_url(self, url: str) -> Tuple[bool, str]:
        """Validate a Vault server URL.
        
        Args:
            url: The URL to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not url:
            return False, "Vault URL is required"
        
        url = url.strip()
        
        # Check basic URL format
        if not self.url_pattern.match(url):
            return False, "Invalid URL format. Must be a valid HTTP/HTTPS URL"
        
        # Parse URL for additional validation
        try:
            parsed = urlparse(url)
            
            # Check for dangerous schemes
            if parsed.scheme not in ['http', 'https']:
                return False, "Only HTTP and HTTPS URLs are allowed"
            
            # Check for localhost or private IP ranges
            if parsed.hostname in ['localhost', '127.0.0.1']:
                return False, "Localhost URLs are not allowed for security reasons"
            
            # Check for private IP ranges
            if self._is_private_ip(parsed.hostname):
                return False, "Private IP addresses are not allowed for security reasons"
            
            # Check port if specified
            if parsed.port and not (1 <= parsed.port <= 65535):
                return False, "Invalid port number"
            
            return True, ""
            
        except Exception as e:
            logger.error(f"Error parsing URL {url}: {e}")
            return False, "Invalid URL format"
    
    def validate_vault_token(self, token: str) -> Tuple[bool, str]:
        """Validate a Vault authentication token.
        
        Args:
            token: The token to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not token:
            return False, "Vault token is required"
        
        token = token.strip()
        
        # Check token length
        if len(token) < 10:
            return False, "Token appears to be too short"
        
        if len(token) > 1000:
            return False, "Token appears to be too long"
        
        # Check for basic token format (alphanumeric, hyphens, underscores, dots)
        if not self.token_pattern.match(token):
            return False, "Token contains invalid characters"
        
        # Check for common patterns that might indicate it's not a real token
        if token.lower() in ['test', 'demo', 'example', 'token', 'password']:
            return False, "Token appears to be a placeholder value"
        
        return True, ""
    
    def validate_search_term(self, term: str) -> Tuple[bool, str]:
        """Validate a search term.
        
        Args:
            term: The search term to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not term:
            return False, "Search term is required"
        
        term = term.strip()
        
        # Check length
        if len(term) < 2:
            return False, "Search term must be at least 2 characters long"
        
        if len(term) > 100:
            return False, "Search term is too long (maximum 100 characters)"
        
        # Check for dangerous patterns
        dangerous_patterns = [
            '..', '//', '\\', 'script', 'javascript', 'data:', 'vbscript:'
        ]
        
        term_lower = term.lower()
        for pattern in dangerous_patterns:
            if pattern in term_lower:
                return False, f"Search term contains invalid pattern: {pattern}"
        
        # Check for basic character set
        if not self.search_pattern.match(term):
            return False, "Search term contains invalid characters"
        
        return True, ""
    
    def validate_path(self, path: str) -> Tuple[bool, str]:
        """Validate a file or directory path.
        
        Args:
            path: The path to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not path:
            return False, "Path is required"
        
        path = path.strip()
        
        # Check for path traversal attempts
        dangerous_patterns = [
            '..', '//', '\\', '~', '..\\', '../', '..\\', '..//'
        ]
        
        for pattern in dangerous_patterns:
            if pattern in path:
                return False, f"Path contains invalid pattern: {pattern}"
        
        # Check for absolute paths
        if path.startswith('/') or path.startswith('\\'):
            return False, "Absolute paths are not allowed"
        
        # Check for basic character set
        if not self.path_pattern.match(path):
            return False, "Path contains invalid characters"
        
        return True, ""
    
    def sanitize_input(self, input_str: str, max_length: int = 1000) -> str:
        """Sanitize user input to prevent XSS and injection attacks.
        
        Args:
            input_str: The input string to sanitize
            max_length: Maximum allowed length
            
        Returns:
            Sanitized string
        """
        if not input_str:
            return ""
        
        # Convert to string if needed
        input_str = str(input_str)
        
        # Remove null bytes and control characters
        input_str = ''.join(char for char in input_str if ord(char) >= 32)
        
        # Remove potentially dangerous HTML/script tags
        dangerous_tags = [
            '<script', '</script>', '<iframe', '</iframe>', '<object', '</object>',
            '<embed', '</embed>', '<form', '</form>', '<input', '<textarea',
            '<select', '<option', '<button', '<link', '<meta', '<style', '</style>',
            'javascript:', 'vbscript:', 'data:', 'onload=', 'onerror=', 'onclick='
        ]
        
        input_lower = input_str.lower()
        for tag in dangerous_tags:
            input_lower = input_lower.replace(tag, '')
        
        # Remove SQL injection patterns
        sql_patterns = [
            'union', 'select', 'insert', 'update', 'delete', 'drop', 'create',
            'alter', 'exec', 'execute', 'declare', 'cast', 'convert'
        ]
        
        for pattern in sql_patterns:
            # Use word boundaries to avoid false positives
            pattern_regex = re.compile(r'\b' + re.escape(pattern) + r'\b', re.IGNORECASE)
            input_str = pattern_regex.sub('', input_str)
        
        # Remove command injection patterns
        command_patterns = [
            ';', '|', '&', '`', '$', '(', ')', '{', '}', '[', ']'
        ]
        
        for pattern in command_patterns:
            input_str = input_str.replace(pattern, '')
        
        # Truncate to maximum length
        if len(input_str) > max_length:
            input_str = input_str[:max_length]
        
        return input_str.strip()
    
    def validate_search_query(self, query: str) -> Tuple[bool, str]:
        """Enhanced validation for search queries with regex and wildcard support.
        
        Args:
            query: The search query to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not query:
            return False, "Search query is required"
        
        query = query.strip()
        
        # Check length
        if len(query) < 1:
            return False, "Search query cannot be empty"
        
        if len(query) > 200:
            return False, "Search query is too long (maximum 200 characters)"
        
        # Check for regex patterns
        if query.startswith('/') and query.endswith('/'):
            # Validate regex pattern
            try:
                pattern = query[1:-1]  # Remove delimiters
                re.compile(pattern)
            except re.error as e:
                return False, f"Invalid regex pattern: {str(e)}"
        
        # Check for dangerous patterns
        dangerous_patterns = [
            '..', '//', '\\', 'script', 'javascript', 'data:', 'vbscript:',
            'file://', 'ftp://', 'gopher://', 'mailto:', 'telnet://'
        ]
        
        query_lower = query.lower()
        for pattern in dangerous_patterns:
            if pattern in query_lower:
                return False, f"Search query contains invalid pattern: {pattern}"
        
        # Check for excessive wildcards (potential DoS)
        if query.count('*') > 10 or query.count('?') > 20:
            return False, "Too many wildcards in search query"
        
        return True, ""
    
    def validate_numeric_input(self, value: str, min_val: int = None, max_val: int = None) -> Tuple[bool, str]:
        """Validate numeric input with range checking.
        
        Args:
            value: The numeric value to validate
            min_val: Minimum allowed value
            max_val: Maximum allowed value
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not value:
            return False, "Numeric value is required"
        
        try:
            num_val = int(value)
        except ValueError:
            return False, "Value must be a valid integer"
        
        if min_val is not None and num_val < min_val:
            return False, f"Value must be at least {min_val}"
        
        if max_val is not None and num_val > max_val:
            return False, f"Value must be at most {max_val}"
        
        return True, ""
    
    def validate_engine_filter(self, filter_value: str) -> Tuple[bool, str]:
        """Validate engine filter values.
        
        Args:
            filter_value: The engine filter to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not filter_value:
            return True, ""  # Empty filter is valid (no filtering)
        
        allowed_filters = ['kv', 'database', 'ssh', 'pki', 'transit', 'aws', 'azure', 'gcp']
        
        if filter_value not in allowed_filters:
            return False, f"Invalid engine filter. Allowed values: {', '.join(allowed_filters)}"
        
        return True, ""
    
    def validate_match_type_filter(self, filter_value: str) -> Tuple[bool, str]:
        """Validate match type filter values.
        
        Args:
            filter_value: The match type filter to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not filter_value:
            return True, ""  # Empty filter is valid (no filtering)
        
        allowed_filters = ['name', 'key', 'value', 'metadata']
        
        if filter_value not in allowed_filters:
            return False, f"Invalid match type filter. Allowed values: {', '.join(allowed_filters)}"
        
        return True, ""
    
    def validate_form_data(self, form_data: Dict[str, Any]) -> Tuple[bool, Dict[str, str]]:
        """Validate form data for common fields.
        
        Args:
            form_data: Dictionary of form data
            
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = {}
        
        # Validate Vault URL if present
        if 'vault_url' in form_data:
            is_valid, error = self.validate_vault_url(form_data['vault_url'])
            if not is_valid:
                errors['vault_url'] = error
        
        # Validate Vault token if present
        if 'vault_token' in form_data:
            is_valid, error = self.validate_vault_token(form_data['vault_token'])
            if not is_valid:
                errors['vault_token'] = error
        
        # Validate search term if present
        if 'search_term' in form_data:
            is_valid, error = self.validate_search_term(form_data['search_term'])
            if not is_valid:
                errors['search_term'] = error
        
        return len(errors) == 0, errors
    
    def _is_private_ip(self, hostname: str) -> bool:
        """Check if a hostname resolves to a private IP address.
        
        Args:
            hostname: The hostname to check
            
        Returns:
            True if it's a private IP, False otherwise
        """
        if not hostname:
            return False
        
        # Check for common private IP patterns
        private_patterns = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
            r'^192\.168\.',
            r'^127\.',
            r'^169\.254\.',
            r'^::1$',  # IPv6 localhost
            r'^fe80:',  # IPv6 link-local
        ]
        
        for pattern in private_patterns:
            if re.match(pattern, hostname):
                return True
        
        return False
    
    def validate_json_payload(self, payload: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate JSON payload structure and content.
        
        Args:
            payload: The JSON payload to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not isinstance(payload, dict):
            return False, "Payload must be a JSON object"
        
        # Check for required fields if this is an authentication payload
        if 'vault_url' in payload or 'vault_token' in payload:
            if 'vault_url' not in payload:
                return False, "vault_url is required"
            if 'vault_token' not in payload:
                return False, "vault_token is required"
        
        # Check payload size
        import json
        payload_str = json.dumps(payload)
        if len(payload_str) > 10000:  # 10KB limit
            return False, "Payload is too large"
        
        return True, ""


# Global validator instance
input_validator = InputValidator()
