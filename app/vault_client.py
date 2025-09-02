"""
Vault Client Implementation

This module provides a comprehensive client for interacting with HashiCorp Vault,
including connection management, authentication, and secret engine operations.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse
import hvac
from hvac.exceptions import VaultError, InvalidRequest, Forbidden, Unauthorized, UnexpectedError
import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

from .logging_config import get_logger

logger = get_logger(__name__)


class VaultClientError(Exception):
    """Base exception for Vault client errors."""
    pass


class VaultConnectionError(VaultClientError):
    """Raised when unable to connect to Vault server."""
    pass


class VaultAuthenticationError(VaultClientError):
    """Raised when authentication fails."""
    pass


class VaultPermissionError(VaultClientError):
    """Raised when the token lacks required permissions."""
    pass


class VaultClient:
    """
    A comprehensive client for interacting with HashiCorp Vault.
    
    This client provides connection management, authentication validation,
    and secret engine enumeration capabilities.
    """
    
    def __init__(self, vault_url: str, token: str, timeout: int = 30):
        """
        Initialize the Vault client.
        
        Args:
            vault_url: The URL of the Vault server
            token: The authentication token
            timeout: Request timeout in seconds
        """
        self.vault_url = self._normalize_url(vault_url)
        self.token = token
        self.timeout = timeout
        self.client = None
        self._connection_established = False
        
        # Performance optimization settings
        self._session = None
        self._connection_pool_size = 10
        self._max_retries = 3
        
        # Don't log the full URL as it may contain sensitive information
        logger.info(f"Initializing Vault client")
        
    def _normalize_url(self, url: str) -> str:
        """
        Normalize the Vault URL to ensure proper format.
        
        Args:
            url: The raw URL
            
        Returns:
            Normalized URL
        """
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        # Remove trailing slash if present
        url = url.rstrip('/')
        
        return url
    
    def _optimize_connection(self):
        """
        Optimize the connection for better performance with large datasets.
        """
        try:
            # Configure session for connection pooling
            if hasattr(self.client, '_session') and self.client._session:
                session = self.client._session
                adapter = requests.adapters.HTTPAdapter(
                    pool_connections=self._connection_pool_size,
                    pool_maxsize=self._connection_pool_size,
                    max_retries=self._max_retries
                )
                session.mount('http://', adapter)
                session.mount('https://', adapter)
                
                logger.debug(f"Optimized connection with pool_size={self._connection_pool_size}, max_retries={self._max_retries}")
        except Exception as e:
            logger.debug(f"Could not optimize connection: {e}")
    
    def connect(self) -> bool:
        """
        Establish connection to the Vault server with performance optimizations.
        
        Returns:
            True if connection is successful, False otherwise
        """
        try:
            logger.debug(f"Attempting to connect to Vault at {self.vault_url}")
            
            # Initialize hvac client with performance optimizations
            self.client = hvac.Client(
                url=self.vault_url,
                token=self.token,
                timeout=self.timeout
            )
            
            # Optimize connection for performance
            self._optimize_connection()
            
            # Test connection by checking if the client is authenticated
            if not self.client.is_authenticated():
                logger.error("Vault client authentication failed")
                raise VaultAuthenticationError("Invalid token or authentication failed")
            
            # Test basic connectivity
            self._test_connection()
            
            self._connection_established = True
            logger.info("Successfully connected to Vault server")
            return True
            
        except VaultAuthenticationError:
            # Re-raise authentication errors as-is
            self._connection_established = False
            raise
        except Exception as e:
            logger.error(f"Failed to connect to Vault: {str(e)}")
            self._connection_established = False
            raise VaultConnectionError(f"Connection failed: {str(e)}")
    
    def _test_connection(self) -> None:
        """
        Test basic connectivity to the Vault server.
        
        Raises:
            VaultConnectionError: If connection test fails
        """
        try:
            # Try to access a basic endpoint
            response = self.client.sys.read_health_status()
            logger.debug(f"Vault health check response: {response}")
        except Exception as e:
            logger.error(f"Connection test failed: {str(e)}")
            raise VaultConnectionError(f"Connection test failed: {str(e)}")
    
    def is_connected(self) -> bool:
        """
        Check if the client is connected and authenticated.
        
        Returns:
            True if connected and authenticated, False otherwise
        """
        if not self._connection_established or not self.client:
            return False
        
        try:
            return self.client.is_authenticated()
        except Exception as e:
            logger.warning(f"Authentication check failed: {str(e)}")
            return False
    
    def validate_token(self) -> Dict[str, Any]:
        """
        Validate the current token and return token information.
        
        Returns:
            Dictionary containing token information
            
        Raises:
            VaultAuthenticationError: If token validation fails
        """
        if not self.is_connected():
            raise VaultConnectionError("Not connected to Vault server")
        
        try:
            logger.debug("Validating Vault token")
            
            # Get token lookup information
            token_info = self.client.auth.token.lookup_self()
            
            # Extract relevant information
            import datetime
            
            # Convert expire_time from ISO string to Unix timestamp if present
            expire_time = token_info['data'].get('expire_time')
            if expire_time and isinstance(expire_time, str):
                try:
                    # Handle ISO 8601 string with microseconds by removing them first
                    if '.' in expire_time:
                        # Remove microseconds and timezone info, then parse
                        expire_time_clean = expire_time.split('.')[0] + 'Z'
                        expire_dt = datetime.datetime.fromisoformat(expire_time_clean.replace('Z', '+00:00'))
                    else:
                        # No microseconds, parse directly
                        expire_dt = datetime.datetime.fromisoformat(expire_time.replace('Z', '+00:00'))
                    expire_time = int(expire_dt.timestamp())
                except (ValueError, TypeError) as e:
                    logger.warning(f"Failed to parse expire_time '{expire_time}': {e}")
                    expire_time = None
            
            token_data = {
                'id': token_info['data']['id'],
                'policies': token_info['data']['policies'],
                'ttl': token_info['data']['ttl'],
                'creation_time': token_info['data']['creation_time'],
                'expire_time': expire_time,
                'num_uses': token_info['data'].get('num_uses', 0),
                'orphan': token_info['data'].get('orphan', False),
                'renewable': token_info['data'].get('renewable', False)
            }
            
            logger.info(f"Token validated successfully. Policies: {token_data['policies']}")
            return token_data
            
        except Unauthorized:
            logger.error("Token validation failed: Unauthorized")
            raise VaultAuthenticationError("Invalid or expired token")
        except Exception as e:
            logger.error(f"Token validation failed: {str(e)}")
            raise VaultAuthenticationError(f"Token validation failed: {str(e)}")
    
    def list_secret_engines(self) -> List[Dict[str, Any]]:
        """
        List all available secret engines.
        
        Returns:
            List of secret engine information dictionaries
            
        Raises:
            VaultPermissionError: If the token lacks required permissions
        """
        if not self.is_connected():
            raise VaultConnectionError("Not connected to Vault server")
        
        try:
            logger.debug("Listing secret engines")
            
            # Get all mounted secret engines
            mounts = self.client.sys.list_mounted_secrets_engines()
            logger.debug(f"Raw mounts response: {mounts}")
            
            if not mounts or 'data' not in mounts:
                logger.error(f"Invalid response from Vault: {mounts}")
                raise VaultClientError("Invalid response from Vault when listing secret engines")
            
            engines = []
            for path, engine_info in mounts['data'].items():
                engine_data = {
                    'path': path,
                    'type': engine_info['type'],
                    'description': engine_info.get('description', ''),
                    'options': engine_info.get('options', {}),
                    'config': engine_info.get('config', {}),
                    'accessor': engine_info.get('accessor', '')
                }
                engines.append(engine_data)
            
            logger.info(f"Found {len(engines)} secret engines")
            return engines
            
        except Forbidden:
            logger.error("Permission denied: Cannot list secret engines")
            raise VaultPermissionError("Token lacks permission to list secret engines")
        except Unauthorized:
            logger.error("Unauthorized: Cannot list secret engines")
            raise VaultAuthenticationError("Token is invalid or expired")
        except InvalidRequest as e:
            logger.error(f"Invalid request when listing secret engines: {str(e)}")
            raise VaultClientError(f"Invalid request when listing secret engines: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to list secret engines: {str(e)}")
            logger.error(f"Exception type: {type(e).__name__}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            raise VaultClientError(f"Failed to list secret engines: {str(e)}")
    
    def list_secrets_in_engine(self, engine_path: str, recursive: bool = True) -> List[str]:
        """
        List all secrets in a specific secret engine.
        
        Args:
            engine_path: The path of the secret engine
            recursive: Whether to recursively list all sub-paths
            
        Returns:
            List of secret paths
            
        Raises:
            VaultPermissionError: If the token lacks required permissions
        """
        if not self.is_connected():
            raise VaultConnectionError("Not connected to Vault server")
        
        try:
            logger.debug(f"Listing secrets in engine: {engine_path}")
            
            secrets = []
            
            # Start with the root of the engine
            try:
                response = self.client.secrets.kv.v2.list_secrets(
                    path='',
                    mount_point=engine_path
                )
                
                if response and 'data' in response and 'keys' in response['data']:
                    for key in response['data']['keys']:
                        # Remove trailing slash if present
                        clean_key = key.rstrip('/')
                        secrets.append(clean_key)
                        
                        # If recursive and this looks like a directory (ends with /), explore it
                        if recursive and key.endswith('/'):
                            try:
                                sub_response = self.client.secrets.kv.v2.list_secrets(
                                    path=clean_key,
                                    mount_point=engine_path
                                )
                                
                                if sub_response and 'data' in sub_response and 'keys' in sub_response['data']:
                                    for sub_key in sub_response['data']['keys']:
                                        full_path = f"{clean_key}/{sub_key.rstrip('/')}"
                                        secrets.append(full_path)
                                        
                            except Exception as e:
                                # Skip sub-paths that can't be listed
                                logger.debug(f"Could not list sub-path {clean_key}: {e}")
                                continue
                                
            except Exception as e:
                logger.error(f"Failed to list secrets in engine {engine_path}: {str(e)}")
                raise VaultClientError(f"Failed to list secrets in engine {engine_path}: {str(e)}")
            
            logger.info(f"Found {len(secrets)} secrets in engine {engine_path}")
            return secrets
            
        except Exception as e:
            logger.error(f"Failed to list secrets in engine {engine_path}: {str(e)}")
            raise VaultClientError(f"Failed to list secrets in engine {engine_path}: {str(e)}")
    
    def get_secret(self, path: str, engine_path: str = None) -> Dict[str, Any]:
        """
        Retrieve a secret from Vault.
        
        Args:
            path: The path to the secret
            engine_path: The secret engine path (if different from default)
            
        Returns:
            Dictionary containing the secret data
            
        Raises:
            VaultPermissionError: If the token lacks required permissions
        """
        if not self.is_connected():
            raise VaultConnectionError("Not connected to Vault server")
        
        try:
            logger.debug(f"Retrieving secret: {path}")
            
            if engine_path:
                # Use specific engine path
                response = self.client.secrets.kv.v2.read_secret_version(
                    path=path,
                    mount_point=engine_path
                )
            else:
                # Use default KV store
                response = self.client.secrets.kv.v2.read_secret_version(path=path)
            
            if response and 'data' in response and 'data' in response['data']:
                secret_data = response['data']['data']
                logger.debug(f"Successfully retrieved secret: {path}")
                return secret_data
            else:
                logger.warning(f"No data found for secret: {path}")
                return {}
                
        except Forbidden:
            logger.error(f"Permission denied for secret: {path}")
            raise VaultPermissionError(f"Token lacks permission to access secret: {path}")
        except InvalidRequest as e:
            logger.error(f"Invalid request for secret {path}: {str(e)}")
            raise VaultClientError(f"Invalid request for secret {path}: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to retrieve secret {path}: {str(e)}")
            raise VaultClientError(f"Failed to retrieve secret {path}: {str(e)}")
    
    def search_secrets(self, search_term: str, engines: List[str] = None, 
                      case_sensitive: bool = False) -> List[Dict[str, Any]]:
        """
        Search for secrets containing the specified term.
        
        Args:
            search_term: The term to search for
            engines: List of engine paths to search in (None for all)
            case_sensitive: Whether the search should be case sensitive
            
        Returns:
            List of matching secrets with metadata
        """
        if not self.is_connected():
            raise VaultConnectionError("Not connected to Vault server")
        
        try:
            logger.info(f"Searching for term '{search_term}' in {len(engines) if engines else 'all'} engines")
            
            # Get all engines if none specified
            if not engines:
                all_engines = self.list_secret_engines()
                engines = [engine['path'] for engine in all_engines if engine['type'] == 'kv']
            
            results = []
            search_term_lower = search_term.lower() if not case_sensitive else search_term
            
            for engine_path in engines:
                try:
                    # List all secrets in this engine
                    secrets = self.list_secrets_in_engine(engine_path, recursive=True)
                    
                    for secret_path in secrets:
                        try:
                            # Get the secret data
                            secret_data = self.get_secret(secret_path, engine_path)
                            
                            # Search in secret data
                            if self._secret_matches_search(secret_data, search_term, case_sensitive):
                                result = {
                                    'engine_path': engine_path,
                                    'secret_path': secret_path,
                                    'full_path': f"{engine_path}/{secret_path}",
                                    'data': secret_data,
                                    'match_type': 'data'
                                }
                                results.append(result)
                                
                        except (VaultPermissionError, VaultClientError):
                            # Skip secrets we can't access
                            continue
                            
                except (VaultPermissionError, VaultClientError):
                    # Skip engines we can't access
                    continue
            
            logger.info(f"Search completed. Found {len(results)} matching secrets")
            return results
            
        except Exception as e:
            logger.error(f"Search failed: {str(e)}")
            raise VaultClientError(f"Search failed: {str(e)}")
    
    def _secret_matches_search(self, secret_data: Dict[str, Any], 
                              search_term: str, case_sensitive: bool) -> bool:
        """
        Check if a secret contains the search term.
        
        Args:
            secret_data: The secret data to search in
            search_term: The term to search for
            case_sensitive: Whether the search should be case sensitive
            
        Returns:
            True if the secret contains the search term
        """
        if not case_sensitive:
            search_term = search_term.lower()
        
        # Convert secret data to string for searching
        secret_str = str(secret_data)
        if not case_sensitive:
            secret_str = secret_str.lower()
        
        return search_term in secret_str
    
    def disconnect(self) -> None:
        """
        Disconnect from the Vault server and clean up resources.
        """
        if self.client:
            logger.debug("Disconnecting from Vault server")
            self.client = None
            self._connection_established = False
            logger.info("Disconnected from Vault server")
    
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()

    def get_auth_methods(self) -> List[str]:
        """
        Get available authentication methods from Vault.
        
        Returns:
            List of available auth method names
        """
        try:
            # Create a client without token to check auth methods
            if not self.client:
                self.client = hvac.Client(
                    url=self.vault_url,
                    timeout=self.timeout
                )
            
            response = self.client.sys.list_auth()
            if response and 'data' in response:
                return list(response['data'].keys())
            return []
        except Exception as e:
            logger.warning(f"Failed to get auth methods: {e}")
            return []
    
    def userpass_login(self, username: str, password: str) -> Dict[str, Any]:
        """
        Authenticate using userpass method.
        
        Args:
            username: Username for authentication
            password: Password for authentication
            
        Returns:
            Authentication response from Vault
        """
        try:
            # Create a fresh client without token for authentication
            auth_client = hvac.Client(url=self.vault_url, timeout=self.timeout)
            
            response = auth_client.auth.userpass.login(username, password)
            
            # Validate response
            if not response:
                raise VaultAuthenticationError("No response received from Vault")
            
            if 'auth' not in response:
                raise VaultAuthenticationError("Invalid response format from Vault")
            
            logger.info(f"Userpass login successful for user: {username}")
            return response
            
        except Exception as e:
            logger.error(f"Userpass login failed: {e}")
            raise VaultAuthenticationError(f"Userpass authentication failed: {str(e)}")
    
    def exchange_oidc_code(self, code: str, state: str = None) -> Dict[str, Any]:
        """
        Exchange OIDC authorization code for token.
        
        Args:
            code: Authorization code from OIDC provider
            state: State parameter for CSRF protection
            
        Returns:
            Token response from Vault
        """
        try:
            # Try different OIDC callback endpoints based on Vault's configuration
            endpoints_to_try = [
                "/v1/auth/oidc/oidc/callback",
                "/v1/auth/oidc/callback", 
                "/v1/auth/oidc/oidc/token",
                "/v1/auth/oidc/token"
            ]
            
            payload = {
                'code': code
            }
            if state:
                payload['state'] = state
            
            # Try each endpoint until one works
            for endpoint in endpoints_to_try:
                try:
                    logger.debug(f"Trying OIDC endpoint: {endpoint}")
                    response = self.client.adapter.post(
                        f"{self.client.url}{endpoint}",
                        json=payload,
                        timeout=30
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        logger.info(f"OIDC token exchange successful via {endpoint}")
                        return result
                    elif response.status_code == 404:
                        # Endpoint doesn't exist, try next one
                        logger.debug(f"OIDC endpoint {endpoint} not found, trying next")
                        continue
                    else:
                        logger.warning(f"OIDC endpoint {endpoint} returned {response.status_code}: {response.text}")
                        continue
                        
                except Exception as e:
                    logger.debug(f"OIDC endpoint {endpoint} failed: {e}")
                    continue
            
            # If we get here, none of the endpoints worked
            raise VaultAuthenticationError("No OIDC endpoints responded successfully")
                
        except Exception as e:
            logger.error(f"OIDC code exchange failed: {e}")
            raise VaultAuthenticationError(f"OIDC authentication failed: {str(e)}")
    
    def ldap_login(self, username: str, password: str) -> Dict[str, Any]:
        """
        Authenticate using LDAP method.
        
        Args:
            username: LDAP username for authentication
            password: LDAP password for authentication
            
        Returns:
            Authentication response from Vault
        """
        try:
            response = self.client.auth.ldap.login(username, password)
            return response
        except Exception as e:
            logger.error(f"LDAP login failed: {e}")
            raise VaultAuthenticationError(f"LDAP authentication failed: {str(e)}")
    
    def radius_login(self, username: str, password: str) -> Dict[str, Any]:
        """
        Authenticate using RADIUS method.
        
        Args:
            username: RADIUS username for authentication
            password: RADIUS password for authentication
            
        Returns:
            Authentication response from Vault
        """
        try:
            response = self.client.auth.radius.login(username, password)
            return response
        except Exception as e:
            logger.error(f"RADIUS login failed: {e}")
            raise VaultAuthenticationError(f"RADIUS authentication failed: {str(e)}")
    
    def approle_login(self, role_id: str, secret_id: str) -> Dict[str, Any]:
        """
        Authenticate using AppRole method.
        
        Args:
            role_id: AppRole role ID
            secret_id: AppRole secret ID
            
        Returns:
            Authentication response from Vault
        """
        try:
            response = self.client.auth.approle.login(role_id, secret_id)
            return response
        except Exception as e:
            logger.error(f"AppRole login failed: {e}")
            raise VaultAuthenticationError(f"AppRole authentication failed: {str(e)}")
    
    def kubernetes_login(self, role: str, jwt: str) -> Dict[str, Any]:
        """
        Authenticate using Kubernetes method.
        
        Args:
            role: Kubernetes role name
            jwt: Kubernetes service account JWT token
            
        Returns:
            Authentication response from Vault
        """
        try:
            response = self.client.auth.kubernetes.login(role, jwt)
            return response
        except Exception as e:
            logger.error(f"Kubernetes login failed: {e}")
            raise VaultAuthenticationError(f"Kubernetes authentication failed: {str(e)}")
    
    def aws_login(self, role: str, pkcs7: str = None, identity: str = None, 
                  signature: str = None, nonce: str = None) -> Dict[str, Any]:
        """
        Authenticate using AWS method.
        
        Args:
            role: AWS role name
            pkcs7: PKCS7 signature of the identity document
            identity: Base64 encoded EC2 instance identity document
            signature: Base64 encoded SHA256 RSA signature of the instance identity document
            nonce: Nonce for the authentication request
            
        Returns:
            Authentication response from Vault
        """
        try:
            response = self.client.auth.aws.login(role, pkcs7, identity, signature, nonce)
            return response
        except Exception as e:
            logger.error(f"AWS login failed: {e}")
            raise VaultAuthenticationError(f"AWS authentication failed: {str(e)}")
    
    def gcp_login(self, role: str, jwt: str) -> Dict[str, Any]:
        """
        Authenticate using Google Cloud Platform method.
        
        Args:
            role: GCP role name
            jwt: GCP service account JWT token
            
        Returns:
            Authentication response from Vault
        """
        try:
            response = self.client.auth.gcp.login(role, jwt)
            return response
        except Exception as e:
            logger.error(f"GCP login failed: {e}")
            raise VaultAuthenticationError(f"GCP authentication failed: {str(e)}")
    
    def azure_login(self, role: str, jwt: str) -> Dict[str, Any]:
        """
        Authenticate using Azure method.
        
        Args:
            role: Azure role name
            jwt: Azure managed identity JWT token
            
        Returns:
            Authentication response from Vault
        """
        try:
            response = self.client.auth.azure.login(role, jwt)
            return response
        except Exception as e:
            logger.error(f"Azure login failed: {e}")
            raise VaultAuthenticationError(f"Azure authentication failed: {str(e)}")
