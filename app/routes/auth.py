"""
Authentication routes for the Secret Sluth application.

This module handles Vault authentication, session management, and logout functionality.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app, jsonify
from app.vault_client import VaultClient, VaultClientError, VaultAuthenticationError, VaultConnectionError
from app.validators import input_validator
from app.audit_logger import audit_logger
from app.logging_config import get_logger
from app.middleware.rate_limit_middleware import rate_limit
import urllib.parse
import time
import hvac
from typing import Optional

logger = get_logger(__name__)

auth = Blueprint('auth', __name__, url_prefix='/auth')


def _auto_discover_token(vault_url: str) -> Optional[str]:
    """
    Automatically discover Vault tokens from common sources.
    
    Args:
        vault_url: The Vault server URL
        
    Returns:
        Token if found, None otherwise
    """
    import os
    
    # Check environment variables
    env_vars = [
        'VAULT_TOKEN',
        'VAULT_CLIENT_TOKEN',
        'VAULT_AUTH_TOKEN'
    ]
    
    for env_var in env_vars:
        token = os.environ.get(env_var)
        if token:
            logger.info(f"Found token in environment variable: {env_var}")
            return token
    
    # Check common token file locations
    token_files = [
        os.path.expanduser('~/.vault-token'),
        os.path.expanduser('~/.vault_token'),
        '/etc/vault/token',
        '/var/lib/vault/token'
    ]
    
    for token_file in token_files:
        if os.path.exists(token_file):
            try:
                with open(token_file, 'r') as f:
                    token = f.read().strip()
                    if token:
                        logger.info(f"Found token in file: {token_file}")
                        return token
            except Exception as e:
                logger.debug(f"Could not read token file {token_file}: {e}")
    
    # Check Kubernetes service account token (if running in K8s)
    k8s_token_file = '/var/run/secrets/kubernetes.io/serviceaccount/token'
    if os.path.exists(k8s_token_file):
        try:
            with open(k8s_token_file, 'r') as f:
                token = f.read().strip()
                if token:
                    logger.info("Found Kubernetes service account token")
                    return token
        except Exception as e:
            logger.debug(f"Could not read Kubernetes token: {e}")
    
    return None


@auth.route('/login', methods=['GET', 'POST'])
@rate_limit('auth')
def login():
    """Handle Vault authentication login."""
    if request.method == 'GET':
        return render_template('auth/login.html')
    
    # Verify CSRF token if enabled
    if current_app.config.get('CSRF_ENABLED', True):
        from app.security import security_manager
        csrf_token = request.form.get('csrf_token')
        if not csrf_token or not security_manager.verify_csrf_token(csrf_token):
            logger.warning("Invalid CSRF token in login request")
            flash('Invalid CSRF token', 'error')
            return render_template('auth/login.html'), 400
    
    # Get form data
    vault_url = request.form.get('vault_url', '').strip()
    auth_method = request.form.get('auth_method', 'auto').strip()
    
    # Enhanced validation using the global validator instance
    # Validate Vault URL
    is_valid, error_msg = input_validator.validate_vault_url(vault_url)
    if not is_valid:
        logger.warning(f"Invalid Vault URL: {vault_url} - {error_msg}")
        flash(error_msg, 'error')
        return render_template('auth/login.html'), 400
    
    try:
        # Store Vault URL in session for the authentication flow
        session['vault_url'] = vault_url
        
        # Try to auto-discover tokens first
        auto_token = _auto_discover_token(vault_url)
        if auto_token:
            try:
                # Test the auto-discovered token
                client = VaultClient(vault_url, auto_token)
                client.connect()
                token_info = client.validate_token()
                
                # Store authentication in session
                from app.session_manager import session_manager
                session_manager.authenticate(vault_url, auto_token, token_info)
                
                # Log successful authentication
                audit_logger.log_authentication_success(vault_url, token_info)
                
                logger.info("Auto-discovered token authentication successful")
                flash('Successfully authenticated with auto-discovered token!', 'success')
                return redirect(url_for('main.dashboard'))
                
            except Exception as e:
                logger.warning(f"Auto-discovered token failed: {e}")
                # Continue with normal auth method detection
        
        # Check if user wants token-only authentication
        if auth_method == 'token':
            logger.info("User selected token-only authentication, redirecting to token login")
            return redirect(url_for('auth.token_login'))
        
        # Try to detect available auth methods directly
        logger.info("Detecting available authentication methods")
        
        # Try userpass first (most common)
        try:
            # Create hvac client directly without authentication
            client = hvac.Client(url=vault_url, timeout=30)
            # Test if userpass endpoint exists by trying to access login endpoint
            response = client.adapter.get("/v1/auth/userpass/login/test")
            logger.info(f"Userpass endpoint response: {response.status_code}")
            if response.status_code in [400, 403, 405]:  # These responses indicate endpoint exists
                logger.info("Userpass auth method detected, redirecting to userpass login")
                return redirect(url_for('auth.userpass_login'))
            else:
                logger.info(f"Userpass endpoint not detected (status: {response.status_code})")
        except Exception as e:
            # Check if the exception indicates the endpoint exists (405 = unsupported operation)
            if "unsupported operation" in str(e).lower():
                logger.info("Userpass auth method detected (405 error), redirecting to userpass login")
                return redirect(url_for('auth.userpass_login'))
            else:
                logger.warning(f"Userpass detection failed: {e}")
        
        # Try LDAP
        try:
            # Create hvac client directly without authentication
            client = hvac.Client(url=vault_url, timeout=30)
            response = client.adapter.get("/v1/auth/ldap/login")
            if response.status_code in [400, 403, 405]:  # These responses indicate endpoint exists
                logger.info("LDAP auth method detected, redirecting to LDAP login")
                return redirect(url_for('auth.ldap_login'))
        except Exception as e:
            # Check if the exception indicates the endpoint exists
            if "permission denied" in str(e).lower():
                logger.info("LDAP auth method detected (403 error), redirecting to LDAP login")
                return redirect(url_for('auth.ldap_login'))
            else:
                logger.debug(f"LDAP detection failed: {e}")
        
        # Try OIDC/OAuth
        try:
            # Create hvac client directly without authentication
            client = hvac.Client(url=vault_url, timeout=30)
            response = client.adapter.get("/v1/auth/oidc/login")
            if response.status_code in [200, 400, 403, 405]:  # These responses indicate endpoint exists
                logger.info("OIDC/OAuth auth method detected, redirecting to OIDC login")
                # Redirect to Vault's OIDC/OAuth endpoint
                auth_url = f"{vault_url}/v1/auth/oidc/login"
                redirect_url = url_for('auth.callback_page', _external=True)
                full_auth_url = f"{auth_url}?redirect_uri={urllib.parse.quote(redirect_url)}"
                
                logger.info(f"Redirecting to Vault OIDC/OAuth: {full_auth_url}")
                return redirect(full_auth_url)
        except Exception as e:
            # Check if the exception indicates the endpoint exists
            if "permission denied" in str(e).lower():
                logger.info("OIDC/OAuth auth method detected (403 error), redirecting to OIDC login")
                # Redirect to Vault's OIDC/OAuth endpoint
                auth_url = f"{vault_url}/v1/auth/oidc/login"
                redirect_url = url_for('auth.callback_page', _external=True)
                full_auth_url = f"{auth_url}?redirect_uri={urllib.parse.quote(redirect_url)}"
                
                logger.info(f"Redirecting to Vault OIDC/OAuth: {full_auth_url}")
                return redirect(full_auth_url)
            else:
                logger.debug(f"OIDC detection failed: {e}")
        
        # Fallback to token login
        logger.info("No interactive auth methods detected, redirecting to token login")
        return redirect(url_for('auth.token_login'))
            
    except VaultConnectionError as e:
        logger.error(f"Failed to connect to Vault: {e}")
        flash(f'Failed to connect to Vault server: {str(e)}', 'error')
        return render_template('auth/login.html', vault_url=vault_url)
        
    except Exception as e:
        logger.error(f"Unexpected error during login: {e}")
        flash(f'Unexpected error: {str(e)}', 'error')
        return render_template('auth/login.html', vault_url=vault_url)


@auth.route('/token-login', methods=['GET', 'POST'])
@rate_limit('auth')
def token_login():
    """Handle token-based authentication for service accounts."""
    if request.method == 'GET':
        try:
            vault_url = session.get('vault_url')
            logger.info(f"Token login GET request, vault_url in session: {vault_url}")
            if not vault_url:
                flash('Please enter a Vault URL first', 'error')
                return redirect(url_for('auth.login'))
            return render_template('auth/token_login.html', vault_url=vault_url)
        except Exception as e:
            logger.error(f"Error in token_login GET: {e}")
            flash('An error occurred while loading the token login page', 'error')
            return redirect(url_for('auth.login'))
    
    # Verify CSRF token
    if current_app.config.get('CSRF_ENABLED', True):
        from app.security import security_manager
        csrf_token = request.form.get('csrf_token')
        if not csrf_token or not security_manager.verify_csrf_token(csrf_token):
            logger.warning("Invalid CSRF token in token login request")
            flash('Invalid CSRF token', 'error')
            return render_template('auth/token_login.html'), 400
    
    vault_url = session.get('vault_url')
    vault_token = request.form.get('vault_token', '').strip()
    
    # Validate token
    is_valid, error_msg = input_validator.validate_vault_token(vault_token)
    if not is_valid:
        logger.warning(f"Invalid Vault token (length: {len(vault_token)}) - {error_msg}")
        flash(error_msg, 'error')
        return render_template('auth/token_login.html', vault_url=vault_url), 400
    
    try:
        # Test the token
        client = VaultClient(vault_url, vault_token)
        with client:
            token_info = client.validate_token()
            
            # Store authentication in session
            from app.session_manager import session_manager
            session_manager.authenticate(vault_url, vault_token, token_info)
            
            # Log successful authentication
            audit_logger.log_authentication_success(vault_url, token_info)
            
            logger.info(f"Token authentication successful for {vault_url}")
            flash('Successfully authenticated with Vault!', 'success')
            return redirect(url_for('main.dashboard'))
            
    except VaultAuthenticationError as e:
        logger.error(f"Token authentication failed: {e}")
        flash(f'Authentication failed: {str(e)}', 'error')
        return render_template('auth/token_login.html', vault_url=vault_url)
        
    except Exception as e:
        logger.error(f"Unexpected error during token authentication: {e}")
        flash(f'Unexpected error: {str(e)}', 'error')
        return render_template('auth/token_login.html', vault_url=vault_url)


@auth.route('/userpass-login', methods=['GET', 'POST'])
@rate_limit('auth')
def userpass_login():
    """Handle userpass authentication."""
    if request.method == 'GET':
        vault_url = session.get('vault_url')
        if not vault_url:
            flash('Please enter a Vault URL first', 'error')
            return redirect(url_for('auth.login'))
        return render_template('auth/userpass_login.html', vault_url=vault_url)
    
    # Handle userpass authentication
    vault_url = session.get('vault_url')
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    
    if not username or not password:
        flash('Username and password are required', 'error')
        return render_template('auth/userpass_login.html', vault_url=vault_url)
    
    try:
        # Attempt userpass authentication
        client = VaultClient(vault_url, None)
        auth_response = client.userpass_login(username, password)
        
        if auth_response and 'auth' in auth_response:
            token = auth_response['auth']['client_token']
            token_info = auth_response['auth']
            
            # Store authentication in session
            from app.session_manager import session_manager
            session_manager.authenticate(vault_url, token, token_info)
            
            # Log successful authentication
            audit_logger.log_authentication_success(vault_url, token_info)
            
            logger.info(f"Userpass authentication successful for user {username}")
            flash('Successfully authenticated with Vault!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Authentication failed: Invalid response from Vault', 'error')
            return render_template('auth/userpass_login.html', vault_url=vault_url)
            
    except VaultAuthenticationError as e:
        logger.error(f"Userpass authentication failed: {e}")
        flash(f'Authentication failed: {str(e)}', 'error')
        return render_template('auth/userpass_login.html', vault_url=vault_url)
        
    except Exception as e:
        logger.error(f"Unexpected error during userpass authentication: {e}")
        flash(f'Unexpected error: {str(e)}', 'error')
        return render_template('auth/userpass_login.html', vault_url=vault_url)


@auth.route('/ldap-login', methods=['GET', 'POST'])
@rate_limit('auth')
def ldap_login():
    """Handle LDAP authentication."""
    if request.method == 'GET':
        vault_url = session.get('vault_url')
        if not vault_url:
            flash('Please enter a Vault URL first', 'error')
            return redirect(url_for('auth.login'))
        return render_template('auth/ldap_login.html', vault_url=vault_url)
    
    # Handle LDAP authentication
    vault_url = session.get('vault_url')
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    
    if not username or not password:
        flash('Username and password are required', 'error')
        return render_template('auth/ldap_login.html', vault_url=vault_url)
    
    try:
        # Attempt LDAP authentication
        client = VaultClient(vault_url, None)
        auth_response = client.ldap_login(username, password)
        
        if auth_response and 'auth' in auth_response:
            token = auth_response['auth']['client_token']
            token_info = auth_response['auth']
            
            # Store authentication in session
            from app.session_manager import session_manager
            session_manager.authenticate(vault_url, token, token_info)
            
            # Log successful authentication
            audit_logger.log_authentication_success(vault_url, token_info)
            
            logger.info(f"LDAP authentication successful for user {username}")
            flash('Successfully authenticated with Vault!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Authentication failed: Invalid response from Vault', 'error')
            return render_template('auth/ldap_login.html', vault_url=vault_url)
            
    except VaultAuthenticationError as e:
        logger.error(f"LDAP authentication failed: {e}")
        flash(f'Authentication failed: {str(e)}', 'error')
        return render_template('auth/ldap_login.html', vault_url=vault_url)
        
    except Exception as e:
        logger.error(f"Unexpected error during LDAP authentication: {e}")
        flash(f'Unexpected error: {str(e)}', 'error')
        return render_template('auth/ldap_login.html', vault_url=vault_url)


@auth.route('/callback')
def callback():
    """Handle OIDC/OAuth callback from Vault."""
    try:
        # Get parameters from the callback
        code = request.args.get('code')
        state = request.args.get('state')
        error = request.args.get('error')
        error_description = request.args.get('error_description')
        
        # Check for OAuth implicit flow tokens (access_token, id_token)
        access_token = request.args.get('access_token')
        id_token = request.args.get('id_token')
        
        # Check for URL fragment tokens (OAuth implicit flow)
        # Note: URL fragments are not sent to the server, so we need to handle this differently
        # For now, we'll rely on query parameters, but this could be enhanced with JavaScript
        
        # Check for errors first
        if error:
            logger.error(f"OIDC callback error: {error} - {error_description}")
            flash(f'Authentication failed: {error_description or error}', 'error')
            return redirect(url_for('auth.login'))
        
        # Get Vault URL from session
        vault_url = session.get('vault_url')
        if not vault_url:
            logger.error("No Vault URL found in session during OIDC callback")
            flash('Authentication failed: Session expired', 'error')
            return redirect(url_for('auth.login'))
        
        # Handle OAuth implicit flow (tokens in URL fragment)
        if access_token or id_token:
            logger.info("Handling OAuth implicit flow callback")
            try:
                # For implicit flow, we might need to exchange the access_token for a Vault token
                # or use it directly depending on Vault's configuration
                if access_token:
                    # Try to use access_token as Vault token
                    client = VaultClient(vault_url, access_token)
                    client.connect()
                    token_info = client.validate_token()
                    
                    # Store authentication in session
                    from app.session_manager import session_manager
                    session_manager.authenticate(vault_url, access_token, token_info)
                    
                    # Log successful authentication
                    audit_logger.log_authentication_success(vault_url, token_info)
                    
                    logger.info("OAuth implicit flow authentication successful")
                    flash('Successfully authenticated with Vault!', 'success')
                    return redirect(url_for('main.dashboard'))
                else:
                    flash('Authentication failed: No access token received', 'error')
                    return redirect(url_for('auth.login'))
                    
            except Exception as e:
                logger.error(f"OAuth implicit flow failed: {e}")
                flash(f'Authentication failed: {str(e)}', 'error')
                return redirect(url_for('auth.login'))
        
        # Handle authorization code flow
        if not code:
            logger.error("OIDC callback received without authorization code or tokens")
            flash('Authentication failed: No authorization code or tokens received', 'error')
            return redirect(url_for('auth.login'))
        
        try:
            # Exchange the authorization code for a token
            client = VaultClient(vault_url, None)  # No token yet
            token_response = client.exchange_oidc_code(code, state)
            
            if token_response and 'auth' in token_response:
                # Extract token information
                auth_data = token_response['auth']
                vault_token = auth_data.get('client_token')
                token_info = {
                    'id': auth_data.get('client_token'),
                    'policies': auth_data.get('policies', []),
                    'ttl': auth_data.get('lease_duration'),
                    'renewable': auth_data.get('renewable', False),
                    'creation_time': int(time.time()),
                    'expire_time': None
                }
                
                if auth_data.get('lease_duration'):
                    token_info['expire_time'] = int(time.time()) + auth_data['lease_duration']
                
                # Store authentication in session
                from app.session_manager import session_manager
                session_manager.authenticate(vault_url, vault_token, token_info)
                
                # Log successful authentication
                audit_logger.log_authentication_success(vault_url, token_info)
                
                logger.info("OIDC/OAuth authentication successful")
                flash('Successfully authenticated with Vault!', 'success')
                return redirect(url_for('main.dashboard'))
            else:
                logger.error("Invalid token response from OIDC exchange")
                flash('Authentication failed: Invalid response from Vault', 'error')
                return redirect(url_for('auth.login'))
                
        except Exception as e:
            logger.error(f"OIDC token exchange failed: {e}")
            flash(f'Authentication failed: {str(e)}', 'error')
            return redirect(url_for('auth.login'))
            
    except Exception as e:
        logger.error(f"Unexpected error in OIDC callback: {e}")
        flash(f'Authentication failed: {str(e)}', 'error')
        return redirect(url_for('auth.login'))


@auth.route('/callback', methods=['POST'])
def callback_post():
    """Handle OAuth implicit flow tokens sent via POST."""
    try:
        # Get tokens from form data
        access_token = request.form.get('access_token')
        id_token = request.form.get('id_token')
        
        if not access_token:
            return jsonify({
                'success': False,
                'message': 'No access token received'
            }), 400
        
        # Get Vault URL from session
        vault_url = session.get('vault_url')
        if not vault_url:
            return jsonify({
                'success': False,
                'message': 'Session expired'
            }), 400
        
        try:
            # Try to use access_token as Vault token
            client = VaultClient(vault_url, access_token)
            client.connect()
            token_info = client.validate_token()
            
            # Store authentication in session
            from app.session_manager import session_manager
            session_manager.authenticate(vault_url, access_token, token_info)
            
            # Log successful authentication
            audit_logger.log_authentication_success(vault_url, token_info)
            
            logger.info("OAuth implicit flow authentication successful")
            
            return jsonify({
                'success': True,
                'message': 'Authentication successful'
            })
            
        except Exception as e:
            logger.error(f"OAuth implicit flow failed: {e}")
            return jsonify({
                'success': False,
                'message': f'Authentication failed: {str(e)}'
            }), 400
            
    except Exception as e:
        logger.error(f"Unexpected error in OAuth implicit flow: {e}")
        return jsonify({
            'success': False,
            'message': f'Unexpected error: {str(e)}'
        }), 500


@auth.route('/callback-page')
def callback_page():
    """Serve the OAuth callback page for handling URL fragments."""
    return render_template('auth/callback.html')


@auth.route('/logout')
def logout():
    """Handle user logout."""
    try:
        # Log logout event
        if session.get('vault_url'):
            audit_logger.log_logout(session.get('vault_url'))
        
        # Clear session
        from app.session_manager import session_manager
        session_manager.logout()
        
        logger.info("User logged out successfully")
        flash('You have been logged out successfully', 'success')
        
    except Exception as e:
        logger.error(f"Error during logout: {e}")
        flash('Error during logout', 'error')
    
    return redirect(url_for('auth.login'))


@auth.route('/status')
def status():
    """Check authentication status and return current session info."""
    if not session.get('connected'):
        return {
            'authenticated': False,
            'message': 'Not authenticated'
        }
    
    return {
        'authenticated': True,
        'vault_url': session.get('vault_url'),
        'token_info': session.get('token_info'),
        'authenticated_at': session.get('authenticated_at')
    }


@auth.route('/validate')
def validate_session():
    """Validate the current session by testing the Vault connection."""
    if not session.get('connected'):
        return {'valid': False, 'message': 'No active session'}, 401
    
    try:
        vault_url = session.get('vault_url')
        vault_token = session.get('vault_token')
        
        with VaultClient(vault_url, vault_token) as client:
            # Test connection by validating token
            token_info = client.validate_token()
            
            # Update session with fresh token info
            session['token_info'] = token_info
            
            return {
                'valid': True,
                'message': 'Session is valid',
                'token_info': token_info
            }
            
    except (VaultAuthenticationError, VaultConnectionError, VaultClientError) as e:
        logger.warning(f"Session validation failed: {e}")
        # Clear invalid session
        session.clear()
        return {'valid': False, 'message': f'Session invalid: {e}'}, 401
        
    except Exception as e:
        logger.error(f"Unexpected error during session validation: {e}")
        return {'valid': False, 'message': f'Unexpected error: {e}'}, 500
