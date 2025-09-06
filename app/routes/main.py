"""
Main routes for the Secret Sluth application.

This module contains the main application routes including the home page,
dashboard, and basic error handling.
"""

from flask import Blueprint, render_template, session, redirect, url_for, jsonify, request, flash
from app.middleware.auth_middleware import require_auth
from app.engine_manager import engine_manager
from app.session_manager import session_manager
from app.rate_limiter import rate_limiter
from app.search_optimizer import search_optimizer
from app.logging_config import get_logger
from app.vault_client import VaultClient, VaultAuthenticationError, VaultConnectionError
from app.validators import input_validator
from app.audit_logger import audit_logger
import psutil
import time

logger = get_logger(__name__)

main = Blueprint('main', __name__)


@main.route('/')
def index():
    """Home page."""
    return render_template('main/index.html')


@main.route('/dashboard')
@require_auth
def dashboard():
    """Dashboard page."""
    # Refresh token info to get current expiration time
    try:
        session_manager.refresh_session()
    except Exception as e:
        logger.warning(f"Failed to refresh session for dashboard: {e}")
    
    # Get token info and vault URL from session
    token_info = session.get('token_info', {})
    vault_url = session.get('vault_url', '')
    timestamp = int(time.time())
    return render_template('main/dashboard.html', token_info=token_info, vault_url=vault_url, timestamp=timestamp)


@main.route('/connect', methods=['GET', 'POST'])
def connect():
    """Engine connection page."""
    if request.method == 'GET':
        return render_template('main/connect.html')
    
    # Handle POST request - redirect to proper auth flow
    vault_url = request.form.get('vault_url', '').strip()
    auth_method = request.form.get('auth_method', 'auto').strip()
    
    # Validate Vault URL
    is_valid_url, error_msg = input_validator.validate_vault_url(vault_url)
    if not is_valid_url:
        flash(error_msg, 'error')
        return render_template('main/connect.html', vault_url=vault_url)
    
    # Store Vault URL in session and redirect to auth flow
    session['vault_url'] = vault_url
    
    # Check authentication method and handle accordingly
    vault_token = request.form.get('vault_token', '').strip()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    
    if auth_method == 'token' and vault_token:
        # Direct token authentication
        is_valid_token, error_msg = input_validator.validate_vault_token(vault_token)
        if not is_valid_token:
            flash(error_msg, 'error')
            return render_template('main/connect.html', vault_url=vault_url)
        
        try:
            # Test the token
            client = VaultClient(vault_url, vault_token)
            with client:
                token_info = client.validate_token()
                
                # Store authentication in session
                session_manager.authenticate(vault_url, vault_token, token_info)
                
                # Log successful authentication
                audit_logger.log_authentication_success(vault_url, token_info)
                
                logger.info(f"Direct token authentication successful for {vault_url}")
                flash('Successfully authenticated with Vault!', 'success')
                return redirect(url_for('main.dashboard'))
                
        except VaultAuthenticationError as e:
            logger.error(f"Token authentication failed: {e}")
            flash(f'Authentication failed: {str(e)}', 'error')
            return render_template('main/connect.html', vault_url=vault_url)
            
        except VaultConnectionError as e:
            logger.error(f"Failed to connect to Vault: {e}")
            flash(f'Failed to connect to Vault server: {str(e)}', 'error')
            return render_template('main/connect.html', vault_url=vault_url)
            
        except Exception as e:
            logger.error(f"Unexpected error during authentication: {e}")
            flash(f'Unexpected error: {str(e)}', 'error')
            return render_template('main/connect.html', vault_url=vault_url)
            
    elif auth_method == 'userpass' and username and password:
        # Username/password authentication
        try:
            # Attempt userpass authentication
            client = VaultClient(vault_url, None)
            auth_response = client.userpass_login(username, password)
            
            if auth_response and 'auth' in auth_response:
                token = auth_response['auth']['client_token']
                token_info = auth_response['auth']
                
                # Store authentication in session
                session_manager.authenticate(vault_url, token, token_info)
                
                # Log successful authentication
                audit_logger.log_authentication_success(vault_url, token_info)
                
                logger.info(f"Userpass authentication successful for user {username}")
                flash('Successfully authenticated with Vault!', 'success')
                return redirect(url_for('main.dashboard'))
            else:
                flash('Authentication failed: Invalid response from Vault', 'error')
                return render_template('main/connect.html', vault_url=vault_url)
                
        except VaultAuthenticationError as e:
            logger.error(f"Userpass authentication failed: {e}")
            flash(f'Authentication failed: {str(e)}', 'error')
            return render_template('main/connect.html', vault_url=vault_url)
            
        except VaultConnectionError as e:
            logger.error(f"Failed to connect to Vault: {e}")
            flash(f'Failed to connect to Vault server: {str(e)}', 'error')
            return render_template('main/connect.html', vault_url=vault_url)
            
        except Exception as e:
            logger.error(f"Unexpected error during userpass authentication: {e}")
            flash(f'Unexpected error: {str(e)}', 'error')
            return render_template('main/connect.html', vault_url=vault_url)
    else:
        # No credentials provided or invalid method, redirect to auth method detection
        return redirect(url_for('auth.login'))


@main.route('/disconnect')
def disconnect():
    """Redirect to authentication logout."""
    return redirect(url_for('auth.logout'))


@main.route('/health')
def health():
    """Health check endpoint for monitoring."""
    try:
        # Basic system health
        health_status = {
            'status': 'healthy',
            'timestamp': time.time(),
            'version': '1.0.0',
            'uptime': time.time() - psutil.boot_time() if hasattr(psutil, 'boot_time') else 0
        }
        
        # System metrics
        try:
            health_status['system'] = {
                'cpu_percent': psutil.cpu_percent(interval=0.1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent
            }
        except Exception as e:
            logger.warning(f"Could not get system metrics: {e}")
            health_status['system'] = {'error': str(e)}
        
        # Application metrics
        try:
            # Rate limiter stats
            rate_limit_stats = rate_limiter.get_stats()
            health_status['rate_limiting'] = rate_limit_stats
            
            # Search optimizer stats
            optimizer_stats = search_optimizer.get_performance_stats()
            health_status['search_performance'] = optimizer_stats
            
            # Session stats
            session_stats = session_manager.get_stats()
            health_status['sessions'] = session_stats
            
        except Exception as e:
            logger.warning(f"Could not get application metrics: {e}")
            health_status['application'] = {'error': str(e)}
        
        # Check for critical issues
        issues = []
        
        # Check system resources
        if 'system' in health_status and 'error' not in health_status['system']:
            if health_status['system']['memory_percent'] > 90:
                issues.append('High memory usage')
            if health_status['system']['disk_percent'] > 90:
                issues.append('High disk usage')
            if health_status['system']['cpu_percent'] > 90:
                issues.append('High CPU usage')
        
        # Check rate limiting
        if 'rate_limiting' in health_status:
            if health_status['rate_limiting']['blocked_ips'] > 10:
                issues.append('High number of blocked IPs')
        
        # Check search performance
        if 'search_performance' in health_status:
            if health_status['search_performance']['avg_search_time'] > 30:
                issues.append('Slow average search time')
        
        if issues:
            health_status['status'] = 'degraded'
            health_status['issues'] = issues
        
        return jsonify(health_status), 200 if health_status['status'] == 'healthy' else 200
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': time.time()
        }), 500


@main.route('/status')
@require_auth
def status():
    """Detailed status page for authenticated users."""
    try:
        # Get comprehensive status information
        status_info = {
            'user': {
                'authenticated': True,
                'vault_url': session.get('vault_url', 'Not set'),
                'policies': session.get('policies', [])
            },
            'system': {
                'cpu_percent': psutil.cpu_percent(interval=0.1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent
            },
            'application': {
                'rate_limiting': rate_limiter.get_stats(),
                'search_performance': search_optimizer.get_performance_stats(),
                'sessions': session_manager.get_stats()
            }
        }
        
        return render_template('main/status.html', status=status_info)
        
    except Exception as e:
        logger.error(f"Status page error: {e}")
        return render_template('main/status.html', status={'error': str(e)})
