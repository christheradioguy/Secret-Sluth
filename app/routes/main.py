"""
Main routes for the Secret Sluth application.

This module contains the main application routes including the home page,
dashboard, and basic error handling.
"""

from flask import Blueprint, render_template, session, redirect, url_for, jsonify
from app.middleware.auth_middleware import require_auth
from app.engine_manager import engine_manager
from app.session_manager import session_manager
from app.rate_limiter import rate_limiter
from app.search_optimizer import search_optimizer
from app.logging_config import get_logger
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


@main.route('/connect')
@require_auth
def connect():
    """Engine connection page."""
    return render_template('main/connect.html')


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
