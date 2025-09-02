"""
Production configuration for Secret Sluth.

This configuration is optimized for production deployment with systemd.
"""

import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent.parent

# Flask Configuration
SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
DEBUG = False
TESTING = False

# Server Configuration
HOST = os.environ.get('HOST', '0.0.0.0')
PORT = int(os.environ.get('PORT', 5000))

# Vault Configuration (User-provided via web UI)
VAULT_URL = os.environ.get('VAULT_URL', '')  # Users provide via web UI
VAULT_TOKEN = os.environ.get('VAULT_TOKEN', '')  # Users provide via web UI

# Security Configuration
CSRF_ENABLED = True
WTF_CSRF_ENABLED = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
PERMANENT_SESSION_LIFETIME = 3600  # 1 hour

# Rate Limiting
RATE_LIMIT_ENABLED = True
RATE_LIMIT_STORAGE_URL = 'memory://'

# Logging Configuration
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
LOG_FILE = BASE_DIR / 'logs' / 'secret-sluth.log'
LOG_MAX_SIZE = 10 * 1024 * 1024  # 10MB
LOG_BACKUP_COUNT = 5

# Cache Configuration
CACHE_TYPE = 'filesystem'
CACHE_DIR = BASE_DIR / 'cache'
CACHE_DEFAULT_TIMEOUT = 1800  # 30 minutes
CACHE_THRESHOLD = 1000

# Search Configuration
SEARCH_CACHE_TTL = 1800  # 30 minutes
SEARCH_MAX_RESULTS = 5000
SEARCH_TIMEOUT = 300  # 5 minutes
SEARCH_PARALLEL_WORKERS = 5
SEARCH_BATCH_SIZE = 50

# Performance Configuration
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
SEND_FILE_MAX_AGE_DEFAULT = 31536000  # 1 year

# Database Configuration (if using SQLite for sessions)
DATABASE_PATH = BASE_DIR / 'data' / 'secret-sluth.db'

# Monitoring Configuration
ENABLE_METRICS = True
METRICS_PORT = int(os.environ.get('METRICS_PORT', 9090))

# SSL/TLS Configuration (if using reverse proxy)
PREFERRED_URL_SCHEME = 'https'

# File Upload Configuration
UPLOAD_FOLDER = BASE_DIR / 'uploads'
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

# Session Configuration
SESSION_TYPE = 'filesystem'
SESSION_FILE_DIR = BASE_DIR / 'sessions'
SESSION_FILE_THRESHOLD = 500

# Error Reporting
SENTRY_DSN = os.environ.get('SENTRY_DSN', '')

# Health Check Configuration
HEALTH_CHECK_ENABLED = True
HEALTH_CHECK_INTERVAL = 30  # seconds

# Backup Configuration
BACKUP_ENABLED = True
BACKUP_DIR = BASE_DIR / 'backups'
BACKUP_RETENTION_DAYS = 7

# Security Headers
SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
}
