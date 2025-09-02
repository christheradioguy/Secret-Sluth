"""
Secret Sluth - A web-based interface for searching HashiCorp Vault secrets.

This package provides a Flask-based web application that allows users to
authenticate with Vault and search across multiple secret engines.
"""

from flask import Flask
from .config import Config
from .logging_config import setup_logging


def create_app(config_class=Config):
    """Application factory pattern for creating Flask app instances."""
    import os
    
    # Get the directory where this file is located
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # Go up one level to the project root
    project_root = os.path.dirname(current_dir)
    
    app = Flask(__name__, 
                template_folder=os.path.join(project_root, 'templates'),
                static_folder=os.path.join(project_root, 'static'))
    
    # Instantiate the configuration class to get environment-dependent values
    config_instance = config_class()
    app.config.from_object(config_instance)

    # Setup logging
    setup_logging(app)

    # Initialize extensions
    from .middleware.auth_middleware import AuthMiddleware
    auth_middleware = AuthMiddleware()
    auth_middleware.init_app(app)

    # Initialize rate limiting middleware
    from .middleware.rate_limit_middleware import RateLimitMiddleware
    rate_limit_middleware = RateLimitMiddleware()
    rate_limit_middleware.init_app(app)

    # Register error handlers
    from .error_handlers import register_error_handlers
    register_error_handlers(app)

    # Register blueprints
    from .routes.main import main as main_blueprint
    from .routes.auth import auth as auth_blueprint
    from .routes.engines import engines as engines_blueprint
    from .routes.search import search as search_blueprint
    app.register_blueprint(main_blueprint)
    app.register_blueprint(auth_blueprint)
    app.register_blueprint(engines_blueprint, url_prefix='/engines')
    app.register_blueprint(search_blueprint, url_prefix='/search')

    # Add context processors
    @app.context_processor
    def inject_csrf_token():
        """Inject CSRF token into templates."""
        from .security import security_manager
        return {'csrf_token': lambda: security_manager.generate_csrf_token()}

    return app
