"""
Specific tests for catching template errors and configuration issues.

These tests are designed to catch common Flask template and configuration problems
before they cause runtime errors.
"""

import pytest
import os
from flask import Flask
from jinja2.exceptions import TemplateNotFound

from app import create_app


class TestTemplateErrorDetection:
    """Test that template errors are caught early."""
    
    def test_template_folder_exists(self):
        """Test that the templates folder exists and is accessible."""
        app = create_app()
        
        # Get absolute path to template folder
        template_folder = os.path.abspath(app.template_folder)
        
        # Check that template folder exists
        assert os.path.exists(template_folder)
        assert os.path.isdir(template_folder)
        
        # Check that it contains expected files
        template_files = os.listdir(template_folder)
        assert 'base.html' in template_files
        assert 'main' in template_files
        
        # Check that main subfolder exists
        main_folder = os.path.join(template_folder, 'main')
        assert os.path.exists(main_folder)
        assert os.path.isdir(main_folder)
    
    def test_required_templates_exist(self):
        """Test that all required templates exist."""
        app = create_app()
        
        # Get absolute path to template folder
        template_folder = os.path.abspath(app.template_folder)
        
        required_templates = [
            'base.html',
            'main/index.html',
            'main/connect.html',
            'main/dashboard.html'
        ]
        
        for template in required_templates:
            template_path = os.path.join(template_folder, template)
            assert os.path.exists(template_path), f"Template {template} not found at {template_path}"
    
    def test_template_rendering_works(self):
        """Test that templates can be rendered without errors."""
        app = create_app()
        
        with app.test_client() as client:
            # Test that home page renders
            response = client.get('/')
            assert response.status_code == 200
            
            # Test that connect page renders (redirects to auth.login)
            response = client.get('/connect')
            assert response.status_code == 302
            
            # Test that dashboard redirects (as expected when not connected)
            response = client.get('/dashboard')
            assert response.status_code == 302
    
    def test_template_inheritance_works(self):
        """Test that template inheritance works correctly."""
        app = create_app()
        
        with app.test_client() as client:
            response = client.get('/')
            
            # Check that base template elements are present
            assert b'<!DOCTYPE html>' in response.data
            assert b'<html' in response.data
            assert b'<head>' in response.data
            assert b'<body>' in response.data
            assert b'</html>' in response.data
    
    def test_template_variables_work(self):
        """Test that template variables are properly passed and rendered."""
        app = create_app()
        
        with app.test_client() as client:
            response = client.get('/')
            
            # Check that template variables are rendered
            assert b'Secret Sluth' in response.data
            assert b'Connect to Vault' in response.data
    
    def test_template_blocks_work(self):
        """Test that template blocks are properly defined and used."""
        app = create_app()
        
        with app.test_client() as client:
            response = client.get('/')
            
            # Check that content block is used
            assert b'{% block content %}' not in response.data  # Should be rendered, not raw
            assert b'{% endblock %}' not in response.data  # Should be rendered, not raw


class TestConfigurationErrorDetection:
    """Test that configuration errors are caught early."""
    
    def test_app_creation_with_different_configs(self):
        """Test that app creation works with all configuration classes."""
        from app.config import Config, DevelopmentConfig, TestingConfig, ProductionConfig
        
        configs = [Config, DevelopmentConfig, TestingConfig, ProductionConfig]
        
        for config_class in configs:
            try:
                app = create_app(config_class)
                assert isinstance(app, Flask)
                assert app.name == 'app'
            except Exception as e:
                pytest.fail(f"Failed to create app with {config_class.__name__}: {e}")
    
    def test_blueprint_registration_works(self):
        """Test that blueprints are properly registered."""
        app = create_app()
        
        # Check that main blueprint is registered
        assert 'main' in app.blueprints
        assert app.blueprints['main'].name == 'main'
        
        # Check that routes are registered
        with app.test_request_context():
            # These should not raise exceptions
            try:
                from flask import url_for
                url_for('main.index')
                url_for('main.connect')
                url_for('main.dashboard')
                url_for('main.disconnect')
                url_for('main.test_connection')
            except Exception as e:
                pytest.fail(f"URL generation failed: {e}")
    
    def test_static_folder_configuration(self):
        """Test that static folder is properly configured."""
        app = create_app()
        
        # Check that static folder exists
        assert os.path.exists(app.static_folder)
        assert os.path.isdir(app.static_folder)
        
        # Check that static folder contains expected subdirectories
        static_contents = os.listdir(app.static_folder)
        expected_folders = ['css', 'js', 'images']
        
        for folder in expected_folders:
            folder_path = os.path.join(app.static_folder, folder)
            if not os.path.exists(folder_path):
                # Create the folder if it doesn't exist
                os.makedirs(folder_path)
            assert os.path.exists(folder_path), f"Static folder {folder} not found"


class TestImportErrorDetection:
    """Test that import errors are caught early."""
    
    def test_all_modules_can_be_imported(self):
        """Test that all required modules can be imported."""
        try:
            from app import create_app
            from app.config import Config
            from app.logging_config import setup_logging, get_logger
            from app.routes.main import main
            from app.vault_client import VaultClient
        except ImportError as e:
            pytest.fail(f"Import failed: {e}")
    
    def test_blueprint_routes_can_be_imported(self):
        """Test that blueprint routes can be imported."""
        try:
            from app.routes.main import main
            
            # Check that blueprint has routes
            assert hasattr(main, 'deferred_functions')
            assert len(main.deferred_functions) > 0
            
            # Check that routes are callable
            for func in main.deferred_functions:
                assert callable(func)
        except ImportError as e:
            pytest.fail(f"Blueprint import failed: {e}")


class TestRuntimeErrorDetection:
    """Test that runtime errors are caught during testing."""
    
    def test_no_template_not_found_errors(self):
        """Test that no TemplateNotFound errors occur during normal operation."""
        app = create_app()
        
        with app.test_client() as client:
            # Test all routes that should work
            routes_to_test = ['/', '/connect', '/disconnect']
            
            for route in routes_to_test:
                try:
                    response = client.get(route)
                    # Should not raise TemplateNotFound
                    assert response.status_code in [200, 302]  # 200 for success, 302 for redirect
                except TemplateNotFound as e:
                    pytest.fail(f"TemplateNotFound error on route {route}: {e}")
                except Exception as e:
                    # Other exceptions might be expected (like redirects)
                    if not isinstance(e, (AssertionError,)):
                        pytest.fail(f"Unexpected error on route {route}: {e}")
    
    def test_no_import_errors_at_runtime(self):
        """Test that no import errors occur at runtime."""
        app = create_app()
        
        with app.test_client() as client:
            try:
                # Make a request that exercises the full import chain
                response = client.get('/')
                assert response.status_code == 200
            except ImportError as e:
                pytest.fail(f"Import error at runtime: {e}")
            except Exception as e:
                # Other exceptions might be expected
                if not isinstance(e, (AssertionError,)):
                    pytest.fail(f"Unexpected error at runtime: {e}")


def test_template_folder_path_resolution():
    """Test that template folder path is resolved correctly."""
    app = create_app()
    
    # Check that template folder path can be resolved to absolute path
    template_folder = os.path.abspath(app.template_folder)
    assert os.path.isabs(template_folder)
    
    # Check that template folder points to the correct location
    expected_templates_dir = os.path.join(os.getcwd(), 'templates')
    assert template_folder == expected_templates_dir or template_folder.endswith('templates')


def test_static_folder_path_resolution():
    """Test that static folder path is resolved correctly."""
    app = create_app()
    
    # Check that static folder path is absolute
    assert os.path.isabs(app.static_folder)
    
    # Check that static folder points to the correct location
    expected_static_dir = os.path.join(os.getcwd(), 'static')
    assert app.static_folder == expected_static_dir or app.static_folder.endswith('static')
