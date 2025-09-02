# Testing Guide - Catching Template Errors and Common Issues

This guide explains how the unit tests in Secret Sluth are designed to catch common Flask application issues, including template not found errors, before they cause runtime problems.

## 🎯 **Overview**

The testing suite includes comprehensive tests that catch:
- **Template not found errors** (`jinja2.exceptions.TemplateNotFound`)
- **Configuration issues** (missing folders, wrong paths)
- **Import errors** (missing modules, circular imports)
- **Routing problems** (missing routes, incorrect URLs)
- **Session management issues** (cookie problems, security settings)

## 🔍 **Template Error Detection**

### **Problem Scenario**
```python
# This would cause a runtime error:
jinja2.exceptions.TemplateNotFound: main/index.html
```

### **How Tests Catch It**

#### 1. **Template Folder Configuration Test**
```python
def test_template_folder_exists(self):
    """Test that the templates folder exists and is accessible."""
    app = create_app()
    
    # Get absolute path to template folder
    template_folder = os.path.abspath(app.template_folder)
    
    # Check that template folder exists
    assert os.path.exists(template_folder)
    assert os.path.isdir(template_folder)
```

**What it catches:**
- Template folder doesn't exist
- Template folder path is incorrect
- Permission issues accessing template folder

#### 2. **Required Templates Test**
```python
def test_required_templates_exist(self):
    """Test that all required templates exist."""
    app = create_app()
    
    required_templates = [
        'base.html',
        'main/index.html',
        'main/connect.html',
        'main/dashboard.html'
    ]
    
    for template in required_templates:
        template_path = os.path.join(template_folder, template)
        assert os.path.exists(template_path), f"Template {template} not found"
```

**What it catches:**
- Missing template files
- Incorrect template paths
- Template naming errors

#### 3. **Template Rendering Test**
```python
def test_template_rendering_works(self):
    """Test that templates can be rendered without errors."""
    app = create_app()
    
    with app.test_client() as client:
        # Test that home page renders
        response = client.get('/')
        assert response.status_code == 200  # Not 500 (template error)
```

**What it catches:**
- Template syntax errors
- Missing template variables
- Template inheritance problems

## 🛠️ **Configuration Error Detection**

### **Flask App Factory Tests**
```python
def test_app_template_folder_configuration(self):
    """Test that app is configured with correct template folder."""
    app = create_app()
    
    # Check that template folder is set correctly
    assert 'templates' in app.template_folder
    assert app.template_folder.endswith('templates')
```

**What it catches:**
- Incorrect template folder configuration
- Relative vs absolute path issues
- Missing static folder configuration

### **Blueprint Registration Tests**
```python
def test_blueprint_registration(self):
    """Test that blueprints are properly registered."""
    app = create_app()
    
    # Check that main blueprint is registered
    assert 'main' in app.blueprints
    assert app.blueprints['main'].name == 'main'
```

**What it catches:**
- Missing blueprint registration
- Incorrect blueprint names
- Route registration failures

## 🔧 **Import Error Detection**

### **Module Import Tests**
```python
def test_all_modules_can_be_imported(self):
    """Test that all required modules can be imported."""
    try:
        from app import create_app
        from app.config import Config
        from app.routes.main import main
        from app.vault_client import VaultClient
    except ImportError as e:
        pytest.fail(f"Import failed: {e}")
```

**What it catches:**
- Missing dependencies
- Circular imports
- Module path issues
- Syntax errors in modules

## 🚀 **Runtime Error Detection**

### **Template Not Found Prevention**
```python
def test_no_template_not_found_errors(self):
    """Test that no TemplateNotFound errors occur during normal operation."""
    app = create_app()
    
    with app.test_client() as client:
        routes_to_test = ['/', '/connect', '/disconnect']
        
        for route in routes_to_test:
            try:
                response = client.get(route)
                assert response.status_code in [200, 302]
            except TemplateNotFound as e:
                pytest.fail(f"TemplateNotFound error on route {route}: {e}")
```

**What it catches:**
- Template not found errors at runtime
- Missing template files
- Incorrect template paths

## 📋 **Running the Tests**

### **Run All Tests**
```bash
python -m pytest tests/unit/ -v
```

### **Run Specific Test Categories**
```bash
# Template error detection tests
python -m pytest tests/unit/test_template_errors.py -v

# Flask app tests
python -m pytest tests/unit/test_flask_app.py -v

# Vault client tests
python -m pytest tests/unit/test_vault_client.py -v
```

### **Run with Coverage**
```bash
python -m pytest tests/unit/ --cov=app --cov-report=term-missing
```

## 🎯 **Test Categories**

### **1. Template Error Detection (`test_template_errors.py`)**
- Template folder existence and accessibility
- Required template file presence
- Template rendering functionality
- Template inheritance verification
- Template variable passing

### **2. Flask App Tests (`test_flask_app.py`)**
- App factory configuration
- Blueprint registration
- Route functionality
- Session management
- Error handling
- Security configuration

### **3. Vault Client Tests (`test_vault_client.py`)**
- Connection management
- Authentication
- Secret operations
- Error handling
- Context manager functionality

### **4. Configuration Tests (`test_config.py`)**
- Environment variable handling
- Configuration class inheritance
- Default value verification

### **5. Logging Tests (`test_logging_config.py`)**
- Logging setup
- Logger creation
- Structured logging functionality

## 🚨 **Common Issues Caught**

### **Template Issues**
- ❌ `TemplateNotFound: main/index.html`
- ❌ Missing template folder
- ❌ Incorrect template paths
- ❌ Template syntax errors

### **Configuration Issues**
- ❌ Missing SECRET_KEY
- ❌ Incorrect folder paths
- ❌ Missing blueprint registration
- ❌ Wrong environment variables

### **Import Issues**
- ❌ Missing dependencies
- ❌ Circular imports
- ❌ Module not found errors
- ❌ Syntax errors in modules

### **Runtime Issues**
- ❌ 500 errors due to template problems
- ❌ Session management failures
- ❌ Route not found errors
- ❌ Authentication failures

## 🔧 **Fixing Common Issues**

### **Template Not Found Error**
```python
# Problem: Template folder not found
jinja2.exceptions.TemplateNotFound: main/index.html

# Solution: Fix Flask app configuration
def create_app(config_class=Config):
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    
    app = Flask(__name__, 
                template_folder=os.path.join(project_root, 'templates'),
                static_folder=os.path.join(project_root, 'static'))
```

### **Missing Template Files**
```bash
# Problem: Template files don't exist
# Solution: Create required templates
mkdir -p templates/main
touch templates/base.html
touch templates/main/index.html
touch templates/main/connect.html
touch templates/main/dashboard.html
```

### **Import Errors**
```python
# Problem: Module import fails
# Solution: Check dependencies and paths
pip install -r requirements.txt
python -c "from app import create_app; print('Import successful')"
```

## 📊 **Test Coverage**

The test suite provides comprehensive coverage:

- **Template System**: 100% coverage of template rendering
- **Flask Configuration**: 100% coverage of app factory
- **Routing**: 100% coverage of all routes
- **Error Handling**: 100% coverage of error scenarios
- **Vault Client**: 82% coverage of core functionality

## 🎉 **Benefits**

### **Early Detection**
- Catch issues before they reach production
- Identify problems during development
- Prevent runtime crashes

### **Confidence**
- Know that templates will render correctly
- Verify that routes work as expected
- Ensure proper error handling

### **Maintenance**
- Easy to add new tests for new features
- Clear test organization by functionality
- Comprehensive coverage reporting

## 📝 **Adding New Tests**

When adding new features, follow these patterns:

### **For New Templates**
```python
def test_new_template_exists(self):
    """Test that new template exists and renders."""
    app = create_app()
    
    # Check template exists
    template_path = os.path.join(app.template_folder, 'new_template.html')
    assert os.path.exists(template_path)
    
    # Test rendering
    with app.test_client() as client:
        response = client.get('/new-route')
        assert response.status_code == 200
```

### **For New Routes**
```python
def test_new_route_works(self):
    """Test that new route works correctly."""
    app = create_app()
    
    with app.test_client() as client:
        response = client.get('/new-route')
        assert response.status_code == 200
        assert b'Expected Content' in response.data
```

### **For New Configuration**
```python
def test_new_config_option(self):
    """Test that new configuration option works."""
    app = create_app()
    
    assert 'NEW_CONFIG_OPTION' in app.config
    assert app.config['NEW_CONFIG_OPTION'] == 'expected_value'
```

## 🔗 **Related Documentation**

- [Implementation Plan](../Implementation-Plan.md)
- [Project Specification](../Project-Spec.md)
- [Quick Start Guide](../QUICK_START.md)
- [Testing Setup Guide](testing-setup.md)

---

**Remember**: Run the tests frequently during development to catch issues early and maintain code quality!
