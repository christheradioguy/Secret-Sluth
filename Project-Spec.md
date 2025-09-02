# Secret Sluth - Project Specification

## Project Overview

**Secret Sluth** is a recursive search tool for HashiCorp Vault that enables users to search for strings across all accessible secret engines and return comprehensive matches including secret names and keys.

### Purpose
The tool addresses the challenge of finding specific secrets or keys across multiple Vault secret engines without manually navigating through each engine individually.

## Requirements

### Functional Requirements

#### Core Functionality
- **Recursive Search**: Search for strings across all accessible secret engines
- **Comprehensive Results**: Return matches for both secret names and secret keys
- **Web Interface**: User-friendly web-based interface for all interactions
- **Authentication Management**: Secure handling of Vault authentication tokens
- **Session Management**: Persistent sessions with cookie-based authentication storage
- **Debuging Ability**: Must have logging capabailites to aid with debugging

#### Search Capabilities
- Search across multiple selected secret engines simultaneously
- Return results with direct links to Vault for easy access
- Support for case-sensitive and case-insensitive search options
- Efficient search algorithms to minimize response times

#### User Experience
- Minimal authentication steps with token persistence
- Intuitive selection of secret engines via checkboxes
- Clear presentation of search results
- Logout functionality to clear all authentication data

### Technical Requirements

#### Technology Stack
- **Language**: Python 3.8+
- **Dependencies**: Minimal external dependencies, prioritizing built-in libraries
- **Web Framework**: Flask or FastAPI (to be determined based on requirements)
- **Authentication**: HashiCorp Vault token-based authentication
- **Session Management**: Secure cookie-based session storage

#### Performance Requirements
- **Efficiency**: Optimized search algorithms for large Vault deployments
- **Accuracy**: 100% accurate results without false positives/negatives
- **Response Time**: Search results returned within reasonable timeframes (< 30 seconds for typical deployments)
- **Scalability**: Support for Vault deployments with hundreds of secret engines

#### Security Requirements
- **Token Security**: Secure storage and transmission of Vault tokens
- **Session Security**: Proper session management with secure cookies
- **Data Protection**: No sensitive data stored in application logs or databases
- **Access Control**: Respect Vault's existing access control policies

## User Workflow

### 1. Initial Authentication
1. User visits the application homepage
2. User enters Vault server URL in provided text field
3. Application redirects user to Vault for authentication
4. Vault authenticates user and redirects back with token (automatic or manual)
5. Application stores token securely in session cookies

### 2. Secret Engine Selection
1. Application retrieves list of accessible secret engines from Vault
2. User interface displays secret engines with checkboxes
3. User selects which secret engines to include in search
4. User can select/deselect all engines with bulk actions

### 3. Search Execution
1. User enters search string in search field
2. User can configure search options (case sensitivity, etc.)
3. Application performs recursive search across selected secret engines
4. Progress indicator shows search status
5. Results are displayed as they become available

### 4. Results Display
1. Search results are presented in organized format
2. Each result includes:
   - Secret engine name
   - Secret path
   - Matching key (if applicable)
   - Direct link to Vault for that secret
3. Results can be filtered, sorted, or exported
4. User can click links to navigate directly to secrets in Vault

### 5. Session Management
1. User can logout to clear all authentication data
2. Session timeout handling for security
3. Option to switch to different Vault server

## Technical Architecture

### Components
1. **Web Interface**: Flask/FastAPI application serving HTML pages
2. **Vault Client**: Python client for HashiCorp Vault API interactions
3. **Search Engine**: Recursive search implementation
4. **Session Manager**: Cookie-based session handling
5. **Result Formatter**: Results presentation and formatting

### Data Flow
1. User authentication → Vault token acquisition
2. Token validation → Secret engine enumeration
3. User selection → Search execution
4. Search results → Results formatting and display

## Implementation Considerations

### Error Handling
- Network connectivity issues with Vault
- Invalid or expired tokens
- Permission denied errors
- Search timeout scenarios
- Malformed search queries

### Performance Optimization
- Parallel search across multiple secret engines
- Caching of secret engine lists
- Pagination for large result sets
- Efficient string matching algorithms

### Security Considerations
- HTTPS enforcement
- Secure cookie configuration
- Input validation and sanitization
- Audit logging for security events

## Success Criteria

### Functional Success
- [ ] Users can successfully authenticate with Vault
- [ ] Users can search across multiple secret engines
- [ ] Search results are accurate and complete
- [ ] Direct links to Vault work correctly
- [ ] Logout functionality clears all session data

### Performance Success
- [ ] Search completes within 30 seconds for typical deployments
- [ ] Application handles 100+ secret engines efficiently
- [ ] Memory usage remains reasonable during large searches

### Security Success
- [ ] No sensitive data is logged or stored insecurely
- [ ] Authentication tokens are handled securely
- [ ] Session management follows security best practices

## Future Enhancements

### Phase 2 Features
- Advanced search filters (regex, wildcards)
- Search result export functionality
- Search history and saved searches
- Bulk operations on search results
- Integration with additional authentication methods

### Phase 3 Features
- Search scheduling and automation
- Result notifications
- Advanced analytics and reporting
- API endpoints for programmatic access
- Multi-tenant support

## Dependencies

### Required Python Packages
- `hvac` - HashiCorp Vault Python client
- `flask` or `fastapi` - Web framework
- `requests` - HTTP client (if not using built-in libraries)

### Optional Dependencies
- `python-dotenv` - Environment variable management
- `gunicorn` - Production WSGI server
- `pytest` - Testing framework

## Development Guidelines

### Code Standards
- Follow PEP 8 style guidelines
- Comprehensive error handling
- Unit tests for all core functionality
- Documentation for all public APIs
- Type hints for function parameters and return values

### Testing Strategy
- Unit tests for search algorithms
- Integration tests for Vault API interactions
- End-to-end tests for user workflows
- Security testing for authentication flows

## Deployment Considerations

### Environment Requirements
- Python 3.8+ runtime
- Network access to HashiCorp Vault
- HTTPS certificate for production deployment
- Sufficient memory for large search operations

### Configuration
- Vault server connection settings
- Session timeout configuration
- Search timeout settings
- Logging configuration