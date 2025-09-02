# Secret Sluth 🔍

A powerful web application for searching and discovering secrets across HashiCorp Vault instances with advanced filtering, security features, and performance optimization.

## 🚀 Features

### Core Functionality
- **Multi-Engine Search**: Search across KV, Database, SSH, PKI, and other Vault engines
- **Advanced Search Patterns**: Support for wildcards (`*`, `?`), regex (`/pattern/`), and exact matches (`"text"`)
- **Real-time Results**: Fast, responsive search with live result updates
- **Export Capabilities**: Export results in JSON, CSV, and other formats

### Security Features
- **Rate Limiting**: Configurable rate limits per endpoint to prevent abuse
- **Input Validation**: Comprehensive validation and sanitization to prevent injection attacks
- **CSRF Protection**: Built-in CSRF token validation
- **Audit Logging**: Complete audit trail of all search operations
- **Session Management**: Secure session handling with Vault token management

### Advanced Search
- **Engine Filtering**: Filter searches by specific engine types
- **Match Type Filtering**: Filter by name, key, value, or metadata matches
- **Search Scope Control**: Granular control over where to search
- **Performance Limits**: Configurable max results and search depth

### Performance Optimization
- **Intelligent Caching**: Smart caching strategies based on query patterns
- **Parallel Processing**: Multi-threaded search operations for better performance
- **Memory Management**: Optimized memory usage with configurable limits
- **Performance Analytics**: Real-time performance monitoring and optimization suggestions

## 📋 Requirements

- Python 3.8+
- HashiCorp Vault server
- Vault authentication token with appropriate permissions

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd secret-sluth
   ```

2. **Create virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure the application**:
   ```bash
   cp app/config.py.example app/config.py
   # Edit app/config.py with your Vault configuration
   ```

## 🚀 Quick Start

1. **Start the application**:
   ```bash
   python run.py
   ```

2. **Open your browser**:
   Navigate to `http://localhost:5000`

3. **Authenticate with Vault**:
   - Enter your Vault server URL
   - Provide your authentication token
   - Click "Connect"

4. **Select engines to search**:
   - Choose which Vault engines to include in your search
   - Configure search scope and options

5. **Perform searches**:
   - Enter your search query
   - Use advanced patterns like `api*`, `/password.*/`, or `"exact match"`
   - View results in real-time

## 🔍 Search Syntax

### Basic Search
```
password          # Simple text search
api-key          # Search for specific terms
```

### Wildcard Search
```
api*             # Matches api-key, api_token, etc.
test?            # Matches test1, test2, etc.
```

### Regex Search
```
/api.*key/       # Regex pattern matching
/^password.*$/   # Anchored regex patterns
```

### Exact Match
```
"exact phrase"   # Exact string matching
"api-key-123"    # Precise term matching
```

## ⚙️ Configuration

### Environment Variables
```bash
export VAULT_URL=https://your-vault-server:8200
export VAULT_TOKEN=your-vault-token
export FLASK_ENV=development
export SECRET_KEY=your-secret-key
```

### Application Configuration
Edit `app/config.py` to customize:
- Rate limiting settings
- Cache configuration
- Security settings
- Performance parameters

## 🔒 Security Features

### Rate Limiting
- **Auth endpoints**: 5 requests per 5 minutes
- **Search endpoints**: 20 requests per minute
- **Export endpoints**: 10 requests per 5 minutes
- **Automatic IP blocking** for repeated violations

### Input Validation
- **SQL Injection Protection**: Removes SQL keywords and patterns
- **XSS Prevention**: Strips dangerous HTML/script tags
- **Command Injection Protection**: Removes shell command characters
- **Length Validation**: Prevents oversized inputs
- **Pattern Validation**: Validates regex and wildcard patterns

### Audit Logging
All search operations are logged with:
- User information and session details
- Search parameters and results count
- Performance metrics and timing
- Security events and violations

## 📊 Performance Optimization

### Caching Strategy
- **Query-based caching**: Different TTL for different query types
- **Regex queries**: Longer cache duration (2x standard)
- **Wildcard queries**: Moderate cache duration (1.5x standard)
- **Simple queries**: Standard cache duration

### Parallel Processing
- **Configurable workers**: Adjustable number of parallel search threads
- **Resource management**: Automatic worker limit based on system resources
- **Error handling**: Graceful handling of failed parallel operations

### Memory Management
- **Result limiting**: Configurable maximum results per search
- **Memory monitoring**: Real-time memory usage tracking
- **Automatic cleanup**: Periodic cleanup of old cache entries

## 🧪 Testing

### Run Unit Tests
```bash
python -m pytest tests/unit/
```

### Run Integration Tests
```bash
python -m pytest tests/integration/
```

### Run End-to-End Tests
```bash
python -m pytest tests/e2e/
```

## 📈 Monitoring

### Performance Metrics
- Search duration and throughput
- Cache hit rates and efficiency
- Memory usage and optimization
- Error rates and timeouts

### Health Checks
```bash
curl http://localhost:5000/health
```

## 🐛 Troubleshooting

### Common Issues

1. **Connection to Vault fails**:
   - Verify Vault server URL and port
   - Check network connectivity
   - Validate authentication token

2. **Search returns no results**:
   - Verify engine selection
   - Check search scope settings
   - Review query syntax

3. **Rate limiting errors**:
   - Wait for rate limit reset
   - Reduce request frequency
   - Check rate limit configuration

4. **Performance issues**:
   - Adjust parallel search settings
   - Review cache configuration
   - Monitor memory usage

### Debug Mode
Enable debug mode for detailed logging:
```bash
export FLASK_ENV=development
python run.py
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Security Notice

This application is designed for searching secrets and should be used responsibly:
- Ensure proper access controls are in place
- Monitor audit logs regularly
- Use in secure environments only
- Follow your organization's security policies

## 🆘 Support

For support and questions:
- Check the troubleshooting section
- Review the documentation
- Open an issue on GitHub
- Contact the development team

---

**Secret Sluth** - Making secret discovery efficient and secure 🔍
