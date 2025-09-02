# Secret Sluth Setup Guide

## Architecture Overview

Secret Sluth is designed as a **web-based Vault client** where users authenticate through the web UI and can switch between different Vault servers without storing persistent credentials.

### Key Design Principles:
- **No Persistent Vault Credentials**: Vault tokens are stored only in user sessions
- **Multi-Vault Support**: Users can switch between different Vault servers
- **Web-Based Authentication**: All Vault authentication happens through the web UI
- **Session-Based Security**: Credentials are cleared when sessions expire

## Minimal Setup Requirements

### 1. System Requirements
- Python 3.8+
- Web browser access
- Network connectivity to Vault servers

### 2. Application Configuration
Only minimal configuration is required:

```bash
# Required: Flask secret key for session security
SECRET_KEY=your-secret-key-here

# Optional: Server settings
HOST=0.0.0.0
PORT=5000
LOG_LEVEL=INFO
```

### 3. No Vault Pre-configuration Needed
- No persistent Vault URLs
- No stored Vault tokens
- No pre-configured authentication

## Deployment Options

### Option A: Quick Development Setup
```bash
# Clone and run directly
git clone <repository>
cd secret-sluth
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python run.py
```

### Option B: Production Systemd Service
```bash
# Automated deployment
sudo ./deploy.sh

# Manual deployment
sudo systemctl start secret-sluth
```

## User Workflow

### 1. Access the Web UI
- Navigate to `http://your-server:5000`
- You'll see the login page

### 2. Authenticate with Vault
- Enter your Vault server URL (e.g., `https://vault.company.com:8200`)
- Provide your Vault token
- Click "Connect to Vault"

### 3. Use the Application
- Select which secret engines to search
- Perform searches across your Vault
- View and manage search results

### 4. Switch Vault Servers
- Use the logout function to clear current session
- Re-authenticate with a different Vault server
- All previous credentials are cleared

## Security Model

### Session Security
- Vault tokens stored only in Flask sessions
- Sessions expire automatically (configurable)
- No persistent storage of sensitive credentials
- CSRF protection enabled

### Network Security
- HTTPS recommended for production
- Reverse proxy (nginx/Apache) recommended
- Firewall rules to restrict access

### Application Security
- Input validation on all user inputs
- Rate limiting to prevent abuse
- Secure headers and cookies
- Sandboxed execution (systemd service)

## Configuration Examples

### Development Environment
```bash
# .env file
SECRET_KEY=dev-secret-key-change-in-production
FLASK_ENV=development
DEBUG=true
```

### Production Environment
```bash
# .env file
SECRET_KEY=your-production-secret-key-here
FLASK_ENV=production
HOST=0.0.0.0
PORT=5000
LOG_LEVEL=INFO
CSRF_ENABLED=true
```

### Reverse Proxy (nginx)
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Troubleshooting

### Common Issues

#### "Unable to connect to Vault"
- Check Vault server URL format
- Verify network connectivity
- Ensure Vault token is valid
- Check Vault server is running

#### "Authentication failed"
- Verify Vault token permissions
- Check token hasn't expired
- Ensure token has required policies

#### "No engines found"
- Verify token has `list` permission on secret engines
- Check Vault server has secret engines configured
- Ensure engines are mounted and accessible

#### "Search returns no results"
- Check token has `read` permission on secrets
- Verify search query syntax
- Ensure engines are selected for search

### Logs and Debugging
```bash
# View application logs
sudo journalctl -u secret-sluth -f

# Check service status
sudo systemctl status secret-sluth

# Test Vault connectivity manually
curl -H "X-Vault-Token: your-token" https://your-vault-server:8200/v1/sys/health
```

## Best Practices

### Security
- Use HTTPS in production
- Implement proper firewall rules
- Regular security updates
- Monitor access logs
- Use strong Flask secret keys

### Performance
- Configure appropriate parallel workers
- Adjust batch sizes based on Vault performance
- Monitor resource usage
- Use caching for repeated searches

### Operations
- Regular backups of configuration
- Monitor application health
- Set up log rotation
- Plan for updates and maintenance

## Support

For issues and questions:
1. Check the logs: `sudo journalctl -u secret-sluth -f`
2. Review this setup guide
3. Check the main README.md
4. Verify Vault connectivity and permissions
