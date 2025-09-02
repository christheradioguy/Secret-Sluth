# Secret Sluth Deployment Guide

This guide covers deploying Secret Sluth as a systemd service for production use.

## Prerequisites

- Ubuntu 20.04+ or CentOS 8+ (or equivalent)
- Python 3.8+
- Root access
- Network access to Vault servers (users provide credentials via web UI)

## Quick Deployment

### 1. Automated Deployment

```bash
# Clone the repository
git clone https://github.com/your-username/secret-sluth.git
cd secret-sluth

# Run the deployment script as root
sudo ./deploy.sh
```

### 2. Manual Deployment

If you prefer manual deployment or need to customize the installation:

```bash
# Create service user
sudo useradd --system --shell /bin/false --home-dir /opt/secret-sluth secret-sluth
sudo groupadd --system secret-sluth
sudo usermod -a -G secret-sluth secret-sluth

# Create installation directory
sudo mkdir -p /opt/secret-sluth
sudo cp -r . /opt/secret-sluth/
sudo chown -R secret-sluth:secret-sluth /opt/secret-sluth

# Set up Python environment
cd /opt/secret-sluth
sudo -u secret-sluth python3 -m venv venv
sudo -u secret-sluth venv/bin/pip install -r requirements.txt

# Install systemd service
sudo cp secret-sluth.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable secret-sluth
```

## Configuration

### Environment Variables

Create `/opt/secret-sluth/.env` with minimal configuration:

```bash
# Flask Configuration (Required)
SECRET_KEY=your-secret-key-here
FLASK_ENV=production

# Server Configuration
HOST=0.0.0.0
PORT=5000

# Logging
LOG_LEVEL=INFO

# Security
CSRF_ENABLED=true

# Note: Vault credentials are provided by users via web UI
# No persistent Vault configuration needed
```

### Service Configuration

The systemd service file (`secret-sluth.service`) includes:

- **Security**: Sandboxed execution with minimal privileges
- **Resource Limits**: Optimized for production workloads
- **Auto-restart**: Automatic restart on failure
- **Logging**: Integrated with systemd journal

## Service Management

### Start the Service

```bash
sudo systemctl start secret-sluth
```

### Check Status

```bash
sudo systemctl status secret-sluth
```

### View Logs

```bash
# Real-time logs
sudo journalctl -u secret-sluth -f

# Recent logs
sudo journalctl -u secret-sluth -n 100

# Logs since boot
sudo journalctl -u secret-sluth -b
```

### Stop/Restart

```bash
sudo systemctl stop secret-sluth
sudo systemctl restart secret-sluth
```

### Enable/Disable Auto-start

```bash
sudo systemctl enable secret-sluth   # Start on boot
sudo systemctl disable secret-sluth  # Don't start on boot
```

## Performance Optimization

The deployment includes several performance optimizations:

### Search Performance
- **Parallel Processing**: Configurable parallel workers (3-10)
- **Batch Processing**: Process secrets in batches (25-200)
- **Connection Pooling**: Optimized HTTP connections
- **Caching**: 30-minute search result caching

### Resource Management
- **File Descriptors**: 65,536 limit for concurrent connections
- **Process Limits**: 4,096 concurrent processes
- **Memory Management**: Optimized for large datasets

### Monitoring
- **Performance Metrics**: Real-time search performance tracking
- **Progress Logging**: Progress indicators for large searches
- **Health Checks**: Built-in health monitoring

## Security Features

### Service Security
- **Sandboxed Execution**: Minimal system access
- **Private Directories**: Isolated file system access
- **No Privilege Escalation**: Cannot gain additional privileges
- **Resource Isolation**: Protected from other services

### Application Security
- **CSRF Protection**: Enabled by default
- **Secure Cookies**: HTTP-only, secure flags
- **Rate Limiting**: Protection against abuse
- **Input Validation**: Comprehensive input sanitization

## Troubleshooting

### Common Issues

#### Service Won't Start
```bash
# Check service status
sudo systemctl status secret-sluth

# Check logs for errors
sudo journalctl -u secret-sluth -n 50

# Verify permissions
sudo ls -la /opt/secret-sluth/
```

#### Permission Denied
```bash
# Fix ownership
sudo chown -R secret-sluth:secret-sluth /opt/secret-sluth

# Fix permissions
sudo chmod -R 755 /opt/secret-sluth
```

#### Vault Connection Issues
```bash
# Test Vault connectivity (users provide credentials via web UI)
# No persistent Vault configuration needed

# Check if service can reach external networks
curl -I https://google.com

# Verify no persistent Vault credentials are stored
sudo -u secret-sluth cat /opt/secret-sluth/.env | grep -v VAULT
```

#### Performance Issues
```bash
# Check resource usage
sudo systemctl status secret-sluth
htop

# Monitor logs for performance metrics
sudo journalctl -u secret-sluth -f | grep "performance"
```

### Log Locations

- **Systemd Logs**: `journalctl -u secret-sluth`
- **Application Logs**: `/opt/secret-sluth/logs/`
- **Cache Directory**: `/opt/secret-sluth/cache/`

## Backup and Recovery

### Backup Configuration
```bash
# Backup configuration
sudo tar -czf secret-sluth-backup-$(date +%Y%m%d).tar.gz \
  /opt/secret-sluth/.env \
  /opt/secret-sluth/config/ \
  /etc/systemd/system/secret-sluth.service
```

### Restore Configuration
```bash
# Stop service
sudo systemctl stop secret-sluth

# Restore from backup
sudo tar -xzf secret-sluth-backup-YYYYMMDD.tar.gz -C /

# Restart service
sudo systemctl start secret-sluth
```

## Monitoring and Maintenance

### Health Checks
```bash
# Check service health
curl http://localhost:5000/health

# Monitor resource usage
sudo systemctl status secret-sluth
```

### Log Rotation
The service uses systemd journal with automatic rotation:
```bash
# Check journal size
sudo journalctl --disk-usage

# Clean old logs
sudo journalctl --vacuum-time=30d
```

### Updates
```bash
# Stop service
sudo systemctl stop secret-sluth

# Update code
cd /opt/secret-sluth
sudo git pull

# Update dependencies
sudo -u secret-sluth venv/bin/pip install -r requirements.txt

# Restart service
sudo systemctl start secret-sluth
```

## Production Considerations

### Reverse Proxy (Recommended)
Use nginx or Apache as a reverse proxy:

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

### SSL/TLS
Configure SSL certificates through your reverse proxy or use Let's Encrypt.

### Firewall
```bash
# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Block direct access to Flask port
sudo ufw deny 5000/tcp
```

### Monitoring
Consider integrating with monitoring solutions like:
- Prometheus + Grafana
- Nagios
- Zabbix

## Support

For issues and questions:
- Check the logs: `sudo journalctl -u secret-sluth -f`
- Review this deployment guide
- Check the main README.md for application-specific issues
