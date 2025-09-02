# Testing Setup Guide

This guide will help you set up a test HashiCorp Vault server to test the Secret Sluth application.

## Option 1: Using Docker (Recommended)

### 1. Install Docker

Make sure you have Docker installed on your system.

### 2. Start Vault Server

```bash
# Start Vault in development mode
docker run -d \
  --name vault-test \
  -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=test-token \
  -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  vault:latest
```

### 3. Access Vault UI

Open your browser and go to: http://localhost:8200

- **Token**: `test-token`

### 4. Create Test Secrets

1. Log into the Vault UI
2. Go to "Secrets" → "Enable new engine"
3. Select "KV" and click "Next"
4. Set the path to `secret` and click "Enable Engine"
5. Go to the `secret` engine and create some test secrets:

   **Secret 1:**
   - Path: `app/database`
   - Key: `username` → Value: `admin`
   - Key: `password` → Value: `secret123`

   **Secret 2:**
   - Path: `api/credentials`
   - Key: `api_key` → Value: `abc123`
   - Key: `password` → Value: `xyz789`

   **Secret 3:**
   - Path: `config/app`
   - Key: `debug` → Value: `true`
   - Key: `database_url` → Value: `postgresql://localhost/db`

## Option 2: Using Vault CLI

### 1. Install Vault CLI

Download and install Vault CLI from: https://www.vaultproject.io/downloads

### 2. Start Vault Server

```bash
# Start Vault in development mode
vault server -dev -dev-root-token-id=test-token -dev-listen-address=0.0.0.0:8200
```

### 3. Set Environment Variables

```bash
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=test-token
```

### 4. Create Test Secrets

```bash
# Enable KV secrets engine
vault secrets enable -path=secret kv

# Create test secrets
vault kv put secret/app/database username=admin password=secret123
vault kv put secret/api/credentials api_key=abc123 password=xyz789
vault kv put secret/config/app debug=true database_url=postgresql://localhost/db
```

## Testing the Application

### 1. Start Secret Sluth

```bash
# Make sure you're in the project directory
cd /path/to/secret-sluth

# Activate virtual environment (if using one)
source venv/bin/activate

# Start the Flask application
python run.py
```

### 2. Access the Web Interface

Open your browser and go to: http://localhost:5000

### 3. Connect to Vault

1. Click "Connect to Vault"
2. Enter the following details:
   - **Vault URL**: `http://localhost:8200`
   - **Vault Token**: `test-token`
3. Click "Connect to Vault"

### 4. Test Features

Once connected, you can:

- **Test Connection**: Click "Test Connection" to verify the connection
- **List Secret Engines**: See available secret engines
- **View Token Info**: Check your token details
- **Search Secrets**: Try searching for terms like "password", "admin", etc.

## Expected Results

When you test the connection, you should see:

- **Connection Status**: Success
- **Secret Engines**: At least one `secret/` engine (KV type)
- **Token Information**: Your token details and policies

When you search for "password", you should find:
- `secret/app/database` (contains password: secret123)
- `secret/api/credentials` (contains password: xyz789)

## Troubleshooting

### Connection Issues

1. **Vault not running**: Make sure Vault is running on port 8200
2. **Wrong URL**: Use `http://localhost:8200` (not https)
3. **Wrong token**: Use `test-token` for development mode

### Permission Issues

In development mode, the `test-token` has full permissions. If you're using a production Vault, make sure your token has these permissions:

```hcl
# Example policy for Secret Sluth
path "sys/mounts" {
  capabilities = ["read"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "secret/*" {
  capabilities = ["read", "list"]
}
```

### Security Note

⚠️ **Important**: This setup is for testing only. Never use development mode or the test token in production!

## Next Steps

Once you've successfully tested the basic functionality:

1. **Try different search terms**: Test case sensitivity, partial matches, etc.
2. **Add more secrets**: Create additional test data
3. **Test error scenarios**: Try invalid tokens, wrong URLs, etc.
4. **Proceed to next step**: Continue with the implementation plan
