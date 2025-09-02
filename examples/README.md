# Secret Sluth Examples

This directory contains example scripts demonstrating how to use the Secret Sluth Vault client and engine discovery functionality.

## vault_client_example.py

A comprehensive example script that demonstrates the core functionality of the VaultClient class.

### Features

- **Connection Management**: Shows how to connect to a Vault server using the context manager
- **Token Validation**: Demonstrates token validation and information retrieval
- **Secret Engine Enumeration**: Lists all available secret engines
- **Secret Search**: Searches for secrets containing specific terms
- **Individual Secret Retrieval**: Shows how to retrieve specific secrets
- **Error Handling**: Comprehensive error handling for various failure scenarios

### Usage

#### Basic Usage

```bash
# Set environment variables
export VAULT_URL="https://your-vault-server.com"
export VAULT_TOKEN="your-vault-token"
export SEARCH_TERM="password"  # Optional
export SECRET_PATH="path/to/secret"  # Optional

# Run the example
python examples/vault_client_example.py
```

#### Interactive Mode

For testing and exploration, you can run the script in interactive mode:

```bash
python examples/vault_client_example.py --interactive
```

This will prompt you for:
- Vault server URL
- Vault token
- Various operations to perform

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VAULT_URL` | URL of the Vault server | `https://vault.example.com` |
| `VAULT_TOKEN` | Authentication token | `your-token-here` |
| `SEARCH_TERM` | Term to search for in secrets | `password` |
| `SECRET_PATH` | Path to a specific secret to retrieve | None |

### Example Output

```
Connecting to Vault at: https://vault.example.com
✅ Successfully connected to Vault!

🔍 Validating token...
✅ Token validated successfully!
   Token ID: hvs.xxxxxxxxxxxxxxxx
   Policies: ['default', 'admin']
   TTL: 3600 seconds
   Renewable: True

🔍 Listing secret engines...
✅ Found 3 secret engines:
   - secret/ (kv)
     Description: KV Version 2 secret engine
   - database/ (database)
     Description: Database secret engine
   - pki/ (pki)
     Description: PKI secret engine

🔍 Searching for secrets containing 'password'...
✅ Found 2 matching secrets:
   1. secret/app/database
      Engine: secret/
      Path: app/database
      Data: {'username': 'admin', 'password': 'secret123'}

   2. secret/api/credentials
      Engine: secret/
      Path: api/credentials
      Data: {'api_key': 'abc123', 'password': 'xyz789'}
```

### Error Handling

The example script demonstrates proper error handling for:

- **Authentication Errors**: Invalid or expired tokens
- **Connection Errors**: Network issues or unreachable servers
- **Permission Errors**: Insufficient permissions for operations
- **General Vault Errors**: Other Vault-related issues

### Security Notes

⚠️ **Important Security Considerations:**

1. **Token Security**: Never hardcode tokens in scripts. Use environment variables or secure token management.
2. **Secret Exposure**: The example shows secret data for demonstration. In production, be careful about logging or displaying secret values.
3. **Network Security**: Ensure connections to Vault are over HTTPS in production environments.
4. **Token Permissions**: Use tokens with minimal required permissions for your use case.

### Integration with Secret Sluth

This example demonstrates the core Vault client functionality that will be used by the Secret Sluth web application. The same VaultClient class will be used for:

- User authentication and token validation
- Secret engine discovery and selection
- Secret search operations
- Result processing and display

## engine_discovery_example.py

A comprehensive example script that demonstrates the advanced engine discovery and caching functionality.

### Features

- **Recursive Engine Discovery**: Discovers all secret engines with detailed metadata
- **Permission Checking**: Tests read/write permissions for each engine
- **Engine Filtering**: Filters engines by type, path patterns, and tags
- **Performance Caching**: Demonstrates memory and file-based caching
- **Statistics and Analytics**: Provides detailed discovery and cache statistics
- **Parallel Processing**: Uses thread pools for efficient discovery

### Usage

#### Basic Usage

```bash
# Set environment variables
export VAULT_URL="https://your-vault-server.com"
export VAULT_TOKEN="your-vault-token"

# Run the example
python examples/engine_discovery_example.py
```

### Example Output

```
🔍 Secret Sluth - Engine Discovery Example
==================================================
🔗 Connecting to Vault at https://vault.example.com...
✅ Successfully connected to Vault

📁 Initializing engine discovery...

🔍 Discovering engines (basic)...
   Found 3 engines
   - secret/ (kv)
   - database/ (database)
   - pki/ (pki)

🔍 Discovering engines (recursive)...
   Found 3 engines
   ✅ secret/ (kv) - 15 secrets
   ✅ database/ (database) - 8 secrets
   ❌ pki/ (pki) - 0 secrets

🔍 Filtering engines by type (KV only)...
   Found 1 KV engines
   - secret/

🔍 Filtering engines by tag (readable)...
   Found 2 readable engines
   - secret/
   - database/

📊 Discovery Statistics:
   Total engines: 3
   Accessible engines: 2
   Inaccessible engines: 1
   Engine types: {'kv': 1, 'database': 1, 'pki': 1}
   Permission cache size: 3

💾 Testing caching...
   First discovery (should be slow)...
   Second discovery (should be fast due to cache)...
   First discovery: 2.34s
   Second discovery: 0.01s
   Speed improvement: 234.0x faster

✅ Example completed successfully!
```

### Key Features Demonstrated

1. **Engine Metadata**: Each engine includes path, type, description, permissions, and secret count
2. **Permission Analysis**: Automatically tests read/write permissions for each engine
3. **Tagging System**: Engines are tagged based on type, permissions, and size
4. **Caching Performance**: Shows significant performance improvements with caching
5. **Filtering Options**: Multiple ways to filter and organize engines
6. **Statistics**: Comprehensive statistics about discovery process and cache usage

### Next Steps

After understanding these examples, you can:

1. **Explore the Test Suite**: 
   - Run `python -m pytest tests/unit/test_vault_client.py -v` for Vault client tests
   - Run `python -m pytest tests/unit/test_engine_discovery.py -v` for engine discovery tests
   - Run `python -m pytest tests/unit/test_engine_cache.py -v` for caching tests

2. **Review the Implementation**: 
   - Examine `app/vault_client.py` for the complete Vault client implementation
   - Examine `app/engine_discovery.py` for the engine discovery functionality
   - Examine `app/engine_cache.py` for the caching system

3. **Proceed to Next Phase**: Continue with Step 3.2 of the implementation plan to create the user interface for engine selection
