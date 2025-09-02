#!/usr/bin/env python3
"""
Example usage of the Vault Client implementation.

This script demonstrates how to use the VaultClient class to connect to a Vault server,
validate tokens, list secret engines, and search for secrets.
"""

import os
import sys
from typing import Dict, Any

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.vault_client import VaultClient, VaultClientError, VaultAuthenticationError, VaultConnectionError


def main():
    """Main function demonstrating Vault client usage."""
    
    # Configuration - you would typically get these from environment variables
    vault_url = os.environ.get('VAULT_URL', 'https://vault.example.com')
    vault_token = os.environ.get('VAULT_TOKEN', 'your-token-here')
    
    print(f"Connecting to Vault at: {vault_url}")
    
    try:
        # Create and connect to Vault
        with VaultClient(vault_url, vault_token) as client:
            print("✅ Successfully connected to Vault!")
            
            # Validate the token
            print("\n🔍 Validating token...")
            token_info = client.validate_token()
            print(f"✅ Token validated successfully!")
            print(f"   Token ID: {token_info['id']}")
            print(f"   Policies: {token_info['policies']}")
            print(f"   TTL: {token_info['ttl']} seconds")
            print(f"   Renewable: {token_info['renewable']}")
            
            # List secret engines
            print("\n🔍 Listing secret engines...")
            engines = client.list_secret_engines()
            print(f"✅ Found {len(engines)} secret engines:")
            
            for engine in engines:
                print(f"   - {engine['path']} ({engine['type']})")
                if engine['description']:
                    print(f"     Description: {engine['description']}")
            
            # Search for secrets (example)
            search_term = os.environ.get('SEARCH_TERM', 'password')
            print(f"\n🔍 Searching for secrets containing '{search_term}'...")
            
            try:
                results = client.search_secrets(search_term, case_sensitive=False)
                print(f"✅ Found {len(results)} matching secrets:")
                
                for i, result in enumerate(results[:5], 1):  # Show first 5 results
                    print(f"   {i}. {result['full_path']}")
                    print(f"      Engine: {result['engine_path']}")
                    print(f"      Path: {result['secret_path']}")
                    
                    # Show a preview of the secret data (be careful with sensitive data)
                    data_preview = str(result['data'])[:100] + "..." if len(str(result['data'])) > 100 else str(result['data'])
                    print(f"      Data: {data_preview}")
                    print()
                
                if len(results) > 5:
                    print(f"   ... and {len(results) - 5} more results")
                    
            except VaultClientError as e:
                print(f"⚠️  Search failed: {e}")
            
            # Example: Get a specific secret
            secret_path = os.environ.get('SECRET_PATH')
            if secret_path:
                print(f"\n🔍 Retrieving secret: {secret_path}")
                try:
                    secret_data = client.get_secret(secret_path)
                    print(f"✅ Secret retrieved successfully!")
                    print(f"   Data: {secret_data}")
                except VaultClientError as e:
                    print(f"❌ Failed to retrieve secret: {e}")
            
    except VaultAuthenticationError as e:
        print(f"❌ Authentication failed: {e}")
        print("   Please check your Vault token and ensure it's valid.")
        sys.exit(1)
        
    except VaultConnectionError as e:
        print(f"❌ Connection failed: {e}")
        print("   Please check your Vault URL and ensure the server is accessible.")
        sys.exit(1)
        
    except VaultClientError as e:
        print(f"❌ Vault client error: {e}")
        sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled by user")
        sys.exit(0)
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)


def interactive_mode():
    """Interactive mode for testing Vault client functionality."""
    
    print("🔐 Vault Client Interactive Mode")
    print("=" * 40)
    
    # Get connection details
    vault_url = input("Enter Vault URL (default: https://vault.example.com): ").strip()
    if not vault_url:
        vault_url = "https://vault.example.com"
    
    vault_token = input("Enter Vault token: ").strip()
    if not vault_token:
        print("❌ Token is required!")
        return
    
    try:
        with VaultClient(vault_url, vault_token) as client:
            print("✅ Connected to Vault!")
            
            while True:
                print("\nOptions:")
                print("1. Validate token")
                print("2. List secret engines")
                print("3. Search secrets")
                print("4. Get specific secret")
                print("5. Exit")
                
                choice = input("\nEnter your choice (1-5): ").strip()
                
                if choice == '1':
                    try:
                        token_info = client.validate_token()
                        print(f"✅ Token is valid!")
                        print(f"   Policies: {token_info['policies']}")
                        print(f"   TTL: {token_info['ttl']} seconds")
                    except VaultClientError as e:
                        print(f"❌ Token validation failed: {e}")
                
                elif choice == '2':
                    try:
                        engines = client.list_secret_engines()
                        print(f"✅ Found {len(engines)} secret engines:")
                        for engine in engines:
                            print(f"   - {engine['path']} ({engine['type']})")
                    except VaultClientError as e:
                        print(f"❌ Failed to list engines: {e}")
                
                elif choice == '3':
                    search_term = input("Enter search term: ").strip()
                    if search_term:
                        try:
                            results = client.search_secrets(search_term, case_sensitive=False)
                            print(f"✅ Found {len(results)} matching secrets:")
                            for i, result in enumerate(results[:10], 1):
                                print(f"   {i}. {result['full_path']}")
                        except VaultClientError as e:
                            print(f"❌ Search failed: {e}")
                
                elif choice == '4':
                    secret_path = input("Enter secret path: ").strip()
                    if secret_path:
                        try:
                            secret_data = client.get_secret(secret_path)
                            print(f"✅ Secret retrieved:")
                            print(f"   {secret_data}")
                        except VaultClientError as e:
                            print(f"❌ Failed to retrieve secret: {e}")
                
                elif choice == '5':
                    print("👋 Goodbye!")
                    break
                
                else:
                    print("❌ Invalid choice. Please enter 1-5.")
                    
    except VaultClientError as e:
        print(f"❌ Vault client error: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--interactive":
        interactive_mode()
    else:
        main()
