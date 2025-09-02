#!/usr/bin/env python3
"""
Engine Discovery Example

This example demonstrates how to use the engine discovery and caching
functionality to discover and analyze secret engines in a Vault server.
"""

import os
import sys
import tempfile
from pathlib import Path

# Add the app directory to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.vault_client import VaultClient
from app.engine_discovery import EngineDiscovery
from app.engine_cache import EngineCache


def main():
    """Main example function."""
    print("🔍 Secret Sluth - Engine Discovery Example")
    print("=" * 50)
    
    # Configuration
    vault_url = os.getenv('VAULT_URL', 'https://vault.example.com')
    vault_token = os.getenv('VAULT_TOKEN', 'your-token-here')
    
    if vault_token == 'your-token-here':
        print("❌ Please set VAULT_URL and VAULT_TOKEN environment variables")
        print("   export VAULT_URL='https://your-vault-server.com'")
        print("   export VAULT_TOKEN='your-vault-token'")
        return
    
    try:
        # Initialize Vault client
        print(f"🔗 Connecting to Vault at {vault_url}...")
        vault_client = VaultClient(vault_url, vault_token)
        
        with vault_client:
            # Test connection
            if not vault_client.is_connected():
                print("❌ Failed to connect to Vault")
                return
            
            print("✅ Successfully connected to Vault")
            
            # Initialize engine discovery with caching
            print("\n📁 Initializing engine discovery...")
            cache_dir = tempfile.mkdtemp(prefix="vault_cache_")
            engine_cache = EngineCache(cache_dir=cache_dir, default_ttl=300)
            engine_discovery = EngineDiscovery(vault_client, max_workers=3, timeout=30)
            
            # Discover engines with different options
            print("\n🔍 Discovering engines (basic)...")
            engines_basic = engine_discovery.discover_engines(
                recursive=False,
                include_inaccessible=False
            )
            
            print(f"   Found {len(engines_basic)} engines")
            for engine in engines_basic:
                print(f"   - {engine.path} ({engine.type})")
            
            # Discover engines with recursive scanning
            print("\n🔍 Discovering engines (recursive)...")
            engines_recursive = engine_discovery.discover_engines(
                recursive=True,
                include_inaccessible=True
            )
            
            print(f"   Found {len(engines_recursive)} engines")
            for engine in engines_recursive:
                status = "✅" if engine.permissions.get('read', False) else "❌"
                count = engine.secret_count or 0
                print(f"   {status} {engine.path} ({engine.type}) - {count} secrets")
            
            # Filter engines by type
            print("\n🔍 Filtering engines by type (KV only)...")
            kv_engines = engine_discovery.get_engines_by_type('kv')
            print(f"   Found {len(kv_engines)} KV engines")
            for engine in kv_engines:
                print(f"   - {engine.path}")
            
            # Filter engines by tag
            print("\n🔍 Filtering engines by tag (readable)...")
            readable_engines = engine_discovery.get_engines_by_tag('readable')
            print(f"   Found {len(readable_engines)} readable engines")
            for engine in readable_engines:
                print(f"   - {engine.path}")
            
            # Get accessible engines only
            print("\n🔍 Getting accessible engines...")
            accessible_engines = engine_discovery.get_accessible_engines()
            print(f"   Found {len(accessible_engines)} accessible engines")
            
            # Get discovery statistics
            print("\n📊 Discovery Statistics:")
            stats = engine_discovery.get_discovery_stats()
            print(f"   Total engines: {stats['total_engines']}")
            print(f"   Accessible engines: {stats['accessible_engines']}")
            print(f"   Inaccessible engines: {stats['inaccessible_engines']}")
            print(f"   Engine types: {stats['engine_types']}")
            print(f"   Permission cache size: {stats['cache_size']}")
            
            # Cache statistics
            print("\n📊 Cache Statistics:")
            cache_stats = engine_cache.get_stats()
            print(f"   Memory entries: {cache_stats['memory_entries']}")
            print(f"   File entries: {cache_stats['file_entries']}")
            print(f"   Memory size: {cache_stats['memory_size_mb']:.2f} MB")
            print(f"   File size: {cache_stats['file_size_mb']:.2f} MB")
            
            # Demonstrate caching
            print("\n💾 Testing caching...")
            print("   First discovery (should be slow)...")
            import time
            start_time = time.time()
            engines_cached = engine_discovery.discover_engines(recursive=False)
            first_time = time.time() - start_time
            
            print("   Second discovery (should be fast due to cache)...")
            start_time = time.time()
            engines_cached_again = engine_discovery.discover_engines(recursive=False)
            second_time = time.time() - start_time
            
            print(f"   First discovery: {first_time:.2f}s")
            print(f"   Second discovery: {second_time:.2f}s")
            print(f"   Speed improvement: {first_time/second_time:.1f}x faster")
            
            # Clean up
            print(f"\n🧹 Cleaning up cache directory: {cache_dir}")
            import shutil
            shutil.rmtree(cache_dir)
            
            print("\n✅ Example completed successfully!")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return


if __name__ == "__main__":
    main()
