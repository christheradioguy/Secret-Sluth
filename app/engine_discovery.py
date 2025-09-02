"""
Engine Discovery Module

This module provides advanced secret engine discovery capabilities including
recursive discovery, permission checking, metadata collection, and filtering.
"""

import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache

from .vault_client import VaultClient, VaultClientError, VaultPermissionError
from .logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class EngineMetadata:
    """Metadata for a secret engine."""
    path: str
    type: str
    description: str
    accessor: str
    options: Dict[str, Any]
    config: Dict[str, Any]
    permissions: Dict[str, bool]
    secret_count: Optional[int] = None
    last_accessed: Optional[datetime] = None
    created_at: Optional[datetime] = None
    tags: List[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        data = asdict(self)
        if self.last_accessed:
            data['last_accessed'] = self.last_accessed.isoformat()
        if self.created_at:
            data['created_at'] = self.created_at.isoformat()
        return data


class EngineDiscoveryError(Exception):
    """Base exception for engine discovery errors."""
    pass


class EngineDiscovery:
    """
    Advanced secret engine discovery with recursive scanning, permission checking,
    and metadata collection.
    """
    
    def __init__(self, vault_client: VaultClient, max_workers: int = 5, timeout: int = 30):
        """
        Initialize the engine discovery.
        
        Args:
            vault_client: The Vault client instance
            max_workers: Maximum number of worker threads for parallel discovery
            timeout: Timeout for individual operations in seconds
        """
        self.vault_client = vault_client
        self.max_workers = max_workers
        self.timeout = timeout
        self._discovered_engines: Dict[str, EngineMetadata] = {}
        self._permission_cache: Dict[str, Dict[str, bool]] = {}
        
        logger.info(f"Initialized engine discovery with {max_workers} workers")
    
    def discover_engines(self, recursive: bool = True, include_inaccessible: bool = False,
                        engine_types: List[str] = None, path_filters: List[str] = None) -> List[EngineMetadata]:
        """
        Discover all available secret engines with comprehensive metadata.
        
        Args:
            recursive: Whether to perform recursive discovery
            include_inaccessible: Whether to include engines without read permissions
            engine_types: Filter by specific engine types (e.g., ['kv', 'database'])
            path_filters: Filter by path patterns (supports wildcards)
            
        Returns:
            List of engine metadata objects
        """
        logger.info("Starting engine discovery")
        start_time = time.time()
        
        try:
            # Get basic engine list
            basic_engines = self.vault_client.list_secret_engines()
            
            # Convert to metadata objects
            engines = []
            for engine_data in basic_engines:
                metadata = self._create_engine_metadata(engine_data)
                engines.append(metadata)
            
            # Apply filters
            engines = self._apply_filters(engines, engine_types, path_filters)
            
            # Check permissions and collect additional metadata
            if recursive:
                engines = self._enhance_metadata_recursive(engines, include_inaccessible)
            else:
                engines = self._enhance_metadata_basic(engines, include_inaccessible)
            
            # Cache results
            self._discovered_engines = {engine.path: engine for engine in engines}
            
            discovery_time = time.time() - start_time
            logger.info(f"Engine discovery completed in {discovery_time:.2f}s. Found {len(engines)} engines")
            
            return engines
            
        except Exception as e:
            logger.error(f"Engine discovery failed: {str(e)}")
            raise EngineDiscoveryError(f"Engine discovery failed: {str(e)}")
    
    def _create_engine_metadata(self, engine_data: Dict[str, Any]) -> EngineMetadata:
        """Create an EngineMetadata object from basic engine data."""
        return EngineMetadata(
            path=engine_data['path'],
            type=engine_data['type'],
            description=engine_data.get('description', ''),
            accessor=engine_data.get('accessor', ''),
            options=engine_data.get('options', {}),
            config=engine_data.get('config', {}),
            permissions={},
            tags=[]
        )
    
    def _apply_filters(self, engines: List[EngineMetadata], 
                      engine_types: List[str] = None, 
                      path_filters: List[str] = None) -> List[EngineMetadata]:
        """Apply type and path filters to the engine list."""
        filtered_engines = engines
        
        # Filter by engine type
        if engine_types:
            filtered_engines = [
                engine for engine in filtered_engines 
                if engine.type in engine_types
            ]
            logger.debug(f"Filtered by engine types {engine_types}: {len(filtered_engines)} engines")
        
        # Filter by path patterns
        if path_filters:
            import fnmatch
            filtered_engines = [
                engine for engine in filtered_engines
                if any(fnmatch.fnmatch(engine.path, pattern) for pattern in path_filters)
            ]
            logger.debug(f"Filtered by path patterns {path_filters}: {len(filtered_engines)} engines")
        
        return filtered_engines
    
    def _enhance_metadata_basic(self, engines: List[EngineMetadata], 
                               include_inaccessible: bool) -> List[EngineMetadata]:
        """Enhance metadata with basic permission checking."""
        enhanced_engines = []
        
        for engine in engines:
            try:
                # Check basic permissions
                permissions = self._check_engine_permissions(engine.path)
                engine.permissions = permissions
                
                # Only include if accessible or if including inaccessible engines
                if permissions.get('read', False) or include_inaccessible:
                    enhanced_engines.append(engine)
                    
            except Exception as e:
                logger.warning(f"Failed to check permissions for engine {engine.path}: {str(e)}")
                if include_inaccessible:
                    engine.permissions = {'read': False, 'write': False, 'delete': False}
                    enhanced_engines.append(engine)
        
        return enhanced_engines
    
    def _enhance_metadata_recursive(self, engines: List[EngineMetadata], 
                                   include_inaccessible: bool) -> List[EngineMetadata]:
        """Enhance metadata with recursive permission checking and secret counting."""
        enhanced_engines = []
        
        # Use thread pool for parallel processing
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit tasks for parallel processing
            future_to_engine = {
                executor.submit(self._enhance_single_engine, engine, include_inaccessible): engine
                for engine in engines
            }
            
            # Collect results
            for future in as_completed(future_to_engine, timeout=self.timeout):
                try:
                    enhanced_engine = future.result()
                    if enhanced_engine:
                        enhanced_engines.append(enhanced_engine)
                except Exception as e:
                    engine = future_to_engine[future]
                    logger.warning(f"Failed to enhance engine {engine.path}: {str(e)}")
                    if include_inaccessible:
                        engine.permissions = {'read': False, 'write': False, 'delete': False}
                        enhanced_engines.append(engine)
        
        return enhanced_engines
    
    def _enhance_single_engine(self, engine: EngineMetadata, 
                              include_inaccessible: bool) -> Optional[EngineMetadata]:
        """Enhance a single engine with detailed metadata."""
        try:
            # Check permissions
            permissions = self._check_engine_permissions(engine.path)
            engine.permissions = permissions
            
            # Only proceed if accessible or if including inaccessible engines
            if not permissions.get('read', False) and not include_inaccessible:
                return None
            
            # Count secrets if we have read permission
            if permissions.get('read', False):
                try:
                    secret_count = self._count_secrets_in_engine(engine.path)
                    engine.secret_count = secret_count
                except Exception as e:
                    logger.debug(f"Could not count secrets in {engine.path}: {str(e)}")
                    engine.secret_count = None
            
            # Add tags based on engine type and characteristics
            engine.tags = self._generate_engine_tags(engine)
            
            return engine
            
        except Exception as e:
            logger.warning(f"Failed to enhance engine {engine.path}: {str(e)}")
            if include_inaccessible:
                engine.permissions = {'read': False, 'write': False, 'delete': False}
                return engine
            return None
    
    def _check_engine_permissions(self, engine_path: str) -> Dict[str, bool]:
        """Check permissions for a specific engine."""
        # Check cache first
        if engine_path in self._permission_cache:
            return self._permission_cache[engine_path]
        
        permissions = {
            'read': False,
            'write': False,
            'delete': False,
            'list': False
        }
        
        try:
            # For KV engines, try to list secrets to check permissions
            # For other engine types, we'll assume basic access if we can connect
            engine_info = self.vault_client.list_secret_engines()
            engine_data = next((e for e in engine_info if e['path'] == engine_path), None)
            
            if engine_data and engine_data.get('type') == 'kv':
                # For KV engines, try to list secrets
                try:
                    self.vault_client.list_secrets_in_engine(engine_path, recursive=False)
                    permissions['read'] = True
                    permissions['list'] = True
                except Exception as e:
                    logger.debug(f"KV engine {engine_path} permission check failed: {str(e)}")
                    # Don't cache failed permissions to allow retry
                    return permissions
            else:
                # For non-KV engines, assume basic access if we can see the engine
                permissions['read'] = True
                permissions['list'] = True
            
            # For write permissions, we'll be conservative and assume read-only
            # unless we can prove otherwise
            permissions['write'] = False
            permissions['delete'] = False
            
            # Cache the results
            self._permission_cache[engine_path] = permissions
            
        except Exception as e:
            logger.debug(f"Permission check failed for {engine_path}: {str(e)}")
            # Don't cache failed permissions to allow retry
        
        return permissions
    
    def _count_secrets_in_engine(self, engine_path: str) -> int:
        """Count the number of secrets in an engine."""
        try:
            # Only try to count secrets for KV engines
            engine_info = self.vault_client.list_secret_engines()
            engine_data = next((e for e in engine_info if e['path'] == engine_path), None)
            
            if engine_data and engine_data.get('type') == 'kv':
                # For KV engines, try to list secrets
                secrets = self.vault_client.list_secrets_in_engine(engine_path, recursive=True)
                return len(secrets)
            else:
                # For non-KV engines, we can't easily count secrets
                logger.debug(f"Not counting secrets in {engine_path} (non-KV engine)")
                return None  # Return None to indicate we can't count
                
        except Exception as e:
            # For engines with different APIs or permission issues, we can't count secrets
            # This is expected behavior, not an error
            logger.debug(f"Could not count secrets in {engine_path}: {str(e)}")
            return None  # Return None to indicate we can't count
    
    def _generate_engine_tags(self, engine: EngineMetadata) -> List[str]:
        """Generate tags for an engine based on its characteristics."""
        tags = []
        
        # Add engine type tag
        tags.append(f"type:{engine.type}")
        
        # Add permission tags
        if engine.permissions.get('read', False):
            tags.append("readable")
        if engine.permissions.get('write', False):
            tags.append("writable")
        
        # Add size tags based on secret count
        if engine.secret_count is not None:
            if engine.secret_count == 0:
                tags.append("empty")
            elif engine.secret_count < 10:
                tags.append("small")
            elif engine.secret_count < 100:
                tags.append("medium")
            else:
                tags.append("large")
        
        # Add special tags for common engine types
        if engine.type == 'kv':
            tags.append("key-value")
        elif engine.type == 'database':
            tags.append("database")
        elif engine.type == 'ssh':
            tags.append("ssh")
        elif engine.type == 'pki':
            tags.append("certificate")
        
        return tags
    
    def get_engine_by_path(self, path: str) -> Optional[EngineMetadata]:
        """Get a specific engine by path."""
        return self._discovered_engines.get(path)
    
    def get_engines_by_type(self, engine_type: str) -> List[EngineMetadata]:
        """Get all engines of a specific type."""
        return [
            engine for engine in self._discovered_engines.values()
            if engine.type == engine_type
        ]
    
    def get_engines_by_tag(self, tag: str) -> List[EngineMetadata]:
        """Get all engines with a specific tag."""
        return [
            engine for engine in self._discovered_engines.values()
            if tag in engine.tags
        ]
    
    def get_accessible_engines(self) -> List[EngineMetadata]:
        """Get all engines with read permission."""
        return [
            engine for engine in self._discovered_engines.values()
            if engine.permissions.get('read', False)
        ]
    
    def clear_cache(self):
        """Clear the permission cache."""
        self._permission_cache.clear()
        logger.debug("Permission cache cleared")
    
    def get_discovery_stats(self) -> Dict[str, Any]:
        """Get statistics about the discovery process."""
        total_engines = len(self._discovered_engines)
        accessible_engines = len(self.get_accessible_engines())
        
        engine_types = {}
        for engine in self._discovered_engines.values():
            engine_types[engine.type] = engine_types.get(engine.type, 0) + 1
        
        return {
            'total_engines': total_engines,
            'accessible_engines': accessible_engines,
            'inaccessible_engines': total_engines - accessible_engines,
            'engine_types': engine_types,
            'cache_size': len(self._permission_cache)
        }
