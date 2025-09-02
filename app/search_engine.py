"""
Search Engine Implementation for Secret Sluth.

This module provides the core search functionality for discovering secrets
across multiple Vault secret engines with optimized performance for large datasets.
"""

from typing import List, Dict, Optional, Any, Set
from dataclasses import dataclass
from datetime import datetime
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from app.logging_config import get_logger
from app.vault_client import VaultClient, VaultClientError
from app.engine_manager import EngineManager
from app.search_algorithms import SearchAlgorithms
from app.result_collector import ResultCollector, SearchResult

logger = get_logger(__name__)


@dataclass
class SearchConfig:
    """Configuration for search operations."""
    query: str
    case_sensitive: bool = False
    search_in_names: bool = True
    search_in_keys: bool = True
    search_in_values: bool = True
    search_in_metadata: bool = False
    max_results: int = 1000
    timeout: int = 300  # 5 minutes
    max_depth: int = 10
    include_secret_data: bool = False
    parallel_searches: int = 5
    engine_filter: str = ""  # Filter by engine type
    match_type_filter: str = ""  # Filter by match type
    batch_size: int = 50  # Number of secrets to process in parallel
    enable_parallel_processing: bool = True  # Enable parallel processing


class SearchEngine:
    """
    Main search engine that coordinates searches across multiple Vault secret engines.
    Optimized for performance with parallel processing and batch operations.
    """
    
    def __init__(self, vault_client: VaultClient, engine_manager: EngineManager):
        """
        Initialize the search engine.
        
        Args:
            vault_client: Authenticated Vault client
            engine_manager: Engine manager for selected engines
        """
        self.vault_client = vault_client
        self.engine_manager = engine_manager
        self.search_algorithms = SearchAlgorithms()
        self.result_collector = ResultCollector()
        self.logger = get_logger(__name__)
        self._results_lock = threading.Lock()
        
    def search(self, config: SearchConfig, session: Dict) -> List[SearchResult]:
        """
        Perform a search across all selected engines with optimized performance.
        
        Args:
            config: Search configuration
            session: Flask session object
            
        Returns:
            List of search results
        """
        self.logger.info(f"Starting optimized search with query: '{config.query}' across selected engines")
        start_time = time.time()
        
        # Get selected engines from session
        selected_paths = self.engine_manager.get_selected_paths(session)
        self.logger.info(f"Selected paths from session: {selected_paths}")
        
        if not selected_paths:
            raise ValueError("No engines selected for search")
        
        # Apply engine filter if specified
        if config.engine_filter:
            selected_paths = self._filter_engines_by_type(selected_paths, config.engine_filter)
            self.logger.info(f"Filtered to {len(selected_paths)} engines of type: {config.engine_filter}")
        
        # Initialize result collector
        self.result_collector.reset()
        
        # Perform optimized search across engines
        try:
            if config.enable_parallel_processing and len(selected_paths) > 1:
                results = self._search_engines_parallel(selected_paths, config)
            else:
                results = self._search_engines_sequential(selected_paths, config)
            
            # Apply match type filter if specified
            if config.match_type_filter:
                results = self._filter_results_by_match_type(results, config.match_type_filter)
                self.logger.info(f"Filtered to {len(results)} results of match type: {config.match_type_filter}")
            
            search_duration = time.time() - start_time
            self.logger.info(f"Optimized search completed in {search_duration:.2f}s. Found {len(results)} results")
            return results
            
        except Exception as e:
            self.logger.error(f"Search failed: {e}")
            raise
    
    def _search_engines_parallel(self, selected_paths: List[str], config: SearchConfig) -> List[SearchResult]:
        """
        Search across multiple engines in parallel for better performance.
        
        Args:
            selected_paths: List of selected engine paths to search
            config: Search configuration
            
        Returns:
            List of search results
        """
        self.logger.info(f"Starting parallel search across {len(selected_paths)} engines")
        results = []
        
        # Use ThreadPoolExecutor for parallel processing
        max_workers = min(config.parallel_searches, len(selected_paths))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit search tasks for each engine
            future_to_engine = {
                executor.submit(self._search_single_engine, engine_path, config): engine_path
                for engine_path in selected_paths
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_engine):
                engine_path = future_to_engine[future]
                try:
                    engine_results = future.result()
                    with self._results_lock:
                        results.extend(engine_results)
                    self.logger.info(f"Engine {engine_path}: completed with {len(engine_results)} results")
                except Exception as e:
                    self.logger.error(f"Error searching engine {engine_path}: {e}")
                    continue
        
        self.logger.info(f"Parallel search completed: {len(results)} total results")
        return results
    
    def _search_engines_sequential(self, selected_paths: List[str], config: SearchConfig) -> List[SearchResult]:
        """
        Search across multiple engines sequentially (fallback method).
        
        Args:
            selected_paths: List of selected engine paths to search
            config: Search configuration
            
        Returns:
            List of search results
        """
        self.logger.info(f"Starting sequential search across {len(selected_paths)} engines")
        results = []
        
        for engine_path in selected_paths:
            self.logger.info(f"Searching engine: {engine_path}")
            try:
                engine_results = self._search_single_engine(engine_path, config)
                results.extend(engine_results)
                self.logger.info(f"Engine {engine_path}: found {len(engine_results)} results")
            except Exception as e:
                self.logger.error(f"Failed to search engine {engine_path}: {e}")
                continue
        
        return results
    
    def _search_single_engine(self, engine_path: str, config: SearchConfig) -> List[SearchResult]:
        """
        Search a single engine with optimized path processing.
        
        Args:
            engine_path: Engine path to search
            config: Search configuration
            
        Returns:
            List of search results from this engine
        """
        try:
            # Get all paths in this engine
            paths = self._discover_paths(engine_path, max_depth=config.max_depth)
            self.logger.info(f"Engine {engine_path}: discovered {len(paths)} paths to search")
            
            if not paths:
                return []
            
            # Process paths in batches for better performance
            results = []
            batch_size = config.batch_size
            
            for i in range(0, len(paths), batch_size):
                batch_paths = paths[i:i + batch_size]
                batch_results = self._search_paths_batch(batch_paths, config, "kv")
                results.extend(batch_results)
                
                # Log progress for large datasets
                if len(paths) > 100:
                    progress = min(100, (i + batch_size) * 100 / len(paths))
                    self.logger.info(f"Engine {engine_path}: {progress:.1f}% complete ({len(results)} results so far)")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to search engine {engine_path}: {e}")
            return []
    
    def _search_paths_batch(self, paths: List[str], config: SearchConfig, engine_type: str) -> List[SearchResult]:
        """
        Search multiple paths in parallel for better performance.
        
        Args:
            paths: List of paths to search
            config: Search configuration
            engine_type: Type of the engine
            
        Returns:
            List of search results
        """
        if not paths:
            return []
        
        results = []
        
        # Use ThreadPoolExecutor for parallel path processing
        max_workers = min(config.parallel_searches, len(paths))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit search tasks for each path
            future_to_path = {
                executor.submit(self._search_path, path, config, engine_type): path
                for path in paths
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    path_results = future.result()
                    if path_results:
                        with self._results_lock:
                            results.extend(path_results)
                except Exception as e:
                    self.logger.debug(f"Error searching path {path}: {e}")
                    continue
        
        return results
    

    
    def _discover_paths(self, engine_path: str, max_depth: int) -> List[str]:
        """
        Discover all paths within an engine up to a maximum depth.
        Optimized for performance with caching and batch operations.
        
        Args:
            engine_path: Base path of the engine
            max_depth: Maximum depth to search
            
        Returns:
            List of discovered paths
        """
        try:
            self.logger.info(f"Discovering paths in engine: {engine_path}")
            start_time = time.time()
            
            # Get all secrets in the engine
            secrets = self.vault_client.list_secrets_in_engine(engine_path, recursive=True)
            
            # Filter paths based on max_depth and construct full paths
            filtered_paths = []
            for secret_path in secrets:
                # Calculate depth by counting path separators
                depth = secret_path.count('/')
                if depth <= max_depth:
                    # Construct the full path including the engine
                    full_path = f"{engine_path.rstrip('/')}/{secret_path}"
                    filtered_paths.append(full_path)
            
            discovery_time = time.time() - start_time
            self.logger.info(f"Discovered {len(filtered_paths)} paths in engine {engine_path} in {discovery_time:.2f}s (max_depth: {max_depth})")
            return filtered_paths
            
        except Exception as e:
            self.logger.error(f"Failed to discover paths in engine {engine_path}: {e}")
            return []
    

    
    def _search_path(self, path: str, config: SearchConfig, engine_type: str) -> List[SearchResult]:
        """
        Search a specific path for secrets matching the query.
        
        Args:
            path: Path to search
            config: Search configuration
            engine_type: Type of the engine (kv, database, ssh, etc.)
            
        Returns:
            List of search results from this path
        """
        results = []
        
        try:
            self.logger.debug(f"Searching path: {path}")
            self.logger.debug(f"Search config: search_in_names={config.search_in_names}, query='{config.query}'")
            
            # Search in path/secret name first
            if config.search_in_names:
                self.logger.debug(f"Checking if path '{path}' matches query '{config.query}'")
                if self.search_algorithms.matches(path, config.query, config.case_sensitive):
                    self.logger.info(f"Path '{path}' matches query '{config.query}'")
                    # Extract the secret name from the path
                    secret_name = path.split('/')[-1] if path.split('/') else path
                    
                    results.append(SearchResult(
                        path=path,
                        key="[PATH]",
                        value=f"Secret name: {secret_name}",
                        match_type="name",
                        match_context=path,
                        engine_path=self._get_engine_path(path),
                        engine_type=engine_type,
                        timestamp=datetime.now()
                    ))
                else:
                    self.logger.debug(f"Path '{path}' does not match query '{config.query}'")
            
            # Try to read the secret at this path
            secret_data = self._read_secret(path)
            if not secret_data:
                self.logger.debug(f"No secret data found for path: {path}")
                return results
            
            # Search in secret data
            path_results = self._search_secret_data(path, secret_data, config, engine_type)
            results.extend(path_results)
            
        except Exception as e:
            self.logger.debug(f"Could not search path {path}: {e}")
        
        return results
    
    def _read_secret(self, path: str) -> Optional[Dict[str, Any]]:
        """
        Read a secret from Vault.
        
        Args:
            path: Path of the secret to read (full path including engine)
            
        Returns:
            Secret data or None if not found/accessible
        """
        try:
            # Extract engine path from the current path
            engine_path = self._get_engine_path(path)
            
            self.logger.debug(f"Reading secret at {path} (engine: {engine_path})")
            
            # Extract the relative path (remove engine path)
            relative_path = path[len(engine_path):].lstrip('/')
            
            # Use the vault client's working get_secret method
            secret_data = self.vault_client.get_secret(relative_path, engine_path)
            
            return secret_data
                
        except Exception as e:
            self.logger.debug(f"Could not read secret at {path}: {e}")
        
        return None
    
    def _search_secret_data(self, path: str, secret_data: Optional[Dict[str, Any]], 
                           config: SearchConfig, engine_type: str) -> List[SearchResult]:
        """
        Search within secret data for matches.
        
        Args:
            path: Path of the secret
            secret_data: Secret data to search (can be None)
            config: Search configuration
            engine_type: Type of the engine (kv, database, ssh, etc.)
            
        Returns:
            List of search results
        """
        results = []
        
        # Handle case where secret_data is None
        if not secret_data:
            return results
        
        # Ensure secret_data is a dictionary
        if not isinstance(secret_data, dict):
            self.logger.debug(f"Secret data is not a dictionary for path {path}: {type(secret_data)}")
            return results
        
        for key, value in secret_data.items():
            # Search in key
            if config.search_in_keys:
                if self.search_algorithms.matches(key, config.query, config.case_sensitive):
                    results.append(SearchResult(
                        path=path,
                        key=key,
                        value=value if config.include_secret_data else "[REDACTED]",
                        match_type="key",
                        match_context=key,
                        engine_path=self._get_engine_path(path),
                        engine_type=engine_type,
                        timestamp=datetime.now()
                    ))
            
            # Search in value
            if config.search_in_values and isinstance(value, str):
                if self.search_algorithms.matches(value, config.query, config.case_sensitive):
                    results.append(SearchResult(
                        path=path,
                        key=key,
                        value=value if config.include_secret_data else "[REDACTED]",
                        match_type="value",
                        match_context=self.search_algorithms.get_match_context(value, config.query, config.case_sensitive),
                        engine_path=self._get_engine_path(path),
                        engine_type=engine_type,
                        timestamp=datetime.now()
                    ))
        
        return results
    
    def _get_engine_path(self, secret_path: str) -> str:
        """
        Extract the engine path from a secret path.
        
        Args:
            secret_path: Full path of the secret
            
        Returns:
            Engine path
        """
        # Split path and return the first component as engine path
        parts = secret_path.strip('/').split('/')
        if parts:
            # Return without leading slash for consistency
            return parts[0]
        return ""
    
    def _filter_engines_by_type(self, engine_paths: List[str], engine_type: str) -> List[str]:
        """
        Filter engines by type.
        
        Args:
            engine_paths: List of engine paths
            engine_type: Type to filter by (kv, database, ssh, pki, etc.)
            
        Returns:
            Filtered list of engine paths
        """
        # For now, we'll do a simple filter based on path patterns
        # In a real implementation, you'd query the engine metadata
        filtered_paths = []
        
        for path in engine_paths:
            # Simple heuristic based on path patterns
            if engine_type == "kv" and ("kv" in path.lower() or "secret" in path.lower()):
                filtered_paths.append(path)
            elif engine_type == "database" and ("database" in path.lower() or "db" in path.lower()):
                filtered_paths.append(path)
            elif engine_type == "ssh" and "ssh" in path.lower():
                filtered_paths.append(path)
            elif engine_type == "pki" and "pki" in path.lower():
                filtered_paths.append(path)
            # If no specific type matches, include all (fallback)
            elif not engine_type:
                filtered_paths.append(path)
        
        return filtered_paths if filtered_paths else engine_paths
    
    def _filter_results_by_match_type(self, results: List[SearchResult], match_type: str) -> List[SearchResult]:
        """
        Filter results by match type.
        
        Args:
            results: List of search results
            match_type: Type to filter by (name, key, value, metadata)
            
        Returns:
            Filtered list of results
        """
        if not match_type:
            return results
        
        filtered_results = []
        for result in results:
            if result.match_type == match_type:
                filtered_results.append(result)
        
        return filtered_results
