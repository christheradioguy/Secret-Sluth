"""
Result Collector for Secret Sluth.

This module handles the collection, organization, and processing of search results
from across multiple Vault secret engines.
"""

import json
from typing import List, Dict, Optional, Any, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime
from collections import defaultdict
import hashlib

from app.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class SearchResult:
    """Represents a single search result."""
    path: str
    key: str
    value: str
    match_type: str  # "key", "value", "metadata"
    match_context: str
    engine_path: str
    engine_type: str  # "kv", "database", "ssh", etc.
    timestamp: datetime
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization processing."""
        if isinstance(self.timestamp, str):
            self.timestamp = datetime.fromisoformat(self.timestamp)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        try:
            result = asdict(self)
            result['timestamp'] = self.timestamp.isoformat()
            return result
        except Exception as e:
            # Fallback manual conversion if asdict fails
            return {
                'path': str(self.path) if self.path else '',
                'key': str(self.key) if self.key else '',
                'value': str(self.value) if self.value else '',
                'match_type': str(self.match_type) if self.match_type else '',
                'match_context': str(self.match_context) if self.match_context else '',
                'engine_path': str(self.engine_path) if self.engine_path else '',
                'engine_type': str(self.engine_type) if self.engine_type else '',
                'timestamp': self.timestamp.isoformat() if self.timestamp else '',
                'confidence': float(self.confidence) if self.confidence else 0.0,
                'metadata': dict(self.metadata) if self.metadata else {}
            }
    
    def get_unique_id(self) -> str:
        """Generate a unique identifier for this result."""
        content = f"{self.path}:{self.key}:{self.match_type}:{self.engine_path}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def get_display_path(self) -> str:
        """Get a display-friendly version of the path."""
        return self.path.replace(self.engine_path, '').strip('/') or '/'
    
    def get_severity_level(self) -> str:
        """Determine severity level based on match type and content."""
        # Highest severity for name matches (exact secret identification)
        if self.match_type == "name":
            return "high"
        
        # High severity for key matches (more likely to be important)
        if self.match_type == "key":
            return "high"
        
        # Medium severity for value matches
        if self.match_type == "value":
            return "medium"
        
        # Low severity for metadata matches
        return "low"


@dataclass
class SearchSummary:
    """Summary statistics for a search operation."""
    total_results: int
    results_by_engine: Dict[str, int]
    results_by_type: Dict[str, int]
    search_duration: float
    engines_searched: int
    total_paths_searched: int
    errors_encountered: int
    warnings_encountered: int
    start_time: datetime
    end_time: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = asdict(self)
        result['start_time'] = self.start_time.isoformat()
        result['end_time'] = self.end_time.isoformat()
        return result


class ResultCollector:
    """
    Collects, organizes, and processes search results from multiple engines.
    """
    
    def __init__(self):
        """Initialize the result collector."""
        self.results: List[SearchResult] = []
        self.duplicate_hashes: Set[str] = set()
        self.logger = get_logger(__name__)
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
    
    def reset(self):
        """Reset the collector for a new search."""
        self.results.clear()
        self.duplicate_hashes.clear()
        self.start_time = None
        self.end_time = None
    
    def add_result(self, result: SearchResult) -> bool:
        """
        Add a search result to the collection.
        
        Args:
            result: Search result to add
            
        Returns:
            True if result was added, False if it was a duplicate
        """
        # Check for duplicates
        result_id = result.get_unique_id()
        if result_id in self.duplicate_hashes:
            self.logger.debug(f"Skipping duplicate result: {result.path}")
            return False
        
        # Add result
        self.results.append(result)
        self.duplicate_hashes.add(result_id)
        return True
    
    def add_results(self, results: List[SearchResult]) -> int:
        """
        Add multiple search results to the collection.
        
        Args:
            results: List of search results to add
            
        Returns:
            Number of results actually added (excluding duplicates)
        """
        added_count = 0
        for result in results:
            if self.add_result(result):
                added_count += 1
        
        return added_count
    
    def get_results(self, limit: Optional[int] = None, 
                   offset: int = 0, 
                   sort_by: str = "timestamp",
                   sort_order: str = "desc") -> List[SearchResult]:
        """
        Get search results with optional pagination and sorting.
        
        Args:
            limit: Maximum number of results to return
            offset: Number of results to skip
            sort_by: Field to sort by ("timestamp", "path", "key", "engine_path")
            sort_order: Sort order ("asc" or "desc")
            
        Returns:
            List of search results
        """
        # Sort results
        sorted_results = self._sort_results(self.results, sort_by, sort_order)
        
        # Apply pagination
        start = offset
        end = start + limit if limit else len(sorted_results)
        
        return sorted_results[start:end]
    
    def _sort_results(self, results: List[SearchResult], 
                     sort_by: str, sort_order: str) -> List[SearchResult]:
        """
        Sort results by the specified field and order.
        
        Args:
            results: Results to sort
            sort_by: Field to sort by
            sort_order: Sort order
            
        Returns:
            Sorted list of results
        """
        reverse = sort_order.lower() == "desc"
        
        if sort_by == "timestamp":
            return sorted(results, key=lambda r: r.timestamp, reverse=reverse)
        elif sort_by == "path":
            return sorted(results, key=lambda r: r.path, reverse=reverse)
        elif sort_by == "key":
            return sorted(results, key=lambda r: r.key, reverse=reverse)
        elif sort_by == "engine_path":
            return sorted(results, key=lambda r: r.engine_path, reverse=reverse)
        elif sort_by == "severity":
            severity_order = {"high": 3, "medium": 2, "low": 1}
            return sorted(results, key=lambda r: severity_order.get(r.get_severity_level(), 0), reverse=reverse)
        else:
            # Default to timestamp
            return sorted(results, key=lambda r: r.timestamp, reverse=reverse)
    
    def get_results_by_engine(self) -> Dict[str, List[SearchResult]]:
        """
        Group results by engine path.
        
        Returns:
            Dictionary mapping engine paths to lists of results
        """
        grouped = defaultdict(list)
        for result in self.results:
            grouped[result.engine_path].append(result)
        
        return dict(grouped)
    
    def get_results_by_type(self) -> Dict[str, List[SearchResult]]:
        """
        Group results by match type.
        
        Returns:
            Dictionary mapping match types to lists of results
        """
        grouped = defaultdict(list)
        for result in self.results:
            grouped[result.match_type].append(result)
        
        return dict(grouped)
    
    def get_results_by_severity(self) -> Dict[str, List[SearchResult]]:
        """
        Group results by severity level.
        
        Returns:
            Dictionary mapping severity levels to lists of results
        """
        grouped = defaultdict(list)
        for result in self.results:
            severity = result.get_severity_level()
            grouped[severity].append(result)
        
        return dict(grouped)
    
    def filter_results(self, filters: Dict[str, Any]) -> List[SearchResult]:
        """
        Filter results based on specified criteria.
        
        Args:
            filters: Dictionary of filter criteria
                - engine_path: Filter by engine path
                - match_type: Filter by match type
                - severity: Filter by severity level
                - path_contains: Filter by path containing string
                - key_contains: Filter by key containing string
                
        Returns:
            Filtered list of results
        """
        filtered = self.results
        
        if 'engine_path' in filters:
            engine_path = filters['engine_path']
            filtered = [r for r in filtered if r.engine_path == engine_path]
        
        if 'match_type' in filters:
            match_type = filters['match_type']
            filtered = [r for r in filtered if r.match_type == match_type]
        
        if 'severity' in filters:
            severity = filters['severity']
            filtered = [r for r in filtered if r.get_severity_level() == severity]
        
        if 'path_contains' in filters:
            path_contains = filters['path_contains']
            filtered = [r for r in filtered if path_contains.lower() in r.path.lower()]
        
        if 'key_contains' in filters:
            key_contains = filters['key_contains']
            filtered = [r for r in filtered if key_contains.lower() in r.key.lower()]
        
        return filtered
    
    def get_summary(self, search_duration: float, engines_searched: int,
                   total_paths_searched: int, errors: int = 0, warnings: int = 0) -> SearchSummary:
        """
        Generate a summary of the search results.
        
        Args:
            search_duration: Duration of the search in seconds
            engines_searched: Number of engines searched
            total_paths_searched: Total number of paths searched
            errors: Number of errors encountered
            warnings: Number of warnings encountered
            
        Returns:
            Search summary object
        """
        # Group results by engine
        results_by_engine = {}
        for result in self.results:
            engine = result.engine_path
            results_by_engine[engine] = results_by_engine.get(engine, 0) + 1
        
        # Group results by type
        results_by_type = {}
        for result in self.results:
            match_type = result.match_type
            results_by_type[match_type] = results_by_type.get(match_type, 0) + 1
        
        return SearchSummary(
            total_results=len(self.results),
            results_by_engine=results_by_engine,
            results_by_type=results_by_type,
            search_duration=search_duration,
            engines_searched=engines_searched,
            total_paths_searched=total_paths_searched,
            errors_encountered=errors,
            warnings_encountered=warnings,
            start_time=self.start_time or datetime.now(),
            end_time=self.end_time or datetime.now()
        )
    
    def export_results(self, format: str = "json", include_secret_data: bool = False) -> str:
        """
        Export results in the specified format.
        
        Args:
            format: Export format ("json", "csv")
            include_secret_data: Whether to include actual secret values
            
        Returns:
            Exported data as string
        """
        if format.lower() == "json":
            return self._export_json(include_secret_data)
        elif format.lower() == "csv":
            return self._export_csv(include_secret_data)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def _export_json(self, include_secret_data: bool) -> str:
        """Export results as JSON."""
        export_data = []
        
        for result in self.results:
            result_dict = result.to_dict()
            
            # Handle secret data inclusion
            if not include_secret_data and result.match_type == "value":
                result_dict['value'] = "[REDACTED]"
            
            export_data.append(result_dict)
        
        return json.dumps(export_data, indent=2, default=str)
    
    def _export_csv(self, include_secret_data: bool) -> str:
        """Export results as CSV."""
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            "Path", "Key", "Value", "Match Type", "Engine Path", 
            "Timestamp", "Severity", "Match Context"
        ])
        
        # Write data
        for result in self.results:
            value = result.value if include_secret_data else "[REDACTED]"
            writer.writerow([
                result.path,
                result.key,
                value,
                result.match_type,
                result.engine_path,
                result.timestamp.isoformat(),
                result.get_severity_level(),
                result.match_context
            ])
        
        return output.getvalue()
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get detailed statistics about the search results.
        
        Returns:
            Dictionary containing various statistics
        """
        if not self.results:
            return {
                "total_results": 0,
                "unique_paths": 0,
                "unique_keys": 0,
                "engines_with_results": 0,
                "severity_distribution": {},
                "type_distribution": {}
            }
        
        # Calculate statistics
        unique_paths = len(set(r.path for r in self.results))
        unique_keys = len(set(r.key for r in self.results))
        engines_with_results = len(set(r.engine_path for r in self.results))
        
        # Severity distribution
        severity_distribution = {}
        for result in self.results:
            severity = result.get_severity_level()
            severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
        
        # Type distribution
        type_distribution = {}
        for result in self.results:
            match_type = result.match_type
            type_distribution[match_type] = type_distribution.get(match_type, 0) + 1
        
        return {
            "total_results": len(self.results),
            "unique_paths": unique_paths,
            "unique_keys": unique_keys,
            "engines_with_results": engines_with_results,
            "severity_distribution": severity_distribution,
            "type_distribution": type_distribution
        }
