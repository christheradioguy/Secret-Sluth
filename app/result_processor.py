"""
Result Processor for Secret Sluth.

This module handles advanced result processing including formatting, organization,
metadata extraction, and result grouping as specified in Stage 5.1.
"""

import json
import re
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import hashlib
import base64
from urllib.parse import urlparse, parse_qs

from app.result_collector import SearchResult
from app.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class ProcessedResult:
    """Enhanced result with additional processing and metadata."""
    original_result: SearchResult
    formatted_path: str
    formatted_key: str
    formatted_value: str
    extracted_metadata: Dict[str, Any] = field(default_factory=dict)
    security_indicators: List[str] = field(default_factory=list)
    data_type: str = "unknown"
    confidence_score: float = 1.0
    risk_level: str = "low"
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'original_result': self.original_result.to_dict(),
            'formatted_path': self.formatted_path,
            'formatted_key': self.formatted_key,
            'formatted_value': self.formatted_value,
            'extracted_metadata': self.extracted_metadata,
            'security_indicators': self.security_indicators,
            'data_type': self.data_type,
            'confidence_score': self.confidence_score,
            'risk_level': self.risk_level,
            'tags': self.tags
        }


@dataclass
class ResultGroup:
    """Represents a group of related results."""
    group_id: str
    group_type: str  # "engine", "path", "key_pattern", "data_type"
    group_name: str
    results: List[ProcessedResult]
    summary: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'group_id': self.group_id,
            'group_type': self.group_type,
            'group_name': self.group_name,
            'results_count': len(self.results),
            'summary': self.summary,
            'metadata': self.metadata
        }


class ResultProcessor:
    """
    Advanced result processor for formatting, organization, and metadata extraction.
    """
    
    def __init__(self):
        """Initialize the result processor."""
        self.logger = get_logger(__name__)
        
        # Data type detection patterns
        self.data_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'url': r'https?://[^\s<>"]+|www\.[^\s<>"]+',
            'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'api_key': r'(api[_-]?key|token|secret|password|credential)',
            'jwt_token': r'^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
            'base64': r'^[A-Za-z0-9+/]*={0,2}$',
            'json': r'^\{.*\}$|^\[.*\]$',
            'uuid': r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            'ssh_key': r'^ssh-rsa|^ssh-dss|^ssh-ed25519|^ecdsa-',
            'private_key': r'^-----BEGIN.*PRIVATE KEY-----',
            'certificate': r'^-----BEGIN.*CERTIFICATE-----'
        }
        
        # Security indicators
        self.security_indicators = {
            'high_risk': ['password', 'secret', 'token', 'key', 'credential', 'auth'],
            'medium_risk': ['config', 'setting', 'param', 'env', 'var'],
            'low_risk': ['description', 'comment', 'note', 'info']
        }
    
    def process_results(self, results: List[SearchResult]) -> List[ProcessedResult]:
        """
        Process and enhance search results with formatting and metadata.
        
        Args:
            results: List of search results to process
            
        Returns:
            List of processed results
        """
        processed_results = []
        
        for result in results:
            try:
                processed_result = self._process_single_result(result)
                processed_results.append(processed_result)
            except Exception as e:
                self.logger.error(f"Failed to process result {result.path}: {e}")
                # Create a basic processed result as fallback
                processed_result = ProcessedResult(
                    original_result=result,
                    formatted_path=result.path,
                    formatted_key=result.key,
                    formatted_value=result.value,
                    data_type="unknown",
                    confidence_score=0.5,
                    risk_level="unknown"
                )
                processed_results.append(processed_result)
        
        return processed_results
    
    def _process_single_result(self, result: SearchResult) -> ProcessedResult:
        """
        Process a single search result.
        
        Args:
            result: Search result to process
            
        Returns:
            Processed result
        """
        # Format path, key, and value
        formatted_path = self._format_path(result.path)
        formatted_key = self._format_key(result.key)
        formatted_value = self._format_value(result.value)
        
        # Extract metadata
        extracted_metadata = self._extract_metadata(result)
        
        # Detect data type
        data_type = self._detect_data_type(result.value)
        
        # Identify security indicators
        security_indicators = self._identify_security_indicators(result)
        
        # Calculate confidence score
        confidence_score = self._calculate_confidence(result, data_type, security_indicators)
        
        # Determine risk level
        risk_level = self._determine_risk_level(result, security_indicators, data_type)
        
        # Generate tags
        tags = self._generate_tags(result, data_type, security_indicators)
        
        return ProcessedResult(
            original_result=result,
            formatted_path=formatted_path,
            formatted_key=formatted_key,
            formatted_value=formatted_value,
            extracted_metadata=extracted_metadata,
            security_indicators=security_indicators,
            data_type=data_type,
            confidence_score=confidence_score,
            risk_level=risk_level,
            tags=tags
        )
    
    def _format_path(self, path: str) -> str:
        """Format path for better readability."""
        if not path:
            return "/"
        
        # Remove redundant slashes
        formatted = re.sub(r'/+', '/', path)
        
        # Add leading slash if missing
        if not formatted.startswith('/'):
            formatted = '/' + formatted
        
        # Remove trailing slash unless it's root
        if formatted != '/' and formatted.endswith('/'):
            formatted = formatted[:-1]
        
        return formatted
    
    def _format_key(self, key: str) -> str:
        """Format key for better readability."""
        if not key:
            return ""
        
        # Convert snake_case or kebab-case to Title Case
        formatted = re.sub(r'[_-]', ' ', key)
        formatted = formatted.title()
        
        return formatted
    
    def _format_value(self, value: str) -> str:
        """Format value for better readability."""
        if not value:
            return ""
        
        # Truncate very long values
        if len(value) > 100:
            return value[:97] + "..."
        
        return value
    
    def _extract_metadata(self, result: SearchResult) -> Dict[str, Any]:
        """Extract metadata from the search result."""
        metadata = {}
        
        try:
            # Extract path components
            path_parts = result.path.strip('/').split('/')
            if len(path_parts) >= 2:
                metadata['engine_type'] = result.engine_type
                metadata['path_depth'] = len(path_parts)
                metadata['path_components'] = path_parts
            
            # Extract key patterns
            if result.key:
                metadata['key_length'] = len(result.key)
                metadata['key_contains_special'] = bool(re.search(r'[^a-zA-Z0-9\s]', result.key))
                metadata['key_case'] = 'mixed' if re.search(r'[a-z]', result.key) and re.search(r'[A-Z]', result.key) else 'single'
            
            # Extract value patterns
            if result.value:
                metadata['value_length'] = len(result.value)
                metadata['value_contains_special'] = bool(re.search(r'[^a-zA-Z0-9\s]', result.value))
                metadata['value_is_numeric'] = result.value.replace('.', '').replace('-', '').isdigit()
                metadata['value_is_hex'] = bool(re.match(r'^[0-9a-fA-F]+$', result.value))
                metadata['value_is_base64'] = bool(re.match(r'^[A-Za-z0-9+/]*={0,2}$', result.value))
            
            # Extract timestamp information
            if result.timestamp:
                metadata['timestamp'] = result.timestamp.isoformat()
                metadata['age_hours'] = (datetime.now() - result.timestamp).total_seconds() / 3600
            
        except Exception as e:
            self.logger.warning(f"Failed to extract metadata from result {result.path}: {e}")
        
        return metadata
    
    def _detect_data_type(self, value: str) -> str:
        """Detect the data type of a value."""
        if not value:
            return "empty"
        
        # Check for specific patterns
        for data_type, pattern in self.data_patterns.items():
            if re.search(pattern, value, re.IGNORECASE):
                return data_type
        
        # Check for JSON
        try:
            json.loads(value)
            return "json"
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Check for base64
        try:
            if len(value) % 4 == 0 and re.match(r'^[A-Za-z0-9+/]*={0,2}$', value):
                base64.b64decode(value)
                return "base64"
        except Exception:
            pass
        
        # Check for numeric
        if value.replace('.', '').replace('-', '').isdigit():
            return "numeric"
        
        # Check for boolean
        if value.lower() in ['true', 'false', 'yes', 'no', '1', '0']:
            return "boolean"
        
        # Default to text
        return "text"
    
    def _identify_security_indicators(self, result: SearchResult) -> List[str]:
        """Identify security-related indicators in the result."""
        indicators = []
        
        # Check key for security indicators
        key_lower = result.key.lower()
        for risk_level, keywords in self.security_indicators.items():
            for keyword in keywords:
                if keyword in key_lower:
                    indicators.append(f"{risk_level}_{keyword}")
        
        # Check value for security indicators
        value_lower = result.value.lower()
        for risk_level, keywords in self.security_indicators.items():
            for keyword in keywords:
                if keyword in value_lower:
                    indicators.append(f"{risk_level}_{keyword}")
        
        # Check path for security indicators
        path_lower = result.path.lower()
        for risk_level, keywords in self.security_indicators.items():
            for keyword in keywords:
                if keyword in path_lower:
                    indicators.append(f"{risk_level}_{keyword}")
        
        return list(set(indicators))  # Remove duplicates
    
    def _calculate_confidence(self, result: SearchResult, data_type: str, 
                            security_indicators: List[str]) -> float:
        """Calculate confidence score for the result."""
        confidence = 1.0
        
        # Reduce confidence for unknown data types
        if data_type == "unknown":
            confidence *= 0.8
        
        # Increase confidence for specific data types
        if data_type in ['email', 'url', 'ip_address', 'jwt_token', 'uuid']:
            confidence *= 1.2
        
        # Increase confidence for security indicators
        if security_indicators:
            confidence *= 1.1
        
        # Reduce confidence for very short values
        if len(result.value) < 3:
            confidence *= 0.7
        
        # Cap confidence at 1.0
        return min(confidence, 1.0)
    
    def _determine_risk_level(self, result: SearchResult, security_indicators: List[str], 
                            data_type: str) -> str:
        """Determine the risk level of the result."""
        risk_score = 0
        
        # Base risk from match type
        if result.match_type == "name":
            risk_score += 3
        elif result.match_type == "key":
            risk_score += 2
        elif result.match_type == "value":
            risk_score += 1
        
        # Risk from security indicators
        for indicator in security_indicators:
            if indicator.startswith("high_risk"):
                risk_score += 3
            elif indicator.startswith("medium_risk"):
                risk_score += 2
            elif indicator.startswith("low_risk"):
                risk_score += 1
        
        # Risk from data type
        if data_type in ['api_key', 'jwt_token', 'private_key', 'certificate']:
            risk_score += 3
        elif data_type in ['email', 'credit_card', 'ssh_key']:
            risk_score += 2
        elif data_type in ['url', 'ip_address']:
            risk_score += 1
        
        # Determine risk level
        if risk_score >= 6:
            return "high"
        elif risk_score >= 3:
            return "medium"
        else:
            return "low"
    
    def _generate_tags(self, result: SearchResult, data_type: str, 
                      security_indicators: List[str]) -> List[str]:
        """Generate tags for the result."""
        tags = []
        
        # Add data type tag
        tags.append(f"type:{data_type}")
        
        # Add match type tag
        tags.append(f"match:{result.match_type}")
        
        # Add security indicator tags
        for indicator in security_indicators:
            tags.append(f"security:{indicator}")
        
        # Add engine tag
        tags.append(f"engine:{result.engine_path}")
        
        # Add risk level tag
        risk_level = self._determine_risk_level(result, security_indicators, data_type)
        tags.append(f"risk:{risk_level}")
        
        return tags
    
    def group_results(self, processed_results: List[ProcessedResult], 
                     group_by: str = "engine") -> List[ResultGroup]:
        """
        Group processed results by specified criteria.
        
        Args:
            processed_results: List of processed results to group
            group_by: Grouping criteria ("engine", "path", "key_pattern", "data_type", "risk_level")
            
        Returns:
            List of result groups
        """
        groups = defaultdict(list)
        
        for result in processed_results:
            group_key = self._get_group_key(result, group_by)
            groups[group_key].append(result)
        
        result_groups = []
        for group_key, results in groups.items():
            group = self._create_result_group(group_key, group_by, results)
            result_groups.append(group)
        
        # Sort groups by result count (descending)
        result_groups.sort(key=lambda g: len(g.results), reverse=True)
        
        return result_groups
    
    def _get_group_key(self, result: ProcessedResult, group_by: str) -> str:
        """Get the grouping key for a result."""
        if group_by == "engine":
            return result.original_result.engine_path
        elif group_by == "path":
            # Group by top-level path component
            path_parts = result.formatted_path.strip('/').split('/')
            return path_parts[0] if path_parts else "root"
        elif group_by == "key_pattern":
            # Group by key pattern (first word)
            key_parts = result.formatted_key.split()
            return key_parts[0] if key_parts else "unknown"
        elif group_by == "data_type":
            return result.data_type
        elif group_by == "risk_level":
            return result.risk_level
        else:
            return "unknown"
    
    def _create_result_group(self, group_key: str, group_type: str, 
                           results: List[ProcessedResult]) -> ResultGroup:
        """Create a result group from grouped results."""
        # Calculate summary statistics
        summary = {
            'total_results': len(results),
            'unique_paths': len(set(r.original_result.path for r in results)),
            'unique_keys': len(set(r.original_result.key for r in results)),
            'data_types': list(set(r.data_type for r in results)),
            'risk_levels': list(set(r.risk_level for r in results)),
            'average_confidence': sum(r.confidence_score for r in results) / len(results),
            'high_risk_count': len([r for r in results if r.risk_level == "high"]),
            'medium_risk_count': len([r for r in results if r.risk_level == "medium"]),
            'low_risk_count': len([r for r in results if r.risk_level == "low"])
        }
        
        # Generate group metadata
        metadata = {
            'group_key': group_key,
            'group_type': group_type,
            'created_at': datetime.now().isoformat(),
            'most_common_data_type': max(set(r.data_type for r in results), 
                                       key=lambda x: len([r for r in results if r.data_type == x])),
            'most_common_risk_level': max(set(r.risk_level for r in results),
                                        key=lambda x: len([r for r in results if r.risk_level == x]))
        }
        
        return ResultGroup(
            group_id=f"{group_type}_{group_key}_{hashlib.md5(group_key.encode()).hexdigest()[:8]}",
            group_type=group_type,
            group_name=group_key,
            results=results,
            summary=summary,
            metadata=metadata
        )
    
    def deduplicate_results(self, processed_results: List[ProcessedResult]) -> List[ProcessedResult]:
        """
        Remove duplicate results based on content similarity.
        
        Args:
            processed_results: List of processed results to deduplicate
            
        Returns:
            List of deduplicated results
        """
        seen_hashes = set()
        deduplicated = []
        
        for result in processed_results:
            # Create a hash based on key content and path
            content_hash = hashlib.md5(
                f"{result.original_result.key}:{result.original_result.path}".encode()
            ).hexdigest()
            
            if content_hash not in seen_hashes:
                seen_hashes.add(content_hash)
                deduplicated.append(result)
        
        return deduplicated
    
    def get_processing_summary(self, original_count: int, processed_count: int, 
                             groups: List[ResultGroup]) -> Dict[str, Any]:
        """
        Generate a summary of the processing operation.
        
        Args:
            original_count: Number of original results
            processed_count: Number of processed results
            groups: List of result groups
            
        Returns:
            Processing summary
        """
        return {
            'original_count': original_count,
            'processed_count': processed_count,
            'duplicates_removed': original_count - processed_count,
            'groups_created': len(groups),
            'group_types': list(set(g.group_type for g in groups)),
            'processing_timestamp': datetime.now().isoformat(),
            'group_summaries': [g.to_dict() for g in groups]
        }
