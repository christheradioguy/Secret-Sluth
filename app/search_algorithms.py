"""
Search Algorithms for Secret Sluth.

This module provides various string matching algorithms for searching
within secret keys, values, and metadata.
"""

import re
from typing import List, Optional, Tuple
from app.logging_config import get_logger

logger = get_logger(__name__)


class SearchAlgorithms:
    """
    Provides various search algorithms for string matching.
    """
    
    def __init__(self):
        """Initialize the search algorithms."""
        self.logger = get_logger(__name__)
    
    def matches(self, text: str, query: str, case_sensitive: bool = False) -> bool:
        """
        Check if text matches the search query.
        Automatically detects and handles wildcards, regex, and exact matches.
        
        Args:
            text: Text to search in
            query: Search query
            case_sensitive: Whether to perform case-sensitive search
            
        Returns:
            True if text matches query, False otherwise
        """
        if not text or not query:
            return False
        
        # Convert to strings if needed
        text = str(text)
        query = str(query)
        
        # Handle case sensitivity
        if not case_sensitive:
            text = text.lower()
            query = query.lower()
        
        # Check for wildcard patterns (* or ?)
        if '*' in query or '?' in query:
            return self.wildcard_match(text, query, case_sensitive)
        
        # Check for regex patterns (starts with / and ends with /)
        if query.startswith('/') and query.endswith('/') and len(query) > 2:
            pattern = query[1:-1]  # Remove the / delimiters
            return self.regex_match(text, pattern, case_sensitive)
        
        # Check for exact match (wrapped in quotes)
        if query.startswith('"') and query.endswith('"') and len(query) > 2:
            exact_query = query[1:-1]  # Remove the quotes
            return self.exact_match(text, exact_query, case_sensitive)
        
        # Simple substring search (default)
        return query in text
    
    def exact_match(self, text: str, query: str, case_sensitive: bool = False) -> bool:
        """
        Check for exact match between text and query.
        
        Args:
            text: Text to match
            query: Query to match against
            case_sensitive: Whether to perform case-sensitive matching
            
        Returns:
            True if text exactly matches query, False otherwise
        """
        if not text or not query:
            return False
        
        text = str(text)
        query = str(query)
        
        if not case_sensitive:
            text = text.lower()
            query = query.lower()
        
        return text == query
    
    def regex_match(self, text: str, pattern: str, case_sensitive: bool = False) -> bool:
        """
        Check if text matches a regex pattern.
        
        Args:
            text: Text to search in
            pattern: Regex pattern to match
            case_sensitive: Whether to perform case-sensitive matching
            
        Returns:
            True if text matches pattern, False otherwise
        """
        if not text or not pattern:
            return False
        
        text = str(text)
        
        try:
            flags = 0 if case_sensitive else re.IGNORECASE
            # Use re.match to match from the beginning, or re.search for substring matching
            return bool(re.match(pattern, text, flags)) or bool(re.search(pattern, text, flags))
        except re.error as e:
            self.logger.warning(f"Invalid regex pattern '{pattern}': {e}")
            return False
    
    def wildcard_match(self, text: str, pattern: str, case_sensitive: bool = False) -> bool:
        """
        Check if text matches a wildcard pattern (* and ?).
        
        Args:
            text: Text to search in
            pattern: Wildcard pattern (* for any sequence, ? for single character)
            case_sensitive: Whether to perform case-sensitive matching
            
        Returns:
            True if text matches pattern, False otherwise
        """
        if not text or not pattern:
            return False
        
        text = str(text)
        pattern = str(pattern)
        
        if not case_sensitive:
            text = text.lower()
            pattern = pattern.lower()
        
        # Convert wildcard pattern to regex
        regex_pattern = self._wildcard_to_regex(pattern)
        
        try:
            return bool(re.match(regex_pattern, text))
        except re.error as e:
            self.logger.warning(f"Invalid wildcard pattern '{pattern}': {e}")
            return False
    
    def _wildcard_to_regex(self, pattern: str) -> str:
        """
        Convert wildcard pattern to regex pattern.
        
        Args:
            pattern: Wildcard pattern
            
        Returns:
            Regex pattern
        """
        # Escape regex special characters except * and ?
        pattern = re.escape(pattern)
        
        # Replace escaped * and ? with regex equivalents
        pattern = pattern.replace(r'\*', '.*')
        pattern = pattern.replace(r'\?', '.')
        
        # Anchor to start and end
        return f"^{pattern}$"
    
    def fuzzy_match(self, text: str, query: str, threshold: float = 0.8) -> bool:
        """
        Perform fuzzy string matching using Levenshtein distance.
        
        Args:
            text: Text to search in
            query: Query to match
            threshold: Similarity threshold (0.0 to 1.0)
            
        Returns:
            True if similarity is above threshold, False otherwise
        """
        if not text or not query:
            return False
        
        text = str(text).lower()
        query = str(query).lower()
        
        # Calculate similarity
        similarity = self._calculate_similarity(text, query)
        return similarity >= threshold
    
    def _calculate_similarity(self, text: str, query: str) -> float:
        """
        Calculate similarity between two strings using Levenshtein distance.
        
        Args:
            text: First string
            query: Second string
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        if not text and not query:
            return 1.0
        
        if not text or not query:
            return 0.0
        
        # Use simple substring similarity for performance
        if query in text:
            return 1.0
        
        # Calculate Levenshtein distance
        distance = self._levenshtein_distance(text, query)
        max_len = max(len(text), len(query))
        
        if max_len == 0:
            return 1.0
        
        return 1.0 - (distance / max_len)
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """
        Calculate Levenshtein distance between two strings.
        
        Args:
            s1: First string
            s2: Second string
            
        Returns:
            Levenshtein distance
        """
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def get_match_context(self, text: str, query: str, case_sensitive: bool = False, 
                         context_length: int = 50) -> str:
        """
        Get context around a match in the text.
        
        Args:
            text: Text containing the match
            query: Query that was matched
            case_sensitive: Whether the search was case-sensitive
            context_length: Number of characters to include around the match
            
        Returns:
            Context string with match highlighted
        """
        if not text or not query:
            return ""
        
        text = str(text)
        query = str(query)
        
        # Handle case sensitivity
        search_text = text
        search_query = query
        if not case_sensitive:
            search_text = text.lower()
            search_query = query.lower()
        
        # Find the match position
        match_pos = search_text.find(search_query)
        if match_pos == -1:
            return text[:context_length] + "..." if len(text) > context_length else text
        
        # Calculate context boundaries
        start = max(0, match_pos - context_length // 2)
        end = min(len(text), match_pos + len(query) + context_length // 2)
        
        # Extract context
        context = text[start:end]
        
        # Add ellipsis if needed
        if start > 0:
            context = "..." + context
        if end < len(text):
            context = context + "..."
        
        return context
    
    def highlight_matches(self, text: str, query: str, case_sensitive: bool = False) -> str:
        """
        Highlight all matches of query in text.
        
        Args:
            text: Text to highlight matches in
            query: Query to highlight
            case_sensitive: Whether the search was case-sensitive
            
        Returns:
            Text with matches highlighted using HTML tags
        """
        if not text or not query:
            return text
        
        text = str(text)
        query = str(query)
        
        # Handle case sensitivity
        search_text = text
        search_query = query
        if not case_sensitive:
            search_text = text.lower()
            search_query = query.lower()
        
        # Find all matches
        matches = []
        start = 0
        while True:
            pos = search_text.find(search_query, start)
            if pos == -1:
                break
            matches.append((pos, pos + len(query)))
            start = pos + 1
        
        # Highlight matches
        highlighted = text
        offset = 0
        for start, end in matches:
            # Adjust positions for HTML tags
            start += offset
            end += offset
            
            # Insert highlight tags
            highlighted = (
                highlighted[:start] + 
                f'<mark class="search-highlight">{highlighted[start:end]}</mark>' + 
                highlighted[end:]
            )
            
            # Update offset for next iteration
            offset += len('<mark class="search-highlight"></mark>')
        
        return highlighted
    
    def get_match_positions(self, text: str, query: str, case_sensitive: bool = False) -> List[Tuple[int, int]]:
        """
        Get all positions where query matches in text.
        
        Args:
            text: Text to search in
            query: Query to find
            case_sensitive: Whether to perform case-sensitive search
            
        Returns:
            List of (start, end) position tuples
        """
        if not text or not query:
            return []
        
        text = str(text)
        query = str(query)
        
        # Handle case sensitivity
        search_text = text
        search_query = query
        if not case_sensitive:
            search_text = text.lower()
            search_query = query.lower()
        
        positions = []
        start = 0
        while True:
            pos = search_text.find(search_query, start)
            if pos == -1:
                break
            positions.append((pos, pos + len(query)))
            start = pos + 1
        
        return positions
    
    def search_multiple_queries(self, text: str, queries: List[str], 
                              case_sensitive: bool = False, 
                              match_all: bool = False) -> bool:
        """
        Search for multiple queries in text.
        
        Args:
            text: Text to search in
            queries: List of queries to search for
            case_sensitive: Whether to perform case-sensitive search
            match_all: If True, all queries must match; if False, any query can match
            
        Returns:
            True if queries match according to match_all logic, False otherwise
        """
        if not text or not queries:
            return False
        
        matches = [self.matches(text, query, case_sensitive) for query in queries]
        
        if match_all:
            return all(matches)
        else:
            return any(matches)
