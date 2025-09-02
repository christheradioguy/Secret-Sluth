"""
Unit tests for the search algorithms module.
"""

import pytest
from app.search_algorithms import SearchAlgorithms


class TestSearchAlgorithms:
    """Test SearchAlgorithms class."""
    
    @pytest.fixture
    def algorithms(self):
        """Create a SearchAlgorithms instance."""
        return SearchAlgorithms()
    
    def test_matches_basic(self, algorithms):
        """Test basic string matching."""
        # Case insensitive (default)
        assert algorithms.matches("Hello World", "hello") is True
        assert algorithms.matches("Hello World", "world") is True
        assert algorithms.matches("Hello World", "xyz") is False
        
        # Case sensitive
        assert algorithms.matches("Hello World", "hello", case_sensitive=True) is False
        assert algorithms.matches("Hello World", "Hello", case_sensitive=True) is True
    
    def test_matches_edge_cases(self, algorithms):
        """Test edge cases for string matching."""
        # Empty strings
        assert algorithms.matches("", "test") is False
        assert algorithms.matches("test", "") is False
        assert algorithms.matches("", "") is False
        
        # None values
        assert algorithms.matches(None, "test") is False
        assert algorithms.matches("test", None) is False
        
        # Non-string values
        assert algorithms.matches(123, "123") is True
        assert algorithms.matches("123", 123) is True
    
    def test_exact_match(self, algorithms):
        """Test exact matching."""
        # Case insensitive (default)
        assert algorithms.exact_match("Hello", "hello") is True
        assert algorithms.exact_match("Hello World", "hello") is False
        
        # Case sensitive
        assert algorithms.exact_match("Hello", "hello", case_sensitive=True) is False
        assert algorithms.exact_match("Hello", "Hello", case_sensitive=True) is True
    
    def test_regex_match(self, algorithms):
        """Test regex matching."""
        # Basic regex patterns
        assert algorithms.regex_match("Hello World", r"Hello.*") is True
        assert algorithms.regex_match("Hello World", r"^Hello.*World$") is True
        assert algorithms.regex_match("Hello World", r"xyz") is False
        
        # Case sensitivity
        assert algorithms.regex_match("Hello World", r"hello.*", case_sensitive=True) is False
        assert algorithms.regex_match("Hello World", r"hello.*", case_sensitive=False) is True
        
        # Invalid regex
        assert algorithms.regex_match("test", r"[invalid") is False
    
    def test_wildcard_match(self, algorithms):
        """Test wildcard matching."""
        # Basic wildcards
        assert algorithms.wildcard_match("Hello World", "Hello*") is True
        assert algorithms.wildcard_match("Hello World", "*World") is True
        assert algorithms.wildcard_match("Hello World", "Hello*World") is True
        assert algorithms.wildcard_match("Hello World", "H?llo*") is True
        
        # No wildcards
        assert algorithms.wildcard_match("Hello World", "Hello World") is True
        assert algorithms.wildcard_match("Hello World", "Hello") is False
        
        # Case sensitivity
        assert algorithms.wildcard_match("Hello World", "hello*", case_sensitive=True) is False
        assert algorithms.wildcard_match("Hello World", "hello*", case_sensitive=False) is True
    
    def test_fuzzy_match(self, algorithms):
        """Test fuzzy matching."""
        # High similarity
        assert algorithms.fuzzy_match("Hello World", "Hello World", threshold=0.8) is True
        assert algorithms.fuzzy_match("Hello World", "Hello Worl", threshold=0.8) is True
        
        # Low similarity
        assert algorithms.fuzzy_match("Hello World", "Completely Different", threshold=0.8) is False
        
        # Edge cases
        assert algorithms.fuzzy_match("", "test", threshold=0.8) is False
        assert algorithms.fuzzy_match("test", "", threshold=0.8) is False
    
    def test_get_match_context(self, algorithms):
        """Test getting match context."""
        text = "This is a long text with the word test in it somewhere"
        query = "test"
        
        context = algorithms.get_match_context(text, query)
        
        # Should contain the query
        assert "test" in context.lower()
        # Should be shorter than the original text
        assert len(context) < len(text)
        # Should include ellipsis if truncated
        assert "..." in context
    
    def test_get_match_context_no_match(self, algorithms):
        """Test getting context when no match is found."""
        text = "This text does not contain the query"
        query = "nonexistent"
        
        context = algorithms.get_match_context(text, query)
        
        # Should return truncated text
        assert len(context) <= 50 or context.endswith("...")
    
    def test_highlight_matches(self, algorithms):
        """Test highlighting matches in text."""
        text = "Hello world, hello there"
        query = "hello"
        
        highlighted = algorithms.highlight_matches(text, query)
        
        # Should contain highlight tags
        assert '<mark class="search-highlight">' in highlighted
        assert '</mark>' in highlighted
        # Should contain the original text (case-insensitive search)
        assert "world" in highlighted
        assert "there" in highlighted
        # Should highlight both "Hello" and "hello"
        assert highlighted.count('<mark class="search-highlight">') == 2
    
    def test_get_match_positions(self, algorithms):
        """Test getting match positions."""
        text = "Hello world, hello there"
        query = "hello"
        
        positions = algorithms.get_match_positions(text, query)
        
        # Should find multiple matches
        assert len(positions) == 2
        # Positions should be tuples of (start, end)
        for start, end in positions:
            assert isinstance(start, int)
            assert isinstance(end, int)
            assert start < end
    
    def test_search_multiple_queries_any(self, algorithms):
        """Test searching for multiple queries with any match."""
        text = "Hello world"
        queries = ["hello", "xyz", "world"]
        
        # Should match if any query matches
        assert algorithms.search_multiple_queries(text, queries, match_all=False) is True
        
        # Should not match if no queries match
        assert algorithms.search_multiple_queries(text, ["xyz", "abc"], match_all=False) is False
    
    def test_search_multiple_queries_all(self, algorithms):
        """Test searching for multiple queries with all match requirement."""
        text = "Hello world"
        queries = ["hello", "world"]
        
        # Should match if all queries match
        assert algorithms.search_multiple_queries(text, queries, match_all=True) is True
        
        # Should not match if not all queries match
        assert algorithms.search_multiple_queries(text, ["hello", "xyz"], match_all=True) is False
    
    def test_wildcard_to_regex(self, algorithms):
        """Test wildcard to regex conversion."""
        # Basic wildcards
        assert algorithms._wildcard_to_regex("test*") == "^test.*$"
        assert algorithms._wildcard_to_regex("*test") == "^.*test$"
        assert algorithms._wildcard_to_regex("test?") == "^test.$"
        
        # Multiple wildcards
        assert algorithms._wildcard_to_regex("test*?") == "^test.*.$"
        
        # No wildcards
        assert algorithms._wildcard_to_regex("test") == "^test$"
        
        # Special characters
        assert algorithms._wildcard_to_regex("test[123]") == r"^test\[123\]$"
    
    def test_levenshtein_distance(self, algorithms):
        """Test Levenshtein distance calculation."""
        # Same strings
        assert algorithms._levenshtein_distance("test", "test") == 0
        
        # One character difference
        assert algorithms._levenshtein_distance("test", "tost") == 1
        
        # Multiple differences
        assert algorithms._levenshtein_distance("kitten", "sitting") == 3
        
        # Empty strings
        assert algorithms._levenshtein_distance("", "test") == 4
        assert algorithms._levenshtein_distance("test", "") == 4
    
    def test_calculate_similarity(self, algorithms):
        """Test similarity calculation."""
        # Identical strings
        assert algorithms._calculate_similarity("test", "test") == 1.0
        
        # Similar strings
        similarity = algorithms._calculate_similarity("test", "tost")
        assert 0.0 < similarity < 1.0
        
        # Very different strings
        similarity = algorithms._calculate_similarity("test", "completely different")
        assert similarity < 0.5
        
        # Empty strings
        assert algorithms._calculate_similarity("", "") == 1.0
        assert algorithms._calculate_similarity("test", "") == 0.0
