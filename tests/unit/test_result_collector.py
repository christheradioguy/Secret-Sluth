"""
Unit tests for the result collector module.
"""

import pytest
import json
from datetime import datetime
from app.result_collector import ResultCollector, SearchResult, SearchSummary


class TestSearchResult:
    """Test SearchResult dataclass."""
    
    def test_search_result_creation(self):
        """Test creating a SearchResult."""
        timestamp = datetime.now()
        result = SearchResult(
            path="/secret/test",
            key="password",
            value="secret123",
            match_type="value",
            match_context="password: secret123",
            engine_path="/secret",
            timestamp=timestamp
        )
        
        assert result.path == "/secret/test"
        assert result.key == "password"
        assert result.value == "secret123"
        assert result.match_type == "value"
        assert result.match_context == "password: secret123"
        assert result.engine_path == "/secret"
        assert result.timestamp == timestamp
        assert result.confidence == 1.0
        assert result.metadata == {}
    
    def test_search_result_to_dict(self):
        """Test converting SearchResult to dictionary."""
        timestamp = datetime.now()
        result = SearchResult(
            path="/secret/test",
            key="password",
            value="secret123",
            match_type="value",
            match_context="password: secret123",
            engine_path="/secret",
            timestamp=timestamp
        )
        
        result_dict = result.to_dict()
        
        assert result_dict['path'] == "/secret/test"
        assert result_dict['key'] == "password"
        assert result_dict['value'] == "secret123"
        assert result_dict['match_type'] == "value"
        assert result_dict['engine_path'] == "/secret"
        assert result_dict['timestamp'] == timestamp.isoformat()
    
    def test_search_result_unique_id(self):
        """Test generating unique ID for SearchResult."""
        result1 = SearchResult(
            path="/secret/test",
            key="password",
            value="secret123",
            match_type="value",
            match_context="context",
            engine_path="/secret",
            timestamp=datetime.now()
        )
        
        result2 = SearchResult(
            path="/secret/test",
            key="password",
            value="secret123",
            match_type="value",
            match_context="context",
            engine_path="/secret",
            timestamp=datetime.now()
        )
        
        # Same content should generate same ID
        assert result1.get_unique_id() == result2.get_unique_id()
        
        # Different content should generate different ID
        result3 = SearchResult(
            path="/secret/test2",
            key="password",
            value="secret123",
            match_type="value",
            match_context="context",
            engine_path="/secret",
            timestamp=datetime.now()
        )
        
        assert result1.get_unique_id() != result3.get_unique_id()
    
    def test_search_result_display_path(self):
        """Test getting display path."""
        result = SearchResult(
            path="/secret/test/path",
            key="password",
            value="secret123",
            match_type="value",
            match_context="context",
            engine_path="/secret",
            timestamp=datetime.now()
        )
        
        assert result.get_display_path() == "test/path"
    
    def test_search_result_severity_levels(self):
        """Test severity level determination."""
        # Key match should be high severity
        key_result = SearchResult(
            path="/secret/test",
            key="password",
            value="secret123",
            match_type="key",
            match_context="context",
            engine_path="/secret",
            timestamp=datetime.now()
        )
        assert key_result.get_severity_level() == "high"
        
        # Value match should be medium severity
        value_result = SearchResult(
            path="/secret/test",
            key="password",
            value="secret123",
            match_type="value",
            match_context="context",
            engine_path="/secret",
            timestamp=datetime.now()
        )
        assert value_result.get_severity_level() == "medium"
        
        # Metadata match should be low severity
        metadata_result = SearchResult(
            path="/secret/test",
            key="password",
            value="secret123",
            match_type="metadata",
            match_context="context",
            engine_path="/secret",
            timestamp=datetime.now()
        )
        assert metadata_result.get_severity_level() == "low"


class TestSearchSummary:
    """Test SearchSummary dataclass."""
    
    def test_search_summary_creation(self):
        """Test creating a SearchSummary."""
        start_time = datetime.now()
        end_time = datetime.now()
        
        summary = SearchSummary(
            total_results=10,
            results_by_engine={"/secret": 5, "/kv": 5},
            results_by_type={"key": 3, "value": 7},
            search_duration=5.5,
            engines_searched=2,
            total_paths_searched=100,
            errors_encountered=1,
            warnings_encountered=2,
            start_time=start_time,
            end_time=end_time
        )
        
        assert summary.total_results == 10
        assert summary.results_by_engine == {"/secret": 5, "/kv": 5}
        assert summary.results_by_type == {"key": 3, "value": 7}
        assert summary.search_duration == 5.5
        assert summary.engines_searched == 2
        assert summary.total_paths_searched == 100
        assert summary.errors_encountered == 1
        assert summary.warnings_encountered == 2
        assert summary.start_time == start_time
        assert summary.end_time == end_time
    
    def test_search_summary_to_dict(self):
        """Test converting SearchSummary to dictionary."""
        start_time = datetime.now()
        end_time = datetime.now()
        
        summary = SearchSummary(
            total_results=10,
            results_by_engine={"/secret": 5},
            results_by_type={"key": 3},
            search_duration=5.5,
            engines_searched=1,
            total_paths_searched=50,
            errors_encountered=0,
            warnings_encountered=0,
            start_time=start_time,
            end_time=end_time
        )
        
        summary_dict = summary.to_dict()
        
        assert summary_dict['total_results'] == 10
        assert summary_dict['search_duration'] == 5.5
        assert summary_dict['start_time'] == start_time.isoformat()
        assert summary_dict['end_time'] == end_time.isoformat()


class TestResultCollector:
    """Test ResultCollector class."""
    
    @pytest.fixture
    def collector(self):
        """Create a ResultCollector instance."""
        return ResultCollector()
    
    @pytest.fixture
    def sample_results(self):
        """Create sample search results."""
        timestamp = datetime.now()
        return [
            SearchResult(
                path="/secret/test1",
                key="password",
                value="secret123",
                match_type="value",
                match_context="context1",
                engine_path="/secret",
                timestamp=timestamp
            ),
            SearchResult(
                path="/secret/test2",
                key="api_key",
                value="key456",
                match_type="key",
                match_context="context2",
                engine_path="/secret",
                timestamp=timestamp
            ),
            SearchResult(
                path="/kv/test3",
                key="token",
                value="token789",
                match_type="value",
                match_context="context3",
                engine_path="/kv",
                timestamp=timestamp
            )
        ]
    
    def test_result_collector_initialization(self, collector):
        """Test ResultCollector initialization."""
        assert collector.results == []
        assert collector.duplicate_hashes == set()
        assert collector.start_time is None
        assert collector.end_time is None
    
    def test_reset(self, collector, sample_results):
        """Test resetting the collector."""
        # Add some results
        for result in sample_results:
            collector.add_result(result)
        
        assert len(collector.results) == 3
        
        # Reset
        collector.reset()
        
        assert len(collector.results) == 0
        assert len(collector.duplicate_hashes) == 0
        assert collector.start_time is None
        assert collector.end_time is None
    
    def test_add_result(self, collector):
        """Test adding a single result."""
        result = SearchResult(
            path="/secret/test",
            key="password",
            value="secret123",
            match_type="value",
            match_context="context",
            engine_path="/secret",
            timestamp=datetime.now()
        )
        
        # Add result
        success = collector.add_result(result)
        
        assert success is True
        assert len(collector.results) == 1
        assert result in collector.results
    
    def test_add_duplicate_result(self, collector):
        """Test adding duplicate results."""
        result = SearchResult(
            path="/secret/test",
            key="password",
            value="secret123",
            match_type="value",
            match_context="context",
            engine_path="/secret",
            timestamp=datetime.now()
        )
        
        # Add result twice
        collector.add_result(result)
        success = collector.add_result(result)
        
        assert success is False
        assert len(collector.results) == 1
    
    def test_add_results(self, collector, sample_results):
        """Test adding multiple results."""
        added_count = collector.add_results(sample_results)
        
        assert added_count == 3
        assert len(collector.results) == 3
    
    def test_get_results_with_pagination(self, collector, sample_results):
        """Test getting results with pagination."""
        # Add results
        collector.add_results(sample_results)
        
        # Get first page
        results = collector.get_results(limit=2, offset=0)
        assert len(results) == 2
        
        # Get second page
        results = collector.get_results(limit=2, offset=2)
        assert len(results) == 1
    
    def test_get_results_with_sorting(self, collector, sample_results):
        """Test getting results with sorting."""
        # Add results
        collector.add_results(sample_results)
        
        # Sort by path
        results = collector.get_results(sort_by="path", sort_order="asc")
        assert results[0].path <= results[1].path <= results[2].path
        
        # Sort by path descending
        results = collector.get_results(sort_by="path", sort_order="desc")
        assert results[0].path >= results[1].path >= results[2].path
    
    def test_get_results_by_engine(self, collector, sample_results):
        """Test grouping results by engine."""
        collector.add_results(sample_results)
        
        grouped = collector.get_results_by_engine()
        
        assert "/secret" in grouped
        assert "/kv" in grouped
        assert len(grouped["/secret"]) == 2
        assert len(grouped["/kv"]) == 1
    
    def test_get_results_by_type(self, collector, sample_results):
        """Test grouping results by type."""
        collector.add_results(sample_results)
        
        grouped = collector.get_results_by_type()
        
        assert "value" in grouped
        assert "key" in grouped
        assert len(grouped["value"]) == 2
        assert len(grouped["key"]) == 1
    
    def test_get_results_by_severity(self, collector, sample_results):
        """Test grouping results by severity."""
        collector.add_results(sample_results)
        
        grouped = collector.get_results_by_severity()
        
        assert "high" in grouped
        assert "medium" in grouped
        assert len(grouped["high"]) == 1  # key match
        assert len(grouped["medium"]) == 2  # value matches
    
    def test_filter_results(self, collector, sample_results):
        """Test filtering results."""
        collector.add_results(sample_results)
        
        # Filter by engine
        filtered = collector.filter_results({"engine_path": "/secret"})
        assert len(filtered) == 2
        
        # Filter by match type
        filtered = collector.filter_results({"match_type": "key"})
        assert len(filtered) == 1
        
        # Filter by severity
        filtered = collector.filter_results({"severity": "high"})
        assert len(filtered) == 1
        
        # Filter by path contains
        filtered = collector.filter_results({"path_contains": "test1"})
        assert len(filtered) == 1
    
    def test_get_summary(self, collector, sample_results):
        """Test generating search summary."""
        collector.add_results(sample_results)
        
        summary = collector.get_summary(
            search_duration=5.5,
            engines_searched=2,
            total_paths_searched=100,
            errors=1,
            warnings=2
        )
        
        assert summary.total_results == 3
        assert summary.search_duration == 5.5
        assert summary.engines_searched == 2
        assert summary.total_paths_searched == 100
        assert summary.errors_encountered == 1
        assert summary.warnings_encountered == 2
    
    def test_export_results_json(self, collector, sample_results):
        """Test exporting results as JSON."""
        collector.add_results(sample_results)
        
        json_data = collector.export_results("json", include_secret_data=False)
        
        # Parse JSON to verify structure
        data = json.loads(json_data)
        assert len(data) == 3
        assert data[0]["path"] == "/secret/test1"
        assert data[0]["value"] == "[REDACTED]"  # Should be redacted
    
    def test_export_results_csv(self, collector, sample_results):
        """Test exporting results as CSV."""
        collector.add_results(sample_results)
        
        csv_data = collector.export_results("csv", include_secret_data=False)
        
        # Verify CSV structure
        lines = csv_data.strip().split('\n')
        assert len(lines) == 4  # Header + 3 data rows
        assert "Path,Key,Value,Match Type,Engine Path,Timestamp,Severity,Match Context" in lines[0]
    
    def test_get_statistics(self, collector, sample_results):
        """Test getting statistics."""
        collector.add_results(sample_results)
        
        stats = collector.get_statistics()
        
        assert stats["total_results"] == 3
        assert stats["unique_paths"] == 3
        assert stats["unique_keys"] == 3
        assert stats["engines_with_results"] == 2
        assert "severity_distribution" in stats
        assert "type_distribution" in stats
        assert stats["average_confidence"] == 1.0
    
    def test_get_statistics_empty(self, collector):
        """Test getting statistics for empty collector."""
        stats = collector.get_statistics()
        
        assert stats["total_results"] == 0
        assert stats["unique_paths"] == 0
        assert stats["unique_keys"] == 0
        assert stats["engines_with_results"] == 0
        assert stats["severity_distribution"] == {}
        assert stats["type_distribution"] == {}
