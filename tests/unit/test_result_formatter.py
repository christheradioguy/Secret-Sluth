"""
Unit tests for result formatter module.

Tests the result formatting functionality for display purposes.
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch

from app.result_formatter import ResultFormatter, FormattedResult, FormattedGroup
from app.result_processor import ProcessedResult
from app.result_collector import SearchResult


class TestFormattedResult:
    """Test FormattedResult dataclass."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.formatter = ResultFormatter()
    
    def test_formatted_result_creation(self):
        """Test creating a FormattedResult."""
        original_result = SearchResult(
            path="/test/path",
            key="test_key",
            value="test_value",
            match_type="key",
            match_context="test context",
            engine_path="/test/engine",
            engine_type="kv",
            timestamp=datetime.now()
        )
        
        processed_result = ProcessedResult(
            original_result=original_result,
            formatted_path="/test/path",
            formatted_key="Test Key",
            formatted_value="test_value",
            extracted_metadata={"key_length": 8},
            security_indicators=["high_risk_password"],
            data_type="text",
            confidence_score=0.9,
            risk_level="high",
            tags=["type:text", "risk:high"]
        )
        
        formatted_result = FormattedResult(
            result_id="test_123",
            display_path="/test/path",
            display_key="Test Key",
            display_value="test_value",
            engine_path="/test",
            engine_type="test",
            match_highlights={"path": ["test"], "key": ["key"]},
            severity_badge='<span class="badge bg-danger">HIGH</span>',
            data_type_badge='<span class="badge bg-primary">TEXT</span>',
            confidence_indicator="🟢",
            security_indicators=['<span class="badge bg-danger">High Risk</span>'],
            tags=['<span class="badge bg-danger">high</span>'],
            metadata_summary="Engine: test | Depth: 2 | Key Length: 8",
            actions=[{"type": "view", "label": "View Details", "icon": "fas fa-eye"}]
        )
        
        assert formatted_result.result_id == "test_123"
        assert formatted_result.display_path == "/test/path"
        assert formatted_result.display_key == "Test Key"
        assert formatted_result.display_value == "test_value"
        assert formatted_result.match_highlights == {"path": ["test"], "key": ["key"]}
        assert "badge bg-danger" in formatted_result.severity_badge
        assert "badge bg-primary" in formatted_result.data_type_badge
        assert formatted_result.confidence_indicator == "🟢"
        assert len(formatted_result.security_indicators) == 1
        assert len(formatted_result.tags) == 1
        assert formatted_result.metadata_summary == "Engine: test | Depth: 2 | Key Length: 8"
        assert len(formatted_result.actions) == 1
    
    def test_formatted_result_to_dict(self):
        """Test FormattedResult to_dict method."""
        formatted_result = FormattedResult(
            result_id="test_123",
            display_path="/test/path",
            display_key="Test Key",
            display_value="test_value",
            engine_path="/test",
            engine_type="test",
            match_highlights={},
            severity_badge="<span>HIGH</span>",
            data_type_badge="<span>TEXT</span>",
            confidence_indicator="🟢",
            security_indicators=[],
            tags=[],
            metadata_summary="",
            actions=[]
        )
        
        result_dict = formatted_result.to_dict()
        
        assert isinstance(result_dict, dict)
        assert "result_id" in result_dict
        assert "display_path" in result_dict
        assert "display_key" in result_dict
        assert "display_value" in result_dict
        assert "match_highlights" in result_dict
        assert "severity_badge" in result_dict
        assert "data_type_badge" in result_dict
        assert "confidence_indicator" in result_dict
        assert "security_indicators" in result_dict
        assert "tags" in result_dict
        assert "metadata_summary" in result_dict
        assert "actions" in result_dict
    
    def test_generate_vault_ui_url(self):
        """Test Vault UI URL generation for different engine types."""
        vault_url = "https://vault.example.com"
        
        # Test KV engine
        kv_url = self.formatter.generate_vault_ui_url(vault_url, "kv", "/chris_personal/metadata/secret")
        assert kv_url == "https://vault.example.com/ui/vault/secrets/chris_personal/kv/metadata/secret"
        
        # Test database engine
        db_url = self.formatter.generate_vault_ui_url(vault_url, "database", "/postgres/creds/role")
        assert db_url == "https://vault.example.com/ui/vault/secrets/postgres/database/creds/role"
        
        # Test SSH engine
        ssh_url = self.formatter.generate_vault_ui_url(vault_url, "ssh", "/ssh/creds/otp")
        assert ssh_url == "https://vault.example.com/ui/vault/secrets/ssh/ssh/creds/otp"
        
        # Test PKI engine
        pki_url = self.formatter.generate_vault_ui_url(vault_url, "pki", "/pki/issue/cert")
        assert pki_url == "https://vault.example.com/ui/vault/secrets/pki/pki/issue/cert"
        
        # Test unknown engine (fallback)
        unknown_url = self.formatter.generate_vault_ui_url(vault_url, "unknown", "/custom/engine/path")
        assert unknown_url == "https://vault.example.com/ui/vault/secrets/custom/engine/path"
        
        # Test with leading slash
        kv_url_with_slash = self.formatter.generate_vault_ui_url(vault_url, "kv", "chris_personal/metadata/secret")
        assert kv_url_with_slash == "https://vault.example.com/ui/vault/secrets/chris_personal/kv/metadata/secret"


class TestFormattedGroup:
    """Test FormattedGroup dataclass."""
    
    def test_formatted_group_creation(self):
        """Test creating a FormattedGroup."""
        summary_stats = {
            "total_results": 5,
            "unique_paths": 3,
            "unique_keys": 4,
            "formatted_total": "5",
            "formatted_unique_paths": "3",
            "formatted_unique_keys": "4",
            "formatted_confidence": "0.85"
        }
        
        badge_info = {
            "risk": '<span class="badge bg-danger">High Risk</span>',
            "data_type": '<span class="badge bg-primary">TEXT</span>',
            "size": '<span class="badge bg-success">Small</span>'
        }
        
        formatted_group = FormattedGroup(
            group_id="test_group_123",
            group_name="test_engine",
            group_type="engine",
            display_name="Engine: test_engine",
            summary_stats=summary_stats,
            badge_info=badge_info,
            collapsed=False
        )
        
        assert formatted_group.group_id == "test_group_123"
        assert formatted_group.group_name == "test_engine"
        assert formatted_group.group_type == "engine"
        assert formatted_group.display_name == "Engine: test_engine"
        assert formatted_group.summary_stats == summary_stats
        assert formatted_group.badge_info == badge_info
        assert formatted_group.collapsed == False
    
    def test_formatted_group_to_dict(self):
        """Test FormattedGroup to_dict method."""
        formatted_group = FormattedGroup(
            group_id="test_group_123",
            group_name="test_engine",
            group_type="engine",
            display_name="Engine: test_engine",
            summary_stats={},
            badge_info={},
            collapsed=True
        )
        
        result_dict = formatted_group.to_dict()
        
        assert isinstance(result_dict, dict)
        assert result_dict["group_id"] == "test_group_123"
        assert result_dict["group_name"] == "test_engine"
        assert result_dict["group_type"] == "engine"
        assert result_dict["display_name"] == "Engine: test_engine"
        assert result_dict["summary_stats"] == {}
        assert result_dict["badge_info"] == {}
        assert result_dict["collapsed"] == True


class TestResultFormatter:
    """Test ResultFormatter class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.formatter = ResultFormatter()
        
        # Create test processed results
        original_result1 = SearchResult(
            path="/test/engine1/path1",
            key="password",
            value="secret123",
            match_type="key",
            match_context="password field",
            engine_path="/test/engine1",
            engine_type="kv",
            timestamp=datetime.now()
        )
        
        original_result2 = SearchResult(
            path="/test/engine2/path2",
            key="api_key",
            value="sk-1234567890abcdef",
            match_type="value",
            match_context="API key value",
            engine_path="/test/engine2",
            engine_type="database",
            timestamp=datetime.now()
        )
        
        self.processed_results = [
            ProcessedResult(
                original_result=original_result1,
                formatted_path="/test/engine1/path1",
                formatted_key="Password",
                formatted_value="secret123",
                extracted_metadata={"key_length": 8, "engine_type": "test"},
                security_indicators=["high_risk_password"],
                data_type="text",
                confidence_score=0.9,
                risk_level="high",
                tags=["type:text", "risk:high"]
            ),
            ProcessedResult(
                original_result=original_result2,
                formatted_path="/test/engine2/path2",
                formatted_key="Api Key",
                formatted_value="sk-1234567890abcdef",
                extracted_metadata={"key_length": 7, "engine_type": "test"},
                security_indicators=["high_risk_key"],
                data_type="api_key",
                confidence_score=0.95,
                risk_level="high",
                tags=["type:api_key", "risk:high"]
            )
        ]
    
    def test_format_results(self):
        """Test formatting processed results."""
        formatted_results = self.formatter.format_results(self.processed_results, "password")
        
        assert len(formatted_results) == 2
        assert all(isinstance(r, FormattedResult) for r in formatted_results)
        
        # Check that results are properly formatted
        for result in formatted_results:
            assert hasattr(result, 'result_id')
            assert hasattr(result, 'display_path')
            assert hasattr(result, 'display_key')
            assert hasattr(result, 'display_value')
            assert hasattr(result, 'match_highlights')
            assert hasattr(result, 'severity_badge')
            assert hasattr(result, 'data_type_badge')
            assert hasattr(result, 'confidence_indicator')
            assert hasattr(result, 'security_indicators')
            assert hasattr(result, 'tags')
            assert hasattr(result, 'metadata_summary')
            assert hasattr(result, 'actions')
    
    def test_format_single_result(self):
        """Test formatting a single result."""
        test_result = self.processed_results[0]
        formatted_result = self.formatter._format_single_result(test_result, "password")

        assert isinstance(formatted_result, FormattedResult)
        assert formatted_result.result_id == test_result.original_result.get_unique_id()
        # The search query "password" should be highlighted in the key, not necessarily in the path
        assert "password" in formatted_result.display_key.lower()
        assert "Password" in formatted_result.display_key
        assert "secret123" in formatted_result.display_value
        assert "high" in formatted_result.severity_badge.lower()
        assert "text" in formatted_result.data_type_badge.lower()
        assert formatted_result.confidence_indicator in ["🟢", "🟡", "🔴"]
    
    def test_format_display_path(self):
        """Test display path formatting with highlighting."""
        # Test normal path
        formatted = self.formatter._format_display_path("/test/path", "")
        assert formatted == "/test/path"
        
        # Test path with highlighting
        formatted = self.formatter._format_display_path("/test/path", "test")
        assert "<mark>test</mark>" in formatted
        
        # Test path with case-insensitive highlighting
        formatted = self.formatter._format_display_path("/TEST/path", "test")
        assert "<mark>TEST</mark>" in formatted
        
        # Test empty path
        formatted = self.formatter._format_display_path("", "")
        assert formatted == "/"
    
    def test_format_display_key(self):
        """Test display key formatting with highlighting."""
        # Test normal key
        formatted = self.formatter._format_display_key("test_key", "")
        assert formatted == "test_key"
        
        # Test key with highlighting
        formatted = self.formatter._format_display_key("test_key", "key")
        assert "<mark>key</mark>" in formatted
        
        # Test empty key
        formatted = self.formatter._format_display_key("", "")
        assert formatted == ""
    
    def test_format_display_value(self):
        """Test display value formatting with highlighting."""
        # Test normal value
        formatted = self.formatter._format_display_value("test_value", "")
        assert formatted == "test_value"
        
        # Test long value (truncation)
        long_value = "a" * 150
        formatted = self.formatter._format_display_value(long_value, "")
        assert len(formatted) == 100
        assert formatted.endswith("...")
        
        # Test value with highlighting
        formatted = self.formatter._format_display_value("test_value", "value")
        assert "<mark>value</mark>" in formatted
        
        # Test empty value
        formatted = self.formatter._format_display_value("", "")
        assert formatted == ""
    
    def test_generate_match_highlights(self):
        """Test match highlight generation."""
        test_result = self.processed_results[0]
        
        # Test with matching query
        highlights = self.formatter._generate_match_highlights(test_result, "password")
        assert "password" in highlights["key"]
        
        # Test with non-matching query
        highlights = self.formatter._generate_match_highlights(test_result, "nonexistent")
        assert all(len(highlights[key]) == 0 for key in highlights)
        
        # Test with empty query
        highlights = self.formatter._generate_match_highlights(test_result, "")
        assert all(len(highlights[key]) == 0 for key in highlights)
    
    def test_generate_severity_badge(self):
        """Test severity badge generation."""
        # Test high severity
        badge = self.formatter._generate_severity_badge("high")
        assert "badge bg-danger" in badge
        assert "HIGH" in badge
        
        # Test medium severity
        badge = self.formatter._generate_severity_badge("medium")
        assert "badge bg-warning" in badge
        assert "MEDIUM" in badge
        
        # Test low severity
        badge = self.formatter._generate_severity_badge("low")
        assert "badge bg-secondary" in badge
        assert "LOW" in badge
        
        # Test unknown severity
        badge = self.formatter._generate_severity_badge("unknown")
        assert "badge bg-light" in badge
        assert "UNKNOWN" in badge
    
    def test_generate_data_type_badge(self):
        """Test data type badge generation."""
        # Test email
        badge = self.formatter._generate_data_type_badge("email")
        assert "badge bg-info" in badge
        assert "EMAIL" in badge
        
        # Test api_key
        badge = self.formatter._generate_data_type_badge("api_key")
        assert "badge bg-danger" in badge
        assert "API_KEY" in badge
        
        # Test text
        badge = self.formatter._generate_data_type_badge("text")
        assert "badge bg-primary" in badge
        assert "TEXT" in badge
        
        # Test unknown
        badge = self.formatter._generate_data_type_badge("unknown")
        assert "badge bg-light" in badge
        assert "UNKNOWN" in badge
    
    def test_generate_confidence_indicator(self):
        """Test confidence indicator generation."""
        # Test high confidence
        indicator = self.formatter._generate_confidence_indicator(0.9)
        assert indicator == "🟢"
        
        # Test medium confidence
        indicator = self.formatter._generate_confidence_indicator(0.6)
        assert indicator == "🟡"
        
        # Test low confidence
        indicator = self.formatter._generate_confidence_indicator(0.3)
        assert indicator == "🔴"
    
    def test_format_security_indicators(self):
        """Test security indicator formatting."""
        indicators = ["high_risk_password", "medium_risk_config", "low_risk_description"]
        formatted = self.formatter._format_security_indicators(indicators)
        
        assert len(formatted) == 3
        assert any("High Risk" in indicator for indicator in formatted)
        assert any("Medium Risk" in indicator for indicator in formatted)
        assert any("Low Risk" in indicator for indicator in formatted)
    
    def test_format_tags(self):
        """Test tag formatting."""
        tags = ["type:text", "risk:high", "engine:/test/engine"]
        formatted = self.formatter._format_tags(tags)
        
        assert len(formatted) == 3
        assert any("text" in tag for tag in formatted)
        assert any("high" in tag for tag in formatted)
        assert any("engine" in tag for tag in formatted)
    
    def test_generate_metadata_summary(self):
        """Test metadata summary generation."""
        metadata = {
            "engine_type": "test",
            "path_depth": 3,
            "key_length": 8,
            "value_length": 9,
            "age_hours": 2.5
        }
        
        summary = self.formatter._generate_metadata_summary(metadata)
        
        assert "Engine: test" in summary
        assert "Depth: 3" in summary
        assert "Key Length: 8" in summary
        assert "Value Length: 9" in summary
        assert "Age: 2.5h" in summary
        
        # Test with age in days
        metadata["age_hours"] = 50
        summary = self.formatter._generate_metadata_summary(metadata)
        assert "Age: 2.1d" in summary
    
    def test_generate_actions(self):
        """Test action generation."""
        test_result = self.processed_results[0]  # high risk
        actions = self.formatter._generate_actions(test_result)
        
        assert len(actions) >= 2  # At least view and copy actions
        assert any(action["type"] == "view" for action in actions)
        assert any(action["type"] == "copy" for action in actions)
        
        # Test high risk result (should have export action)
        assert any(action["type"] == "export" for action in actions)
        
        # Test low risk result
        low_risk_result = self.processed_results[0]
        low_risk_result.risk_level = "low"
        actions = self.formatter._generate_actions(low_risk_result)
        assert not any(action["type"] == "export" for action in actions)
    
    def test_format_groups(self):
        """Test group formatting."""
        from app.result_processor import ResultGroup
        
        # Create test groups
        groups = [
            ResultGroup(
                group_id="group1",
                group_type="engine",
                group_name="/test/engine1",
                results=self.processed_results,
                summary={
                    "total_results": 2, 
                    "unique_paths": 2, 
                    "unique_keys": 2,
                    "average_confidence": 0.9,
                    "high_risk_count": 2,
                    "medium_risk_count": 0,
                    "low_risk_count": 0,
                    "data_types": ["text", "api_key"],
                    "risk_levels": ["high"]
                }
            ),
            ResultGroup(
                group_id="group2",
                group_type="risk_level",
                group_name="high",
                results=self.processed_results,
                summary={
                    "total_results": 2, 
                    "unique_paths": 2, 
                    "unique_keys": 2,
                    "average_confidence": 0.9,
                    "high_risk_count": 2,
                    "medium_risk_count": 0,
                    "low_risk_count": 0,
                    "data_types": ["text", "api_key"],
                    "risk_levels": ["high"]
                }
            )
        ]
        
        formatted_groups = self.formatter.format_groups(groups)
        
        assert len(formatted_groups) == 2
        assert all(isinstance(g, FormattedGroup) for g in formatted_groups)
        
        # Check display names
        display_names = [g.display_name for g in formatted_groups]
        assert "Engine: /test/engine1" in display_names
        assert "Risk Level: HIGH" in display_names
    
    def test_format_single_group(self):
        """Test formatting a single group."""
        from app.result_processor import ResultGroup
        
        group = ResultGroup(
            group_id="test_group",
            group_type="engine",
            group_name="test_engine",
            results=self.processed_results,
            summary={
                "total_results": 2, 
                "unique_paths": 2, 
                "unique_keys": 2,
                "average_confidence": 0.9,
                "high_risk_count": 2,
                "medium_risk_count": 0,
                "low_risk_count": 0,
                "data_types": ["text", "api_key"],
                "risk_levels": ["high"]
            }
        )
        
        formatted_group = self.formatter._format_single_group(group)
        
        assert isinstance(formatted_group, FormattedGroup)
        assert formatted_group.group_id == "test_group"
        assert formatted_group.group_name == "test_engine"
        assert formatted_group.group_type == "engine"
        assert formatted_group.display_name == "Engine: test_engine"
        assert formatted_group.collapsed == True  # Less than 5 results (we have 2)
    
    def test_generate_group_display_name(self):
        """Test group display name generation."""
        from app.result_processor import ResultGroup
        
        # Test engine group
        engine_group = ResultGroup(
            group_id="test",
            group_type="engine",
            group_name="/test/engine",
            results=[],
            summary={}
        )
        display_name = self.formatter._generate_group_display_name(engine_group)
        assert display_name == "Engine: /test/engine"
        
        # Test path group
        path_group = ResultGroup(
            group_id="test",
            group_type="path",
            group_name="test",
            results=[],
            summary={}
        )
        display_name = self.formatter._generate_group_display_name(path_group)
        assert display_name == "Path: test"
        
        # Test data type group
        type_group = ResultGroup(
            group_id="test",
            group_type="data_type",
            group_name="text",
            results=[],
            summary={}
        )
        display_name = self.formatter._generate_group_display_name(type_group)
        assert display_name == "Data Type: TEXT"
    
    def test_generate_group_summary_stats(self):
        """Test group summary statistics generation."""
        from app.result_processor import ResultGroup
        
        group = ResultGroup(
            group_id="test",
            group_type="engine",
            group_name="test_engine",
            results=self.processed_results,
            summary={
                "total_results": 2,
                "unique_paths": 2,
                "unique_keys": 2,
                "average_confidence": 0.925,
                "high_risk_count": 2,
                "medium_risk_count": 0,
                "low_risk_count": 0
            }
        )
        
        stats = self.formatter._generate_group_summary_stats(group)
        
        assert "formatted_total" in stats
        assert "formatted_unique_paths" in stats
        assert "formatted_unique_keys" in stats
        assert "formatted_confidence" in stats
        assert "risk_distribution" in stats
        assert stats["formatted_total"] == "2"
        assert stats["formatted_confidence"] == "0.93"
    
    def test_generate_group_badge_info(self):
        """Test group badge information generation."""
        from app.result_processor import ResultGroup
        
        group = ResultGroup(
            group_id="test",
            group_type="engine",
            group_name="test_engine",
            results=self.processed_results,
            summary={
                "total_results": 2,
                "risk_levels": ["high"],
                "data_types": ["text"]
            }
        )
        
        badge_info = self.formatter._generate_group_badge_info(group)
        
        assert "risk" in badge_info
        assert "data_type" in badge_info
        assert "size" in badge_info
        assert "High Risk" in badge_info["risk"]
        assert "TEXT" in badge_info["data_type"]
        assert "Small" in badge_info["size"]
    
    def test_format_for_export(self):
        """Test export formatting."""
        # Test JSON export
        json_export = self.formatter.format_for_export(self.processed_results, "json")
        assert isinstance(json_export, str)
        # The JSON export should contain the result data
        assert "password" in json_export
        
        # Test CSV export
        csv_export = self.formatter.format_for_export(self.processed_results, "csv")
        assert isinstance(csv_export, str)
        assert "Path,Key,Value" in csv_export
        
        # Test HTML export
        html_export = self.formatter.format_for_export(self.processed_results, "html")
        assert isinstance(html_export, str)
        assert "<!DOCTYPE html>" in html_export
        assert "<table>" in html_export
        
        # Test unsupported format
        with pytest.raises(ValueError):
            self.formatter.format_for_export(self.processed_results, "unsupported")
    
    def test_export_as_json(self):
        """Test JSON export."""
        export_data = self.formatter._export_as_json(self.processed_results)

        assert isinstance(export_data, str)
        import json
        data = json.loads(export_data)

        # Should be a list of result objects
        assert isinstance(data, list)
        assert len(data) == 2
        assert data[0]["path"] == "/test/engine1/path1"
        assert data[0]["key"] == "password"
        assert data[0]["data_type"] == "text"
        assert data[0]["risk_level"] == "high"
    
    def test_export_as_csv(self):
        """Test CSV export."""
        export_data = self.formatter._export_as_csv(self.processed_results)
        
        assert isinstance(export_data, str)
        assert "Path,Key,Value,Match Type,Engine Path,Timestamp,Data Type,Risk Level,Confidence Score,Security Indicators,Tags" in export_data
        assert "/test/engine1/path1" in export_data
        assert "password" in export_data
        assert "text" in export_data
        assert "high" in export_data
    
    def test_export_as_html(self):
        """Test HTML export."""
        export_data = self.formatter._export_as_html(self.processed_results)
        
        assert isinstance(export_data, str)
        assert "<!DOCTYPE html>" in export_data
        assert "<title>Secret Sluth - Search Results Export</title>" in export_data
        assert "<table>" in export_data
        assert "/test/engine1/path1" in export_data
        assert "password" in export_data
    
    def test_format_results_with_errors(self):
        """Test formatting results with errors."""
        # Create a result that will cause an error
        bad_result = Mock(spec=ProcessedResult)
        bad_result.original_result = Mock(spec=SearchResult)
        bad_result.original_result.get_unique_id.return_value = "test_123"
        bad_result.original_result.path = "/test/path"  # Add the path attribute
        bad_result.original_result.engine_path = "/test"  # Add the engine_path attribute
        bad_result.formatted_path = "/test/path"
        bad_result.formatted_key = "Test Key"
        bad_result.formatted_value = "test_value"
        bad_result.extracted_metadata = {"engine_type": "test"}
        bad_result.security_indicators = []
        bad_result.data_type = "text"
        bad_result.confidence_score = 0.9
        bad_result.risk_level = "high"
        bad_result.tags = []

        # Mock the _format_single_result to raise an exception
        with patch.object(self.formatter, '_format_single_result', side_effect=Exception("Test error")):
            formatted_results = self.formatter.format_results([bad_result], "")
            
            # Should still return a result (fallback)
            assert len(formatted_results) == 1
            assert isinstance(formatted_results[0], FormattedResult)
            assert formatted_results[0].result_id == "test_123"
            assert formatted_results[0].severity_badge == 'light'
            assert formatted_results[0].data_type_badge == 'light'
            assert formatted_results[0].confidence_indicator == '🔴'
    
    def test_format_groups_with_errors(self):
        """Test formatting groups with errors."""
        from app.result_processor import ResultGroup
        
        # Create a group that will cause an error
        bad_group = Mock(spec=ResultGroup)
        bad_group.group_id = "test_group"
        bad_group.group_name = "test_engine"
        bad_group.group_type = "engine"
        bad_group.results = []
        bad_group.summary = {}
        
        # Mock the _format_single_group to raise an exception
        with patch.object(self.formatter, '_format_single_group', side_effect=Exception("Test error")):
            formatted_groups = self.formatter.format_groups([bad_group])
            
            # Should still return a group (fallback)
            assert len(formatted_groups) == 1
            assert isinstance(formatted_groups[0], FormattedGroup)
            assert formatted_groups[0].group_id == "test_group"
            assert formatted_groups[0].group_name == "test_engine"
            assert formatted_groups[0].display_name == "test_engine"
            assert formatted_groups[0].summary_stats == {}
            assert formatted_groups[0].badge_info == {}
            assert formatted_groups[0].collapsed == False
    
    def test_format_results_empty(self):
        """Test formatting empty results."""
        formatted_results = self.formatter.format_results([], "")
        assert len(formatted_results) == 0
    
    def test_format_groups_empty(self):
        """Test formatting empty groups."""
        formatted_groups = self.formatter.format_groups([])
        assert len(formatted_groups) == 0
