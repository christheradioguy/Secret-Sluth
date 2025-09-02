"""
Result Formatter for Secret Sluth.

This module handles result formatting and organization for display purposes
as specified in Stage 5.1.
"""

import json
import re
import urllib.parse
from typing import List, Dict, Optional, Any, Union
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import html

from app.result_processor import ProcessedResult, ResultGroup
from app.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class FormattedResult:
    """Formatted result for display purposes."""
    result_id: str
    display_path: str
    display_key: str
    display_value: str
    engine_path: str
    engine_type: str
    match_highlights: Dict[str, List[str]]
    severity_badge: str
    data_type_badge: str
    confidence_indicator: str
    security_indicators: List[str]
    tags: List[str]
    metadata_summary: str
    actions: List[Dict[str, str]]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'result_id': self.result_id,
            'display_path': self.display_path,
            'display_key': self.display_key,
            'display_value': self.display_value,
            'engine_path': self.engine_path,
            'engine_type': self.engine_type,
            'match_highlights': self.match_highlights,
            'severity_badge': self.severity_badge,
            'data_type_badge': self.data_type_badge,
            'confidence_indicator': self.confidence_indicator,
            'security_indicators': self.security_indicators,
            'tags': self.tags,
            'metadata_summary': self.metadata_summary,
            'actions': self.actions
        }


@dataclass
class FormattedGroup:
    """Formatted group for display purposes."""
    group_id: str
    group_name: str
    group_type: str
    display_name: str
    summary_stats: Dict[str, Any]
    badge_info: Dict[str, str]
    collapsed: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'group_id': self.group_id,
            'group_name': self.group_name,
            'group_type': self.group_type,
            'display_name': self.display_name,
            'summary_stats': self.summary_stats,
            'badge_info': self.badge_info,
            'collapsed': self.collapsed
        }


class ResultFormatter:
    """
    Formats results and groups for display purposes.
    """
    
    def __init__(self):
        """Initialize the result formatter."""
        self.logger = get_logger(__name__)
        
        # Badge configurations
        self.severity_badges = {
            'high': 'danger',
            'medium': 'warning',
            'low': 'secondary',
            'unknown': 'light'
        }
        
        self.data_type_badges = {
            'email': 'info',
            'url': 'primary',
            'ip_address': 'secondary',
            'api_key': 'danger',
            'jwt_token': 'warning',
            'base64': 'dark',
            'json': 'success',
            'uuid': 'info',
            'credit_card': 'danger',
            'ssh_key': 'warning',
            'private_key': 'danger',
            'certificate': 'success',
            'numeric': 'secondary',
            'boolean': 'light',
            'text': 'primary',
            'unknown': 'light',
            'empty': 'light'
        }
        
        # Confidence indicators
        self.confidence_indicators = {
            'high': '🟢',
            'medium': '🟡',
            'low': '🔴'
        }
    
    def format_results(self, processed_results: List[ProcessedResult], 
                      search_query: str = "") -> List[FormattedResult]:
        """
        Format processed results for display.
        
        Args:
            processed_results: List of processed results to format
            search_query: Original search query for highlighting
            
        Returns:
            List of formatted results
        """
        formatted_results = []
        
        for result in processed_results:
            try:
                formatted_result = self._format_single_result(result, search_query)
                formatted_results.append(formatted_result)
            except Exception as e:
                self.logger.error(f"Failed to format result {result.original_result.path}: {e}")
                # Create a basic formatted result as fallback
                formatted_result = FormattedResult(
                    result_id=result.original_result.get_unique_id(),
                    display_path=result.formatted_path,
                    display_key=result.formatted_key,
                    display_value=result.formatted_value,
                    engine_path=result.original_result.engine_path,
                    engine_type=result.extracted_metadata.get('engine_type', 'unknown'),
                    match_highlights={},
                    severity_badge='light',
                    data_type_badge='light',
                    confidence_indicator='🔴',
                    security_indicators=[],
                    tags=[],
                    metadata_summary="",
                    actions=[]
                )
                formatted_results.append(formatted_result)
        
        return formatted_results
    
    def _format_single_result(self, result: ProcessedResult, 
                            search_query: str) -> FormattedResult:
        """
        Format a single processed result.
        
        Args:
            result: Processed result to format
            search_query: Original search query for highlighting
            
        Returns:
            Formatted result
        """
        # Generate result ID
        result_id = result.original_result.get_unique_id()
        
        # Format display fields with highlighting
        display_path = self._format_display_path(result.formatted_path, search_query)
        display_key = self._format_display_key(result.formatted_key, search_query)
        display_value = self._format_display_value(result.formatted_value, search_query)
        
        # Generate match highlights
        match_highlights = self._generate_match_highlights(result, search_query)
        
        # Generate badges
        severity_badge = self._generate_severity_badge(result.risk_level)
        data_type_badge = self._generate_data_type_badge(result.data_type)
        confidence_indicator = self._generate_confidence_indicator(result.confidence_score)
        
        # Format security indicators
        security_indicators = self._format_security_indicators(result.security_indicators)
        
        # Format tags
        tags = self._format_tags(result.tags)
        
        # Generate metadata summary
        metadata_summary = self._generate_metadata_summary(result.extracted_metadata)
        
        # Generate actions
        actions = self._generate_actions(result)
        
        # Get engine type from metadata
        engine_type = result.extracted_metadata.get('engine_type', 'unknown')
        
        return FormattedResult(
            result_id=result_id,
            display_path=display_path,
            display_key=display_key,
            display_value=display_value,
            engine_path=result.original_result.engine_path,
            engine_type=engine_type,
            match_highlights=match_highlights,
            severity_badge=severity_badge,
            data_type_badge=data_type_badge,
            confidence_indicator=confidence_indicator,
            security_indicators=security_indicators,
            tags=tags,
            metadata_summary=metadata_summary,
            actions=actions
        )
    
    def _format_display_path(self, path: str, search_query: str) -> str:
        """Format path for display with highlighting."""
        if not path:
            return "/"
        
        # Escape HTML
        escaped_path = html.escape(path)
        
        # Highlight search query if present
        if search_query:
            escaped_query = html.escape(search_query)
            escaped_path = re.sub(
                f'({re.escape(escaped_query)})',
                r'<mark>\1</mark>',
                escaped_path,
                flags=re.IGNORECASE
            )
        
        return escaped_path
    
    def _format_display_key(self, key: str, search_query: str) -> str:
        """Format key for display with highlighting."""
        if not key:
            return ""
        
        # Escape HTML
        escaped_key = html.escape(key)
        
        # Highlight search query if present
        if search_query:
            escaped_query = html.escape(search_query)
            escaped_key = re.sub(
                f'({re.escape(escaped_query)})',
                r'<mark>\1</mark>',
                escaped_key,
                flags=re.IGNORECASE
            )
        
        return escaped_key
    
    def _format_display_value(self, value: str, search_query: str) -> str:
        """Format value for display with highlighting."""
        if not value:
            return ""
        
        # Truncate very long values
        if len(value) > 100:
            display_value = value[:97] + "..."
        else:
            display_value = value
        
        # Escape HTML
        escaped_value = html.escape(display_value)
        
        # Highlight search query if present
        if search_query:
            escaped_query = html.escape(search_query)
            escaped_value = re.sub(
                f'({re.escape(escaped_query)})',
                r'<mark>\1</mark>',
                escaped_value,
                flags=re.IGNORECASE
            )
        
        return escaped_value
    
    def generate_vault_ui_url(self, vault_url: str, engine_type: str, secret_path: str) -> str:
        """
        Generate the correct Vault UI URL based on engine type.
        
        Args:
            vault_url: Base Vault server URL
            engine_type: Type of secret engine (kv, database, ssh, etc.)
            secret_path: Full path to the secret
            
        Returns:
            Complete Vault UI URL
        """
        # Remove leading slash if present
        clean_path = secret_path.lstrip('/')
        
        # Extract engine name and handle different path structures
        path_parts = clean_path.split('/')
        if len(path_parts) >= 3:
            # Format: engine_name/engine_type/secret_path
            engine_name = path_parts[0]
            engine_type_from_path = path_parts[1]
            secret_subpath = '/'.join(path_parts[2:])
        elif len(path_parts) >= 2:
            # Format: engine_name/secret_path
            engine_name = path_parts[0]
            secret_subpath = '/'.join(path_parts[1:])
        else:
            engine_name = clean_path
            secret_subpath = ""
        
        # URL encode the secret subpath to handle forward slashes properly
        encoded_subpath = urllib.parse.quote(secret_subpath, safe='')
        
        # Different engine types have different UI URL patterns
        if engine_type == 'kv':
            # KV stores: /ui/vault/secrets/engine_name/kv/secret_path
            return f"{vault_url}/ui/vault/secrets/{engine_name}/kv/{encoded_subpath}"
        elif engine_type == 'database':
            # Database: /ui/vault/secrets/engine_name/database/secret_path
            return f"{vault_url}/ui/vault/secrets/{engine_name}/database/{encoded_subpath}"
        elif engine_type == 'ssh':
            # SSH: /ui/vault/secrets/engine_name/ssh/secret_path
            return f"{vault_url}/ui/vault/secrets/{engine_name}/ssh/{encoded_subpath}"
        elif engine_type == 'pki':
            # PKI: /ui/vault/secrets/engine_name/pki/secret_path
            return f"{vault_url}/ui/vault/secrets/{engine_name}/pki/{encoded_subpath}"
        elif engine_type == 'transit':
            # Transit: /ui/vault/secrets/engine_name/transit/secret_path
            return f"{vault_url}/ui/vault/secrets/{engine_name}/transit/{encoded_subpath}"
        elif engine_type == 'aws':
            # AWS: /ui/vault/secrets/engine_name/aws/secret_path
            return f"{vault_url}/ui/vault/secrets/{engine_name}/aws/{encoded_subpath}"
        elif engine_type == 'azure':
            # Azure: /ui/vault/secrets/engine_name/azure/secret_path
            return f"{vault_url}/ui/vault/secrets/{engine_name}/azure/{encoded_subpath}"
        elif engine_type == 'gcp':
            # GCP: /ui/vault/secrets/engine_name/gcp/secret_path
            return f"{vault_url}/ui/vault/secrets/{engine_name}/gcp/{encoded_subpath}"
        else:
            # Generic fallback: /ui/vault/secrets/engine_name/secret_path
            encoded_path = urllib.parse.quote(clean_path, safe='')
            return f"{vault_url}/ui/vault/secrets/{encoded_path}"
    
    def _generate_match_highlights(self, result: ProcessedResult, 
                                 search_query: str) -> Dict[str, List[str]]:
        """Generate match highlights for the result."""
        highlights = {
            'path': [],
            'key': [],
            'value': []
        }
        
        if not search_query:
            return highlights
        
        # Check path matches
        if search_query.lower() in result.formatted_path.lower():
            highlights['path'].append(search_query)
        
        # Check key matches
        if search_query.lower() in result.formatted_key.lower():
            highlights['key'].append(search_query)
        
        # Check value matches
        if search_query.lower() in result.formatted_value.lower():
            highlights['value'].append(search_query)
        
        return highlights
    
    def _generate_severity_badge(self, risk_level: str) -> str:
        """Generate severity badge HTML."""
        badge_class = self.severity_badges.get(risk_level, 'light')
        return f'<span class="badge bg-{badge_class}">{risk_level.upper()}</span>'
    
    def _generate_data_type_badge(self, data_type: str) -> str:
        """Generate data type badge HTML."""
        badge_class = self.data_type_badges.get(data_type, 'light')
        return f'<span class="badge bg-{badge_class}">{data_type.upper()}</span>'
    
    def _generate_confidence_indicator(self, confidence_score: float) -> str:
        """Generate confidence indicator."""
        if confidence_score >= 0.8:
            return self.confidence_indicators['high']
        elif confidence_score >= 0.5:
            return self.confidence_indicators['medium']
        else:
            return self.confidence_indicators['low']
    
    def _format_security_indicators(self, indicators: List[str]) -> List[str]:
        """Format security indicators for display."""
        formatted = []
        for indicator in indicators:
            if indicator.startswith('high_risk_'):
                formatted.append(f'<span class="badge bg-danger">High Risk</span>')
            elif indicator.startswith('medium_risk_'):
                formatted.append(f'<span class="badge bg-warning">Medium Risk</span>')
            elif indicator.startswith('low_risk_'):
                formatted.append(f'<span class="badge bg-secondary">Low Risk</span>')
        return formatted
    
    def _format_tags(self, tags: List[str]) -> List[str]:
        """Format tags for display."""
        formatted = []
        for tag in tags:
            if tag.startswith('type:'):
                data_type = tag.split(':', 1)[1]
                badge_class = self.data_type_badges.get(data_type, 'light')
                formatted.append(f'<span class="badge bg-{badge_class}">{data_type}</span>')
            elif tag.startswith('risk:'):
                risk_level = tag.split(':', 1)[1]
                badge_class = self.severity_badges.get(risk_level, 'light')
                formatted.append(f'<span class="badge bg-{badge_class}">{risk_level}</span>')
            else:
                formatted.append(f'<span class="badge bg-light text-dark">{tag}</span>')
        return formatted
    
    def _generate_metadata_summary(self, metadata: Dict[str, Any]) -> str:
        """Generate a summary of metadata for display."""
        summary_parts = []
        
        if 'engine_type' in metadata:
            summary_parts.append(f"Engine: {metadata['engine_type']}")
        
        if 'path_depth' in metadata:
            summary_parts.append(f"Depth: {metadata['path_depth']}")
        
        if 'key_length' in metadata:
            summary_parts.append(f"Key Length: {metadata['key_length']}")
        
        if 'value_length' in metadata:
            summary_parts.append(f"Value Length: {metadata['value_length']}")
        
        if 'age_hours' in metadata:
            age_hours = metadata['age_hours']
            if age_hours < 24:
                summary_parts.append(f"Age: {age_hours:.1f}h")
            else:
                summary_parts.append(f"Age: {age_hours/24:.1f}d")
        
        return " | ".join(summary_parts)
    
    def _generate_actions(self, result: ProcessedResult) -> List[Dict[str, str]]:
        """Generate actions for the result."""
        actions = [
            {
                'type': 'view',
                'label': 'View Details',
                'icon': 'fas fa-eye',
                'class': 'btn-outline-info',
                'onclick': f"showResultDetails('{result.original_result.get_unique_id()}')"
            },
            {
                'type': 'copy',
                'label': 'Copy Path',
                'icon': 'fas fa-copy',
                'class': 'btn-outline-primary',
                'onclick': f"copyToClipboard('{result.original_result.path}')"
            }
        ]
        
        # Add export action if it's a high-risk result
        if result.risk_level == 'high':
            actions.append({
                'type': 'export',
                'label': 'Export',
                'icon': 'fas fa-download',
                'class': 'btn-outline-warning',
                'onclick': f"exportResult('{result.original_result.get_unique_id()}')"
            })
        
        return actions
    
    def format_groups(self, result_groups: List[ResultGroup]) -> List[FormattedGroup]:
        """
        Format result groups for display.
        
        Args:
            result_groups: List of result groups to format
            
        Returns:
            List of formatted groups
        """
        formatted_groups = []
        
        for group in result_groups:
            try:
                formatted_group = self._format_single_group(group)
                formatted_groups.append(formatted_group)
            except Exception as e:
                self.logger.error(f"Failed to format group {group.group_id}: {e}")
                # Create a basic formatted group as fallback
                formatted_group = FormattedGroup(
                    group_id=group.group_id,
                    group_name=group.group_name,
                    group_type=group.group_type,
                    display_name=group.group_name,
                    summary_stats={},
                    badge_info={},
                    collapsed=False
                )
                formatted_groups.append(formatted_group)
        
        return formatted_groups
    
    def _format_single_group(self, group: ResultGroup) -> FormattedGroup:
        """
        Format a single result group.
        
        Args:
            group: Result group to format
            
        Returns:
            Formatted group
        """
        # Generate display name
        display_name = self._generate_group_display_name(group)
        
        # Generate summary statistics
        summary_stats = self._generate_group_summary_stats(group)
        
        # Generate badge information
        badge_info = self._generate_group_badge_info(group)
        
        # Determine if group should be collapsed by default
        collapsed = len(group.results) < 5  # Collapse small groups
        
        return FormattedGroup(
            group_id=group.group_id,
            group_name=group.group_name,
            group_type=group.group_type,
            display_name=display_name,
            summary_stats=summary_stats,
            badge_info=badge_info,
            collapsed=collapsed
        )
    
    def _generate_group_display_name(self, group: ResultGroup) -> str:
        """Generate a display name for the group."""
        if group.group_type == "engine":
            return f"Engine: {group.group_name}"
        elif group.group_type == "path":
            return f"Path: {group.group_name}"
        elif group.group_type == "key_pattern":
            return f"Key Pattern: {group.group_name}"
        elif group.group_type == "data_type":
            return f"Data Type: {group.group_name.upper()}"
        elif group.group_type == "risk_level":
            return f"Risk Level: {group.group_name.upper()}"
        else:
            return group.group_name
    
    def _generate_group_summary_stats(self, group: ResultGroup) -> Dict[str, Any]:
        """Generate summary statistics for the group."""
        stats = group.summary.copy()
        
        # Add formatted statistics
        stats['formatted_total'] = f"{stats['total_results']:,}"
        stats['formatted_unique_paths'] = f"{stats['unique_paths']:,}"
        stats['formatted_unique_keys'] = f"{stats['unique_keys']:,}"
        stats['formatted_confidence'] = f"{stats['average_confidence']:.2f}"
        
        # Add risk distribution
        stats['risk_distribution'] = {
            'high': stats['high_risk_count'],
            'medium': stats['medium_risk_count'],
            'low': stats['low_risk_count']
        }
        
        return stats
    
    def _generate_group_badge_info(self, group: ResultGroup) -> Dict[str, str]:
        """Generate badge information for the group."""
        badge_info = {}
        
        # Generate risk level badge
        risk_levels = group.summary.get('risk_levels', [])
        if 'high' in risk_levels:
            badge_info['risk'] = '<span class="badge bg-danger">High Risk</span>'
        elif 'medium' in risk_levels:
            badge_info['risk'] = '<span class="badge bg-warning">Medium Risk</span>'
        else:
            badge_info['risk'] = '<span class="badge bg-secondary">Low Risk</span>'
        
        # Generate data type badge
        data_types = group.summary.get('data_types', [])
        if data_types:
            primary_type = data_types[0]
            badge_class = self.data_type_badges.get(primary_type, 'light')
            badge_info['data_type'] = f'<span class="badge bg-{badge_class}">{primary_type.upper()}</span>'
        
        # Generate size badge
        total_results = group.summary.get('total_results', 0)
        if total_results > 100:
            badge_info['size'] = '<span class="badge bg-danger">Large</span>'
        elif total_results > 50:
            badge_info['size'] = '<span class="badge bg-warning">Medium</span>'
        else:
            badge_info['size'] = '<span class="badge bg-success">Small</span>'
        
        return badge_info
    
    def format_for_export(self, processed_results: List[ProcessedResult], 
                         format_type: str = "json") -> str:
        """
        Format results for export.
        
        Args:
            processed_results: List of processed results to export
            format_type: Export format ("json", "csv", "html")
            
        Returns:
            Formatted export string
        """
        if format_type.lower() == "json":
            return self._export_as_json(processed_results)
        elif format_type.lower() == "csv":
            return self._export_as_csv(processed_results)
        elif format_type.lower() == "html":
            return self._export_as_html(processed_results)
        elif format_type.lower() == "xml":
            return self._export_as_xml(processed_results)
        elif format_type.lower() == "yaml":
            return self._export_as_yaml(processed_results)
        elif format_type.lower() == "txt":
            return self._export_as_text(processed_results)
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
    
    def _export_as_json(self, processed_results: List[ProcessedResult]) -> str:
        """Export results as JSON."""
        export_data = []
        
        for result in processed_results:
            export_item = {
                'path': result.original_result.path,
                'key': result.original_result.key,
                'value': result.original_result.value,
                'match_type': result.original_result.match_type,
                'engine_path': result.original_result.engine_path,
                'timestamp': result.original_result.timestamp.isoformat(),
                'data_type': result.data_type,
                'risk_level': result.risk_level,
                'confidence_score': result.confidence_score,
                'security_indicators': result.security_indicators,
                'tags': result.tags,
                'metadata': result.extracted_metadata
            }
            export_data.append(export_item)
        
        return json.dumps(export_data, indent=2, default=str)
    
    def _export_as_csv(self, processed_results: List[ProcessedResult]) -> str:
        """Export results as CSV."""
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Path', 'Key', 'Value', 'Match Type', 'Engine Path', 'Timestamp',
            'Data Type', 'Risk Level', 'Confidence Score', 'Security Indicators',
            'Tags', 'Metadata'
        ])
        
        # Write data
        for result in processed_results:
            writer.writerow([
                result.original_result.path,
                result.original_result.key,
                result.original_result.value,
                result.original_result.match_type,
                result.original_result.engine_path,
                result.original_result.timestamp.isoformat(),
                result.data_type,
                result.risk_level,
                result.confidence_score,
                '; '.join(result.security_indicators),
                '; '.join(result.tags),
                json.dumps(result.extracted_metadata)
            ])
        
        return output.getvalue()
    
    def _export_as_html(self, processed_results: List[ProcessedResult]) -> str:
        """Export results as HTML."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        count = len(processed_results)
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secret Sluth - Search Results Export</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .high-risk {{ background-color: #ffebee; }}
                .medium-risk {{ background-color: #fff3e0; }}
                .low-risk {{ background-color: #f1f8e9; }}
            </style>
        </head>
        <body>
            <h1>Secret Sluth - Search Results Export</h1>
            <p>Generated on: {timestamp}</p>
            <p>Total Results: {count}</p>
            <table>
                <thead>
                    <tr>
                        <th>Path</th>
                        <th>Key</th>
                        <th>Value</th>
                        <th>Match Type</th>
                        <th>Engine</th>
                        <th>Data Type</th>
                        <th>Risk Level</th>
                        <th>Confidence</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        for result in processed_results:
            risk_class = f"{result.risk_level}-risk"
            html_content += f"""
                <tr class="{risk_class}">
                    <td>{html.escape(result.original_result.path)}</td>
                    <td>{html.escape(result.original_result.key)}</td>
                    <td>{html.escape(result.original_result.value)}</td>
                    <td>{result.original_result.match_type}</td>
                    <td>{html.escape(result.original_result.engine_path)}</td>
                    <td>{result.data_type}</td>
                    <td>{result.risk_level}</td>
                    <td>{result.confidence_score:.2f}</td>
                </tr>
            """
        
        html_content += """
                </tbody>
            </table>
        </body>
        </html>
        """
        
        return html_content

    def _export_as_xml(self, processed_results: List[ProcessedResult]) -> str:
        """Export results as XML."""
        xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<secret_sluth_export>
    <export_info>
        <timestamp>{timestamp}</timestamp>
        <result_count>{count}</result_count>
    </export_info>
    <results>
        {result_elements}
    </results>
</secret_sluth_export>"""
        
        # Generate result elements
        result_elements = ""
        for result in processed_results:
            result_elements += f"""
        <result>
            <path>{self._escape_xml(result.original_result.path)}</path>
            <key>{self._escape_xml(result.original_result.key)}</key>
            <value>{self._escape_xml(result.original_result.value)}</value>
            <match_type>{result.original_result.match_type}</match_type>
            <engine_path>{self._escape_xml(result.original_result.engine_path)}</engine_path>
            <timestamp>{result.original_result.timestamp.isoformat()}</timestamp>
            <data_type>{result.data_type}</data_type>
            <risk_level>{result.risk_level}</risk_level>
            <confidence_score>{result.confidence_score}</confidence_score>
            <security_indicators>{'; '.join(result.security_indicators)}</security_indicators>
            <tags>{'; '.join(result.tags)}</tags>
        </result>"""
        
        return xml_content.format(
            timestamp=datetime.now().isoformat(),
            count=len(processed_results),
            result_elements=result_elements
        )

    def _export_as_yaml(self, processed_results: List[ProcessedResult]) -> str:
        """Export results as YAML."""
        try:
            import yaml
        except ImportError:
            raise ValueError("PyYAML is required for YAML export")
        
        export_data = {
            'export_info': {
                'timestamp': datetime.now().isoformat(),
                'result_count': len(processed_results)
            },
            'results': []
        }
        
        for result in processed_results:
            result_data = {
                'path': result.original_result.path,
                'key': result.original_result.key,
                'value': result.original_result.value,
                'match_type': result.original_result.match_type,
                'engine_path': result.original_result.engine_path,
                'timestamp': result.original_result.timestamp.isoformat(),
                'data_type': result.data_type,
                'risk_level': result.risk_level,
                'confidence_score': result.confidence_score,
                'security_indicators': result.security_indicators,
                'tags': result.tags
            }
            export_data['results'].append(result_data)
        
        return yaml.dump(export_data, default_flow_style=False)

    def _export_as_text(self, processed_results: List[ProcessedResult]) -> str:
        """Export results as plain text."""
        text_content = f"""Secret Sluth - Search Results Export
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Results: {len(processed_results)}

"""
        
        for i, result in enumerate(processed_results, 1):
            text_content += f"""Result {i}:
  Path: {result.original_result.path}
  Key: {result.original_result.key}
  Value: {result.original_result.value}
  Match Type: {result.original_result.match_type}
  Engine Path: {result.original_result.engine_path}
  Data Type: {result.data_type}
  Risk Level: {result.risk_level}
  Confidence Score: {result.confidence_score}
  Security Indicators: {', '.join(result.security_indicators)}
  Tags: {', '.join(result.tags)}

"""
        
        return text_content

    def _escape_xml(self, text: str) -> str:
        """Escape text for XML output."""
        return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&apos;')
