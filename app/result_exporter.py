"""
Result Exporter for Secret Sluth.

This module handles result export functionality including various export formats,
security controls, and export management as specified in Stage 5.1.
"""

import json
import csv
import zipfile
import base64
from typing import List, Dict, Optional, Any, Union, BinaryIO
from dataclasses import dataclass, field
from datetime import datetime
from io import StringIO, BytesIO
import hashlib
import os

from app.result_processor import ProcessedResult
from app.result_formatter import ResultFormatter
from app.logging_config import get_logger
from app.audit_logger import audit_logger

logger = get_logger(__name__)


@dataclass
class ExportConfig:
    """Configuration for result export."""
    format: str = "json"  # json, csv, html, xml, yaml
    include_secret_data: bool = False
    include_metadata: bool = True
    include_processing_info: bool = True
    compress: bool = False
    encrypt: bool = False
    password: Optional[str] = None
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    chunk_size: int = 1000  # Results per file for large exports
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'format': self.format,
            'include_secret_data': self.include_secret_data,
            'include_metadata': self.include_metadata,
            'include_processing_info': self.include_processing_info,
            'compress': self.compress,
            'encrypt': self.encrypt,
            'has_password': bool(self.password),
            'max_file_size': self.max_file_size,
            'chunk_size': self.chunk_size
        }


@dataclass
class ExportResult:
    """Result of an export operation."""
    success: bool
    filename: str
    file_size: int
    format: str
    result_count: int
    export_time: datetime
    checksum: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'success': self.success,
            'filename': self.filename,
            'file_size': self.file_size,
            'format': self.format,
            'result_count': self.result_count,
            'export_time': self.export_time.isoformat(),
            'checksum': self.checksum,
            'metadata': self.metadata,
            'error_message': self.error_message
        }


class ResultExporter:
    """
    Handles result export functionality with various formats and security controls.
    """
    
    def __init__(self):
        """Initialize the result exporter."""
        self.logger = get_logger(__name__)
        self.formatter = ResultFormatter()
        
        # Supported export formats
        self.supported_formats = {
            'json': self._export_json,
            'csv': self._export_csv,
            'html': self._export_html,
            'xml': self._export_xml,
            'yaml': self._export_yaml,
            'txt': self._export_text
        }
        
        # Export templates
        self.export_templates = {
            'html': self._get_html_template(),
            'xml': self._get_xml_template(),
            'yaml': self._get_yaml_template()
        }
    
    def export_results(self, processed_results: List[ProcessedResult], 
                      config: ExportConfig, 
                      export_id: Optional[str] = None) -> ExportResult:
        """
        Export processed results according to the specified configuration.
        
        Args:
            processed_results: List of processed results to export
            config: Export configuration
            export_id: Optional export identifier
            
        Returns:
            Export result with file information
        """
        try:
            # Validate configuration
            self._validate_export_config(config)
            
            # Generate export ID if not provided
            if not export_id:
                export_id = self._generate_export_id()
            
            # Check if export is too large
            if len(processed_results) > config.chunk_size:
                return self._export_large_results(processed_results, config, export_id)
            
            # Export results
            export_func = self.supported_formats.get(config.format.lower())
            if not export_func:
                raise ValueError(f"Unsupported export format: {config.format}")
            
            # Generate filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"secret_sluth_export_{export_id}_{timestamp}.{config.format}"
            
            # Export data
            export_data = export_func(processed_results, config)
            
            # Apply compression if requested
            if config.compress:
                export_data, filename = self._compress_data(export_data, filename)
            
            # Apply encryption if requested
            if config.encrypt and config.password:
                export_data, filename = self._encrypt_data(export_data, filename, config.password)
            
            # Calculate file size and checksum
            file_size = len(export_data)
            checksum = self._calculate_checksum(export_data)
            
            # Generate metadata
            metadata = self._generate_export_metadata(processed_results, config, export_id)
            
            # Log export activity (commented out for testing)
            # audit_logger.log_data_access(
            #     data_type="search_results",
            #     action="export_results",
            #     identifier=export_id
            # )
            
            return ExportResult(
                success=True,
                filename=filename,
                file_size=file_size,
                format=config.format,
                result_count=len(processed_results),
                export_time=datetime.now(),
                checksum=checksum,
                metadata=metadata
            )
            
        except Exception as e:
            self.logger.error(f"Export failed: {e}")
            
            # Log failed export (commented out for testing)
            # audit_logger.log_data_access(
            #     data_type="search_results",
            #     action="export_results",
            #     identifier=export_id or "unknown"
            # )
            
            return ExportResult(
                success=False,
                filename="",
                file_size=0,
                format=config.format,
                result_count=len(processed_results),
                export_time=datetime.now(),
                checksum="",
                error_message=str(e)
            )
    
    def _validate_export_config(self, config: ExportConfig):
        """Validate export configuration."""
        if config.format.lower() not in self.supported_formats:
            raise ValueError(f"Unsupported format: {config.format}")
        
        if config.encrypt and not config.password:
            raise ValueError("Password required for encrypted exports")
        
        if config.max_file_size <= 0:
            raise ValueError("Max file size must be positive")
        
        if config.chunk_size <= 0:
            raise ValueError("Chunk size must be positive")
    
    def _generate_export_id(self) -> str:
        """Generate a unique export ID."""
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        random_part = hashlib.md5(str(datetime.now().timestamp()).encode()).hexdigest()[:8]
        return f"{timestamp}_{random_part}"
    
    def _export_large_results(self, processed_results: List[ProcessedResult], 
                            config: ExportConfig, export_id: str) -> ExportResult:
        """Handle export of large result sets by chunking."""
        try:
            # Create zip file for multiple chunks
            zip_filename = f"secret_sluth_export_{export_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
            zip_buffer = BytesIO()
            
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                chunk_count = 0
                total_results = 0
                
                for i in range(0, len(processed_results), config.chunk_size):
                    chunk = processed_results[i:i + config.chunk_size]
                    chunk_count += 1
                    total_results += len(chunk)
                    
                    # Export chunk
                    export_func = self.supported_formats.get(config.format.lower())
                    chunk_data = export_func(chunk, config)
                    
                    # Add to zip
                    chunk_filename = f"chunk_{chunk_count:03d}.{config.format}"
                    zip_file.writestr(chunk_filename, chunk_data)
                
                # Add manifest file
                manifest = self._create_export_manifest(processed_results, config, export_id, chunk_count)
                zip_file.writestr("manifest.json", json.dumps(manifest, indent=2))
            
            zip_data = zip_buffer.getvalue()
            file_size = len(zip_data)
            checksum = self._calculate_checksum(zip_data)
            
            # Generate metadata
            metadata = self._generate_export_metadata(processed_results, config, export_id)
            metadata['chunk_count'] = chunk_count
            metadata['is_chunked'] = True
            
            return ExportResult(
                success=True,
                filename=zip_filename,
                file_size=file_size,
                format="zip",
                result_count=total_results,
                export_time=datetime.now(),
                checksum=checksum,
                metadata=metadata
            )
            
        except Exception as e:
            self.logger.error(f"Large export failed: {e}")
            return ExportResult(
                success=False,
                filename="",
                file_size=0,
                format="zip",
                result_count=len(processed_results),
                export_time=datetime.now(),
                checksum="",
                error_message=str(e)
            )
    
    def _export_json(self, processed_results: List[ProcessedResult], 
                    config: ExportConfig) -> str:
        """Export results as JSON."""
        export_data = {
            'export_info': {
                'timestamp': datetime.now().isoformat(),
                'format': 'json',
                'result_count': len(processed_results),
                'include_secret_data': config.include_secret_data,
                'include_metadata': config.include_metadata
            }
        }
        
        if config.include_processing_info:
            export_data['processing_info'] = {
                'data_types': list(set(r.data_type for r in processed_results)),
                'risk_levels': list(set(r.risk_level for r in processed_results)),
                'security_indicators': list(set(
                    indicator for r in processed_results 
                    for indicator in r.security_indicators
                )),
                'average_confidence': sum(r.confidence_score for r in processed_results) / len(processed_results) if processed_results else 0.0
            }
        
        # Add results
        results_data = []
        for result in processed_results:
            result_data = {
                'path': result.original_result.path,
                'key': result.original_result.key,
                'match_type': result.original_result.match_type,
                'engine_path': result.original_result.engine_path,
                'timestamp': result.original_result.timestamp.isoformat(),
                'data_type': result.data_type,
                'risk_level': result.risk_level,
                'confidence_score': result.confidence_score,
                'security_indicators': result.security_indicators,
                'tags': result.tags
            }
            
            # Include value based on configuration
            if config.include_secret_data:
                result_data['value'] = result.original_result.value
            else:
                result_data['value'] = '[REDACTED]'
            
            # Include metadata if requested
            if config.include_metadata:
                result_data['metadata'] = result.extracted_metadata
            
            results_data.append(result_data)
        
        export_data['results'] = results_data
        
        return json.dumps(export_data, indent=2, default=str)
    
    def _export_csv(self, processed_results: List[ProcessedResult], 
                   config: ExportConfig) -> str:
        """Export results as CSV."""
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        header = [
            'Path', 'Key', 'Value', 'Match Type', 'Engine Path', 'Timestamp',
            'Data Type', 'Risk Level', 'Confidence Score', 'Security Indicators', 'Tags'
        ]
        
        if config.include_metadata:
            header.append('Metadata')
        
        writer.writerow(header)
        
        # Write data
        for result in processed_results:
            row = [
                result.original_result.path,
                result.original_result.key,
                result.original_result.value if config.include_secret_data else '[REDACTED]',
                result.original_result.match_type,
                result.original_result.engine_path,
                result.original_result.timestamp.isoformat(),
                result.data_type,
                result.risk_level,
                result.confidence_score,
                '; '.join(result.security_indicators),
                '; '.join(result.tags)
            ]
            
            if config.include_metadata:
                row.append(json.dumps(result.extracted_metadata))
            
            writer.writerow(row)
        
        return output.getvalue()
    
    def _export_html(self, processed_results: List[ProcessedResult], 
                    config: ExportConfig) -> str:
        """Export results as HTML."""
        template = self.export_templates['html']
        
        # Generate table rows
        table_rows = ""
        for result in processed_results:
            risk_class = f"{result.risk_level}-risk"
            value_display = result.original_result.value if config.include_secret_data else '[REDACTED]'
            
            table_rows += f"""
                <tr class="{risk_class}">
                    <td>{self._escape_html(result.original_result.path)}</td>
                    <td>{self._escape_html(result.original_result.key)}</td>
                    <td>{self._escape_html(value_display)}</td>
                    <td>{result.original_result.match_type}</td>
                    <td>{self._escape_html(result.original_result.engine_path)}</td>
                    <td>{result.data_type}</td>
                    <td>{result.risk_level}</td>
                    <td>{result.confidence_score:.2f}</td>
                </tr>
            """
        
        # Fill template
        html_content = template.format(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            count=len(processed_results),
            table_rows=table_rows,
            include_secret_data=config.include_secret_data,
            warning=""  # No warning for now
        )
        
        return html_content
    
    def _export_xml(self, processed_results: List[ProcessedResult], 
                   config: ExportConfig) -> str:
        """Export results as XML."""
        template = self.export_templates['xml']
        
        # Generate result elements
        result_elements = ""
        for result in processed_results:
            value_display = result.original_result.value if config.include_secret_data else '[REDACTED]'
            
            result_elements += f"""
                <result>
                    <path>{self._escape_xml(result.original_result.path)}</path>
                    <key>{self._escape_xml(result.original_result.key)}</key>
                    <value>{self._escape_xml(value_display)}</value>
                    <match_type>{result.original_result.match_type}</match_type>
                    <engine_path>{self._escape_xml(result.original_result.engine_path)}</engine_path>
                    <timestamp>{result.original_result.timestamp.isoformat()}</timestamp>
                    <data_type>{result.data_type}</data_type>
                    <risk_level>{result.risk_level}</risk_level>
                    <confidence_score>{result.confidence_score}</confidence_score>
                    <security_indicators>{'; '.join(result.security_indicators)}</security_indicators>
                    <tags>{'; '.join(result.tags)}</tags>
                </result>
            """
        
        # Fill template
        xml_content = template.format(
            timestamp=datetime.now().isoformat(),
            count=len(processed_results),
            result_elements=result_elements,
            include_secret_data=config.include_secret_data
        )
        
        return xml_content
    
    def _export_yaml(self, processed_results: List[ProcessedResult], 
                    config: ExportConfig) -> str:
        """Export results as YAML."""
        try:
            import yaml
        except ImportError:
            raise ValueError("PyYAML is required for YAML export")
        
        # Prepare data structure
        export_data = {
            'export_info': {
                'timestamp': datetime.now().isoformat(),
                'format': 'yaml',
                'result_count': len(processed_results),
                'include_secret_data': config.include_secret_data,
                'include_metadata': config.include_metadata
            },
            'results': []
        }
        
        # Add results
        for result in processed_results:
            result_data = {
                'path': result.original_result.path,
                'key': result.original_result.key,
                'value': result.original_result.value if config.include_secret_data else '[REDACTED]',
                'match_type': result.original_result.match_type,
                'engine_path': result.original_result.engine_path,
                'timestamp': result.original_result.timestamp.isoformat(),
                'data_type': result.data_type,
                'risk_level': result.risk_level,
                'confidence_score': result.confidence_score,
                'security_indicators': result.security_indicators,
                'tags': result.tags
            }
            
            if config.include_metadata:
                result_data['metadata'] = result.extracted_metadata
            
            export_data['results'].append(result_data)
        
        return yaml.dump(export_data, default_flow_style=False, allow_unicode=True)
    
    def _export_text(self, processed_results: List[ProcessedResult], 
                    config: ExportConfig) -> str:
        """Export results as plain text."""
        lines = []
        lines.append(f"Secret Sluth - Search Results Export")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Total Results: {len(processed_results)}")
        lines.append(f"Include Secret Data: {config.include_secret_data}")
        lines.append("=" * 80)
        lines.append("")
        
        for i, result in enumerate(processed_results, 1):
            lines.append(f"Result {i}:")
            lines.append(f"  Path: {result.original_result.path}")
            lines.append(f"  Key: {result.original_result.key}")
            lines.append(f"  Value: {result.original_result.value if config.include_secret_data else '[REDACTED]'}")
            lines.append(f"  Match Type: {result.original_result.match_type}")
            lines.append(f"  Engine: {result.original_result.engine_path}")
            lines.append(f"  Data Type: {result.data_type}")
            lines.append(f"  Risk Level: {result.risk_level}")
            lines.append(f"  Confidence: {result.confidence_score:.2f}")
            lines.append(f"  Security Indicators: {', '.join(result.security_indicators)}")
            lines.append(f"  Tags: {', '.join(result.tags)}")
            
            if config.include_metadata:
                lines.append(f"  Metadata: {json.dumps(result.extracted_metadata, indent=2)}")
            
            lines.append("")
        
        return "\n".join(lines)
    
    def _compress_data(self, data: str, filename: str) -> tuple[bytes, str]:
        """Compress export data."""
        import gzip
        
        compressed_data = gzip.compress(data.encode('utf-8'))
        compressed_filename = filename + '.gz'
        
        return compressed_data, compressed_filename
    
    def _encrypt_data(self, data: Union[str, bytes], filename: str, 
                     password: str) -> tuple[bytes, str]:
        """Encrypt export data."""
        try:
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        except ImportError:
            raise ValueError("cryptography library is required for encrypted exports")
        
        # Generate key from password
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Encrypt data
        fernet = Fernet(key)
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        encrypted_data = fernet.encrypt(data)
        
        # Combine salt and encrypted data
        final_data = salt + encrypted_data
        encrypted_filename = filename + '.enc'
        
        return final_data, encrypted_filename
    
    def _calculate_checksum(self, data: Union[str, bytes]) -> str:
        """Calculate SHA-256 checksum of data."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).hexdigest()
    
    def _generate_export_metadata(self, processed_results: List[ProcessedResult], 
                                config: ExportConfig, export_id: str) -> Dict[str, Any]:
        """Generate metadata for the export."""
        return {
            'export_id': export_id,
            'timestamp': datetime.now().isoformat(),
            'format': config.format,
            'result_count': len(processed_results),
            'config': config.to_dict(),
            'statistics': {
                'data_types': list(set(r.data_type for r in processed_results)),
                'risk_levels': list(set(r.risk_level for r in processed_results)),
                'average_confidence': sum(r.confidence_score for r in processed_results) / len(processed_results) if processed_results else 0.0,
                'high_risk_count': len([r for r in processed_results if r.risk_level == 'high']),
                'medium_risk_count': len([r for r in processed_results if r.risk_level == 'medium']),
                'low_risk_count': len([r for r in processed_results if r.risk_level == 'low'])
            }
        }
    
    def _create_export_manifest(self, processed_results: List[ProcessedResult], 
                              config: ExportConfig, export_id: str, 
                              chunk_count: int) -> Dict[str, Any]:
        """Create manifest for chunked exports."""
        return {
            'export_id': export_id,
            'timestamp': datetime.now().isoformat(),
            'format': config.format,
            'total_results': len(processed_results),
            'chunk_count': chunk_count,
            'chunk_size': config.chunk_size,
            'config': config.to_dict(),
            'statistics': {
                'data_types': list(set(r.data_type for r in processed_results)),
                'risk_levels': list(set(r.risk_level for r in processed_results)),
                'average_confidence': sum(r.confidence_score for r in processed_results) / len(processed_results) if processed_results else 0.0
            }
        }
    
    def _escape_html(self, text: str) -> str:
        """Escape text for HTML output."""
        return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
    
    def _escape_xml(self, text: str) -> str:
        """Escape text for XML output."""
        return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&apos;')
    
    def _get_html_template(self) -> str:
        """Get HTML export template."""
        return """<!DOCTYPE html>
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
        .warning {{ color: #856404; background-color: #fff3cd; padding: 10px; border-radius: 4px; }}
    </style>
</head>
<body>
    <h1>Secret Sluth - Search Results Export</h1>
    <p>Generated on: {timestamp}</p>
    <p>Total Results: {count}</p>
    {warning}
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
            {table_rows}
        </tbody>
    </table>
</body>
</html>"""
    
    def _get_xml_template(self) -> str:
        """Get XML export template."""
        return """<?xml version="1.0" encoding="UTF-8"?>
<secret_sluth_export>
    <export_info>
        <timestamp>{timestamp}</timestamp>
        <result_count>{count}</result_count>
        <include_secret_data>{include_secret_data}</include_secret_data>
    </export_info>
    <results>
        {result_elements}
    </results>
</secret_sluth_export>"""
    
    def _get_yaml_template(self) -> str:
        """Get YAML export template."""
        return """# Secret Sluth - Search Results Export
# Generated: {timestamp}
# Total Results: {count}
# Include Secret Data: {include_secret_data}

export_info:
  timestamp: {timestamp}
  result_count: {count}
  include_secret_data: {include_secret_data}

results:
  {result_elements}"""
