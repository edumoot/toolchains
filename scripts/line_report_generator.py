#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Report generation module for line table analysis.

This module provides functionality to generate verification reports
from line verification results and write them to various formats.
"""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from line_models import (
    LineVerificationEvidence,
    ReportData,
    ReportGenerationError,
    ReportPaths,
    VerificationResult
)


class VerificationReportGenerator:
    """
    Generates verification reports from line verification results.
    
    This class creates structured reports from verification evidence,
    including statistics, summaries, and detailed analysis.
    
    Attributes:
        include_metadata: Whether to include execution metadata in reports
    """
    
    def __init__(self, include_metadata: bool = True):
        """
        Initialize the report generator.
        
        Args:
            include_metadata: Whether to include metadata in reports
        """
        self.include_metadata = include_metadata
    
    def generate_report(self, results: Dict[int, LineVerificationEvidence],
                       binary_name: str,
                       source_file_path: Optional[Path] = None) -> ReportData:
        """
        Generate a structured verification report.
        
        Creates a comprehensive report from verification results,
        including statistics, summaries, and detailed evidence.
        
        Args:
            results: Dictionary mapping line numbers to verification evidence
            binary_name: Name of the analyzed binary
            source_file_path: Path to the source file (optional)
            
        Returns:
            Structured report data
        """
        # Generate timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Calculate statistics
        stats = self._calculate_statistics(results)
        
        # Extract verified line numbers
        verified_line_numbers = sorted([
            line_num for line_num, evidence in results.items()
            if evidence.result == VerificationResult.VERIFIED
        ])
        
        # Create metadata
        metadata = self._create_metadata(
            binary_name, timestamp, source_file_path, len(verified_line_numbers)
        )
        
        # Build report data
        report_data = ReportData(
            binary_name=binary_name,
            source_file_path=source_file_path,
            timestamp=timestamp,
            total_lines=stats['total_lines'],
            verified_lines=stats['verified_lines'],
            invalid_breakpoints=stats['invalid_breakpoints'],
            errors=stats['errors'],
            not_hit=stats['not_hit'],
            success_rate=stats['success_rate'],
            verified_line_numbers=verified_line_numbers,
            results=results,
            metadata=metadata
        )
        
        return report_data
    
    def format_report(self, report_data: ReportData) -> str:
        """
        Format report data as human-readable text.
        
        Args:
            report_data: Structured report data
            
        Returns:
            Formatted report as text string
        """
        lines = []
        
        # Header
        lines.extend(self._format_header())
        
        # Metadata section
        if self.include_metadata:
            lines.extend(self._format_metadata(report_data))
        
        # Executive summary
        lines.extend(self._format_summary(report_data))
        
        # Verified line numbers
        lines.extend(self._format_verified_lines(report_data))
        
        # Detailed results
        lines.extend(self._format_detailed_results(report_data))
        
        # Analysis recommendations
        lines.extend(self._format_recommendations(report_data))
        
        # Footer
        lines.extend(self._format_footer())
        
        return '\n'.join(lines)
    
    def _calculate_statistics(self, results: Dict[int, LineVerificationEvidence]) -> Dict[str, Any]:
        """Calculate summary statistics from verification results."""
        total_lines = len(results)
        
        stats = {
            'total_lines': total_lines,
            'verified_lines': 0,
            'invalid_breakpoints': 0,
            'errors': 0,
            'not_hit': 0,
            'success_rate': 0.0
        }
        
        for evidence in results.values():
            if evidence.result == VerificationResult.VERIFIED:
                stats['verified_lines'] += 1
            elif evidence.result == VerificationResult.INVALID_BREAKPOINT:
                stats['invalid_breakpoints'] += 1
            elif evidence.result == VerificationResult.ERROR:
                stats['errors'] += 1
            elif evidence.result == VerificationResult.NOT_HIT:
                stats['not_hit'] += 1
        
        if total_lines > 0:
            stats['success_rate'] = (stats['verified_lines'] / total_lines) * 100
        
        return stats
    
    def _create_metadata(self, binary_name: str, timestamp: str,
                        source_file_path: Optional[Path],
                        verified_count: int) -> Dict[str, Any]:
        """Create report metadata."""
        metadata = {
            'binary_name': binary_name,
            'timestamp': timestamp,
            'generation_time': datetime.now().isoformat(),
            'verified_line_count': verified_count,
            'include_metadata': self.include_metadata
        }
        
        if source_file_path:
            metadata['source_file'] = str(source_file_path)
            metadata['source_file_name'] = source_file_path.name
        
        return metadata
    
    def _format_header(self) -> List[str]:
        """Format report header."""
        return [
            "=" * 78,
            "DWARF LINE TABLE VERIFICATION REPORT",
            "=" * 78,
            ""
        ]
    
    def _format_metadata(self, report_data: ReportData) -> List[str]:
        """Format metadata section."""
        lines = [
            "Report Metadata:",
            "-" * 18,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Binary Name: {report_data.binary_name}",
        ]
        
        if report_data.source_file_path:
            lines.extend([
                f"Source File: {report_data.source_file_path.name}",
                f"Full Path: {report_data.source_file_path}",
            ])
        
        lines.append("")
        return lines
    
    def _format_summary(self, report_data: ReportData) -> List[str]:
        """Format executive summary."""
        return [
            "Executive Summary:",
            "-" * 18,
            f"Total lines tested: {report_data.total_lines}",
            f"Successfully verified: {report_data.verified_lines}",
            f"Invalid breakpoints: {report_data.invalid_breakpoints}",
            f"Errors: {report_data.errors}",
            f"Not hit: {report_data.not_hit}",
            f"Success rate: {report_data.success_rate:.1f}%",
            ""
        ]
    
    def _format_verified_lines(self, report_data: ReportData) -> List[str]:
        """Format verified line numbers section."""
        lines = [
            "Verified Line Numbers:",
            "-" * 23,
        ]
        
        if report_data.verified_line_numbers:
            # Format in rows of 10 for readability
            lines_per_row = 10
            for i in range(0, len(report_data.verified_line_numbers), lines_per_row):
                chunk = report_data.verified_line_numbers[i:i+lines_per_row]
                lines.append("  " + ", ".join(f"{num:4d}" for num in chunk))
            lines.append(f"  Total verified: {len(report_data.verified_line_numbers)} lines")
        else:
            lines.append("  No lines successfully verified")
        
        lines.append("")
        return lines
    
    def _format_detailed_results(self, report_data: ReportData) -> List[str]:
        """Format detailed results section."""
        lines = [
            "Detailed Results:",
            "-" * 16,
            ""
        ]
        
        # Group results by status
        for result_type in VerificationResult:
            matching_results = [
                (line_num, evidence)
                for line_num, evidence in report_data.results.items()
                if evidence.result == result_type
            ]
            
            if matching_results:
                status_name = result_type.value.upper().replace('_', ' ')
                lines.append(f"{status_name} ({len(matching_results)} lines):")
                
                for line_num, evidence in sorted(matching_results):
                    line_detail = f"  Line {line_num:4d}"
                    
                    if evidence.actual_address:
                        line_detail += f" -> {evidence.actual_address}"
                    
                    if evidence.hit_count > 0:
                        line_detail += f" (hit {evidence.hit_count} times)"
                    
                    if evidence.error_message:
                        line_detail += f" - {evidence.error_message}"
                    
                    lines.append(line_detail)
                
                lines.append("")
        
        return lines
    
    def _format_recommendations(self, report_data: ReportData) -> List[str]:
        """Format analysis recommendations."""
        lines = [
            "Analysis Recommendations:",
            "-" * 28,
        ]
        
        if report_data.success_rate >= 90:
            lines.append("✓ Excellent verification rate - Line table appears highly accurate")
        elif report_data.success_rate >= 70:
            lines.append("⚠ Good verification rate - Minor issues may exist")
        elif report_data.success_rate >= 50:
            lines.append("⚠ Moderate verification rate - Investigation recommended")
        else:
            lines.append("✗ Low verification rate - Significant debugging issues likely")
        
        if report_data.invalid_breakpoints > 0:
            lines.append(f"• {report_data.invalid_breakpoints} invalid breakpoints detected - "
                        "Check optimization settings")
        
        if report_data.errors > 0:
            lines.append(f"• {report_data.errors} errors encountered - "
                        "Review compilation settings")
        
        if report_data.not_hit > 0:
            lines.append(f"• {report_data.not_hit} lines not executed - "
                        "Consider test coverage")
        
        lines.append("")
        return lines
    
    def _format_footer(self) -> List[str]:
        """Format report footer."""
        return ["=" * 78]


class SourceFileReportWriter:
    """
    Writes verification reports to source files as comments.
    
    This class handles writing formatted reports back to source files,
    including backup creation and comment formatting.
    
    Attributes:
        comment_style: Style of comments ('block' or 'line')
        backup_original: Whether to create backups of original files
    """
    
    def __init__(self, comment_style: str = "block", backup_original: bool = True):
        """
        Initialize the report writer.
        
        Args:
            comment_style: Comment style ('block' for /* */ or 'line' for //)
            backup_original: Whether to backup original files
            
        Raises:
            ReportGenerationError: If invalid comment style specified
        """
        if comment_style not in ["block", "line"]:
            raise ReportGenerationError(
                f"Invalid comment style: {comment_style}. Use 'block' or 'line'"
            )
        
        self.comment_style = comment_style
        self.backup_original = backup_original
    
    def write_report(self, report_content: str, source_file_path: Path,
                    binary_file_path: Path, report_metadata: Dict[str, Any],
                    output_dir: Optional[Path] = None) -> ReportPaths:
        """
        Write verification report as comments to source file.
        
        Args:
            report_content: Formatted report content
            source_file_path: Path to the source file
            binary_file_path: Path to the binary file
            report_metadata: Report metadata dictionary
            output_dir: Directory for standalone reports (optional)
            
        Returns:
            Paths to generated files
            
        Raises:
            ReportGenerationError: If file operations fail
        """
        # Validate inputs
        self._validate_inputs(source_file_path)
        
        # Create backup if requested
        backup_path = None
        if self.backup_original:
            backup_path = self._create_backup(source_file_path, report_metadata['timestamp'])
        
        # Process source file
        original_content = self._read_file(source_file_path)
        cleaned_content = self._remove_existing_reports(
            original_content, binary_file_path
        )
        commented_report = self._format_as_comments(report_content)
        modified_content = self._append_report(cleaned_content, commented_report)
        
        # Write modified content
        self._write_file(source_file_path, modified_content)
        
        # Create standalone files if requested
        standalone_path = None
        json_path = None
        if output_dir:
            standalone_path, json_path = self._create_standalone_files(
                output_dir, report_content, report_metadata
            )
        
        return ReportPaths(
            modified_source=source_file_path,
            backup_file=backup_path,
            standalone_report=standalone_path,
            json_summary=json_path
        )
    
    def _validate_inputs(self, source_file_path: Path) -> None:
        """Validate input parameters."""
        if not source_file_path.exists():
            raise ReportGenerationError(f"Source file not found: {source_file_path}")
        
        valid_extensions = ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx']
        if source_file_path.suffix.lower() not in valid_extensions:
            raise ReportGenerationError(
                f"File must be a C/C++ source file. Got: {source_file_path.suffix}"
            )
    
    def _create_backup(self, source_file_path: Path, timestamp: str) -> Path:
        """Create backup of original file."""
        backup_path = source_file_path.with_suffix(
            f'.backup_{timestamp}{source_file_path.suffix}'
        )
        
        try:
            content = self._read_file(source_file_path)
            self._write_file(backup_path, content)
            return backup_path
        except Exception as e:
            raise ReportGenerationError(f"Failed to create backup: {e}")
    
    def _read_file(self, file_path: Path) -> str:
        """Read file content."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except IOError as e:
            raise ReportGenerationError(f"Failed to read {file_path}: {e}")
    
    def _write_file(self, file_path: Path, content: str) -> None:
        """Write content to file."""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
        except IOError as e:
            raise ReportGenerationError(f"Failed to write {file_path}: {e}")
    
    def _remove_existing_reports(self, content: str, binary_file_path: Path) -> str:
        """Remove existing verification reports for this binary."""
        binary_name = binary_file_path.stem
        binary_name_with_ext = binary_file_path.name
        
        # Build removal patterns
        patterns = self._build_removal_patterns(binary_name, binary_name_with_ext)
        
        # Apply patterns
        modified_content = content
        for pattern in patterns:
            modified_content = re.sub(
                pattern, '', modified_content,
                flags=re.DOTALL | re.MULTILINE
            )
        
        # Clean up whitespace
        modified_content = re.sub(r'\n\s*\n\s*\n+', '\n\n', modified_content)
        
        return modified_content.rstrip()
    
    def _build_removal_patterns(self, binary_name: str, binary_name_with_ext: str) -> List[str]:
        """Build regex patterns for removing existing reports."""
        escaped_name = re.escape(binary_name)
        escaped_name_ext = re.escape(binary_name_with_ext)
        
        patterns = []
        
        if self.comment_style == "block":
            # Block comment patterns
            pattern = (
                r'/\*\s*\n'
                r'\s*\*\s*=+\s*\n'
                r'\s*\*\s*DWARF LINE TABLE VERIFICATION REPORT.*?\n'
                r'(?=.*?\*\s*Binary Name:\s*(?:' + 
                escaped_name + r'|' + escaped_name_ext + r')\s*\n)'
                r'.*?'
                r'\*/'
            )
            patterns.append(pattern)
        else:
            # Line comment patterns
            pattern = (
                r'//\s*=+\s*\n'
                r'//\s*DWARF LINE TABLE VERIFICATION REPORT.*?\n'
                r'(?=(?://.*?\n)*?//\s*Binary Name:\s*(?:' +
                escaped_name + r'|' + escaped_name_ext + r')\s*\n)'
                r'(?://.*?\n)*?'
                r'//\s*=+\s*\n'
            )
            patterns.append(pattern)
        
        return patterns
    
    def _format_as_comments(self, content: str) -> str:
        """Format content as C-style comments."""
        lines = content.split('\n')
        
        if self.comment_style == "block":
            # Block comment style
            commented_lines = ["/*"]
            commented_lines.extend(
                f" * {line}" if line.strip() else " *"
                for line in lines
            )
            commented_lines.append(" */")
            return '\n'.join(commented_lines)
        else:
            # Line comment style
            return '\n'.join(
                f"// {line}" if line.strip() else "//"
                for line in lines
            )
    
    def _append_report(self, original_content: str, report_content: str) -> str:
        """Append report to original content."""
        separator = "\n\n" if original_content.endswith('\n') else "\n\n"
        return original_content + separator + report_content
    
    def _create_standalone_files(self, output_dir: Path, report_content: str,
                                report_metadata: Dict[str, Any]) -> Tuple[Path, Path]:
        """Create standalone report files."""
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Text report
        report_filename = (
            f"{report_metadata['binary_name']}_verification_report_"
            f"{report_metadata['timestamp']}.txt"
        )
        report_path = output_dir / report_filename
        
        try:
            self._write_file(report_path, report_content)
            
            # JSON summary
            json_filename = (
                f"{report_metadata['binary_name']}_verification_summary_"
                f"{report_metadata['timestamp']}.json"
            )
            json_path = output_dir / json_filename
            
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(report_metadata, f, indent=2)
            
            return report_path, json_path
            
        except Exception as e:
            raise ReportGenerationError(f"Failed to create standalone files: {e}")