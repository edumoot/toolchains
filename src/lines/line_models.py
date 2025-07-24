#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Core data models for line table analysis system.

This module defines the fundamental data structures used throughout
the line table analysis system, including verification results,
evidence collection, and DWARF debug information structures.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class VerificationResult(Enum):
    """
    Enumeration of possible line verification results.
    
    Attributes:
        VERIFIED: Line was successfully hit during execution
        NOT_HIT: Line exists but was not executed
        INVALID_BREAKPOINT: Unable to set breakpoint at line
        ERROR: Verification error occurred
    """
    VERIFIED = "verified"
    NOT_HIT = "not_hit"
    INVALID_BREAKPOINT = "invalid_breakpoint"
    ERROR = "error"


@dataclass
class LineVerificationEvidence:
    """
    Evidence collected for each line verification attempt.
    
    This class captures all relevant information about a single
    line verification attempt, including success/failure status,
    execution details, and any error information.
    
    Attributes:
        line_number: Source code line number being verified
        result: Verification result status
        hit_count: Number of times the line was hit during execution
        actual_address: Memory address where breakpoint was set
        error_message: Detailed error message if verification failed
        hit_timestamp: Unix timestamp when line was hit
        source_file: Path to the source file
        actual_line_hit: Actual line number hit (may differ from expected)
        actual_file_hit: Actual file hit (may differ from expected)
        function_name: Name of function containing the line
        breakpoint_id: LLDB breakpoint identifier
    """
    line_number: int
    result: VerificationResult
    hit_count: int = 0
    actual_address: Optional[str] = None
    error_message: Optional[str] = None
    hit_timestamp: Optional[float] = None
    source_file: Optional[str] = None
    actual_line_hit: Optional[int] = None
    actual_file_hit: Optional[str] = None
    function_name: Optional[str] = None
    breakpoint_id: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert evidence to dictionary for serialization."""
        return {
            'line_number': self.line_number,
            'result': self.result.value,
            'hit_count': self.hit_count,
            'actual_address': self.actual_address,
            'error_message': self.error_message,
            'hit_timestamp': self.hit_timestamp,
            'source_file': self.source_file,
            'actual_line_hit': self.actual_line_hit,
            'actual_file_hit': self.actual_file_hit,
            'function_name': self.function_name,
            'breakpoint_id': self.breakpoint_id
        }


@dataclass
class LineTableEntry:
    """
    Represents a single line table entry from DWARF debug information.
    
    Each entry maps a source code location to a machine code address,
    along with additional metadata about the code at that location.
    
    Attributes:
        address: Machine code address
        line: Source code line number
        column: Source code column number
        file_index: Index into the file table
        isa: Instruction set architecture
        discriminator: Discriminator for multiple blocks on same line
        flags: Additional flags (e.g., is_stmt, basic_block)
    """
    address: int
    line: int
    column: int
    file_index: int
    isa: int
    discriminator: int
    flags: str
    
    @property
    def is_statement(self) -> bool:
        """Check if this entry marks a statement boundary."""
        return 'is_stmt' in self.flags
    
    @property
    def is_basic_block(self) -> bool:
        """Check if this entry marks a basic block boundary."""
        return 'basic_block' in self.flags


@dataclass
class FileTableEntry:
    """
    Represents a file entry in the DWARF file table.
    
    The file table maps file indices to actual file paths,
    allowing line table entries to reference files efficiently.
    
    Attributes:
        index: File table index
        name: File name (may be relative)
        dir_index: Directory index for path resolution
    """
    index: int
    name: str
    dir_index: int
    
    def get_full_path(self, directories: List[str]) -> str:
        """
        Resolve full file path using directory table.
        
        Args:
            directories: List of directory paths from DWARF info
            
        Returns:
            Full resolved file path
        """
        if self.dir_index < len(directories):
            return str(Path(directories[self.dir_index]) / self.name)
        return self.name


@dataclass
class ReportData:
    """
    Structured data for verification reports.
    
    This class contains all the data needed to generate various
    report formats (text, JSON, HTML, etc.) from verification results.
    
    Attributes:
        binary_name: Name of the analyzed binary
        source_file_path: Path to the source file
        timestamp: Report generation timestamp
        total_lines: Total number of lines tested
        verified_lines: Number of successfully verified lines
        invalid_breakpoints: Number of invalid breakpoint attempts
        errors: Number of verification errors
        not_hit: Number of lines not executed
        success_rate: Percentage of successfully verified lines
        verified_line_numbers: Sorted list of verified line numbers
        results: Complete verification results by line number
        llvm_version: Version of LLVM used for verification
        metadata: Additional report metadata
    """
    binary_name: str
    source_file_path: Optional[Path]
    timestamp: str
    total_lines: int
    verified_lines: int
    invalid_breakpoints: int
    errors: int
    not_hit: int
    success_rate: float
    verified_line_numbers: List[int]
    results: Dict[int, LineVerificationEvidence]
    llvm_version: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert report data to dictionary for serialization."""
        return {
            'binary_name': self.binary_name,
            'source_file_path': str(self.source_file_path) if self.source_file_path else None,
            'timestamp': self.timestamp,
            'llvm_version': self.llvm_version,
            'statistics': {
                'total_lines': self.total_lines,
                'verified_lines': self.verified_lines,
                'invalid_breakpoints': self.invalid_breakpoints,
                'errors': self.errors,
                'not_hit': self.not_hit,
                'success_rate': self.success_rate
            },
            'verified_line_numbers': self.verified_line_numbers,
            'results': {
                line_num: evidence.to_dict() 
                for line_num, evidence in self.results.items()
            },
            'metadata': self.metadata
        }


@dataclass
class ReportPaths:
    """
    File paths related to report generation.
    
    Tracks the various files created during report generation,
    including modified source files, backups, and standalone reports.
    
    Attributes:
        modified_source: Path to the modified source file
        backup_file: Path to the backup of original source (if created)
        standalone_report: Path to standalone report file (if created)
        json_summary: Path to JSON summary file (if created)
    """
    modified_source: Path
    backup_file: Optional[Path] = None
    standalone_report: Optional[Path] = None
    json_summary: Optional[Path] = None


@dataclass
class AnalysisResult:
    """
    Complete result of line table analysis.
    
    This class encapsulates all outputs from a complete line table
    analysis run, including verification results, generated reports,
    and file paths.
    
    Attributes:
        source_file: Path to the analyzed source file
        binary_file: Path to the analyzed binary
        line_numbers: List of line numbers found in debug info
        verification_results: Line verification evidence by line number
        llvm_version: Version of LLVM used for analysis
        report_data: Structured report data
        report_paths: Paths to generated report files
        success: Whether analysis completed successfully
        error_message: Error message if analysis failed
    """
    source_file: Path
    binary_file: Path
    line_numbers: List[int]
    verification_results: Dict[int, LineVerificationEvidence]
    llvm_version: str = "unknown"
    report_data: Optional[ReportData] = None
    report_paths: Optional[ReportPaths] = None
    success: bool = True
    error_message: Optional[str] = None
    
    @property
    def verified_count(self) -> int:
        """Count of successfully verified lines."""
        return sum(1 for evidence in self.verification_results.values() 
                  if evidence.result == VerificationResult.VERIFIED)
    
    @property
    def error_count(self) -> int:
        """Count of verification errors."""
        return sum(1 for evidence in self.verification_results.values() 
                  if evidence.result == VerificationResult.ERROR)


class LineTableAnalysisError(Exception):
    """Base exception for line table analysis errors."""
    pass


class BinaryParsingError(LineTableAnalysisError):
    """Error during binary or DWARF parsing."""
    pass


class VerificationError(LineTableAnalysisError):
    """Error during line verification."""
    pass


class ReportGenerationError(LineTableAnalysisError):
    """Error during report generation."""
    pass