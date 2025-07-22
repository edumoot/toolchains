#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Main orchestrator for line table analysis system.

This module provides the main interface for performing complete
line table analysis, coordinating parsing, verification, and
report generation.
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

from line_models import AnalysisResult, LineTableAnalysisError
from line_verifier import DwarfLineTableParser, LLDBLineVerifier, get_llvm_version
from line_report_generator import VerificationReportGenerator, SourceFileReportWriter


class LineTableAnalyzer:
    """
    Main orchestrator for line table analysis.
    
    This class coordinates the complete line table analysis workflow,
    including DWARF parsing, line verification, and report generation.
    
    Attributes:
        parser: DWARF line table parser
        verifier: LLDB line verifier
        report_generator: Report generator
        report_writer: Source file report writer
    """
    
    def __init__(self, timeout_seconds: int = 30,
                 max_iterations: Optional[int] = None,
                 comment_style: str = "block",
                 backup_original: bool = True,
                 include_metadata: bool = True):
        """
        Initialize the line table analyzer.
        
        Args:
            timeout_seconds: Timeout for line verification
            max_iterations: Maximum verification iterations
            comment_style: Comment style for source file reports
            backup_original: Whether to backup original files
            include_metadata: Whether to include metadata in reports
        """
        self.parser = None  # Created per analysis
        self.verifier = LLDBLineVerifier(
            timeout_seconds=timeout_seconds,
            max_iterations=max_iterations
        )
        self.report_generator = VerificationReportGenerator(
            include_metadata=include_metadata
        )
        self.report_writer = SourceFileReportWriter(
            comment_style=comment_style,
            backup_original=backup_original
        )
    
    def analyze(self, source_file: Path, binary_file: Path,
                output_dir: Optional[Path] = None) -> AnalysisResult:
        """
        Perform complete line table analysis.
        
        This method orchestrates the entire analysis workflow:
        1. Parse DWARF debug information
        2. Extract line numbers
        3. Verify lines using LLDB
        4. Generate reports
        5. Write results
        
        Args:
            source_file: Path to source file
            binary_file: Path to binary file
            output_dir: Optional directory for standalone reports
            
        Returns:
            Complete analysis result
        """
        try:
            # Get LLVM version
            llvm_version = get_llvm_version()
            print(f"Using LLVM version: {llvm_version}")

            # Step 1: Parse DWARF information
            print(f"Parsing DWARF information from {binary_file.name}...")
            self.parser = DwarfLineTableParser(binary_file)
            self.parser.parse()
            
            # Step 2: Extract line numbers
            print(f"Extracting line numbers for {source_file.name}...")
            line_numbers = self.parser.get_line_numbers(str(source_file))
            
            if not line_numbers:
                return AnalysisResult(
                    source_file=source_file,
                    binary_file=binary_file,
                    line_numbers=[],
                    verification_results={},
                    llvm_version=llvm_version,
                    success=False,
                    error_message="No line numbers found in debug information"
                )
            
            print(f"Found {len(line_numbers)} line numbers to verify")
            
            # Step 3: Verify lines
            print("Verifying line numbers using LLDB...")
            verification_results = self.verifier.verify_lines(
                source_file, binary_file, line_numbers
            )
            
            # Step 4: Generate report
            print("Generating verification report...")
            report_data = self.report_generator.generate_report(
                verification_results,
                binary_name=binary_file.name,
                source_file_path=source_file,
                llvm_version=llvm_version
            )
            
            report_content = self.report_generator.format_report(report_data)
            
            # Step 5: Write results
            print("Writing report to source file...")
            report_paths = self.report_writer.write_report(
                report_content,
                source_file_path=source_file,
                binary_file_path=binary_file,
                report_metadata=report_data.metadata,
                output_dir=output_dir
            )
            
            # Create result
            result = AnalysisResult(
                source_file=source_file,
                binary_file=binary_file,
                line_numbers=line_numbers,
                verification_results=verification_results,
                llvm_version=llvm_version,
                report_data=report_data,
                report_paths=report_paths,
                success=True
            )
            
            # Print summary
            self._print_summary(result)
            
            return result
            
        except Exception as e:
            return AnalysisResult(
                source_file=source_file,
                binary_file=binary_file,
                line_numbers=[],
                verification_results={},
                llvm_version=get_llvm_version(),
                success=False,
                error_message=str(e)
            )
    
    def _print_summary(self, result: AnalysisResult) -> None:
        """Print analysis summary to console."""
        print("\n" + "=" * 50)
        print("ANALYSIS SUMMARY")
        print("=" * 50)
        
        if result.report_data:
            print(f"Binary: {result.report_data.binary_name}")
            print(f"Source: {result.source_file.name}")
            print(f"Total lines tested: {result.report_data.total_lines}")
            print(f"Successfully verified: {result.report_data.verified_lines}")
            print(f"Success rate: {result.report_data.success_rate:.1f}%")
            
            if result.report_data.verified_line_numbers:
                print(f"\nVerified lines: {result.report_data.verified_line_numbers}")
        
        if result.report_paths:
            print("\nGenerated files:")
            print(f"  Modified source: {result.report_paths.modified_source}")
            if result.report_paths.backup_file:
                print(f"  Backup: {result.report_paths.backup_file}")
            if result.report_paths.standalone_report:
                print(f"  Report: {result.report_paths.standalone_report}")
            if result.report_paths.json_summary:
                print(f"  JSON: {result.report_paths.json_summary}")
        
        print("=" * 50)


def main():
    """
    Command-line interface for line table analysis.
    
    Provides a CLI for running line table analysis with various options.
    """
    parser = argparse.ArgumentParser(
        description="Analyze DWARF line table information and verify line numbers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s source.c binary.out
  %(prog)s --timeout 60 --output-dir reports/ source.c binary.out
  %(prog)s --comment-style line --no-backup source.c binary.out
        """
    )
    
    # Positional arguments
    parser.add_argument(
        'source_file',
        type=Path,
        help='Path to the source file'
    )
    parser.add_argument(
        'binary_file',
        type=Path,
        help='Path to the binary file with debug information'
    )
    
    # Optional arguments
    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Timeout in seconds for line verification (default: 30)'
    )
    parser.add_argument(
        '--max-iterations',
        type=int,
        default=None,
        help='Maximum number of verification iterations (default: auto)'
    )
    parser.add_argument(
        '--comment-style',
        choices=['block', 'line'],
        default='block',
        help='Comment style for source file reports (default: block)'
    )
    parser.add_argument(
        '--no-backup',
        action='store_true',
        help='Do not create backup of original source file'
    )
    parser.add_argument(
        '--no-metadata',
        action='store_true',
        help='Exclude metadata from reports'
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=None,
        help='Directory for standalone report files'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.source_file.exists():
        print(f"Error: Source file not found: {args.source_file}", file=sys.stderr)
        sys.exit(1)
    
    if not args.binary_file.exists():
        print(f"Error: Binary file not found: {args.binary_file}", file=sys.stderr)
        sys.exit(1)
    
    # Create analyzer
    analyzer = LineTableAnalyzer(
        timeout_seconds=args.timeout,
        max_iterations=args.max_iterations,
        comment_style=args.comment_style,
        backup_original=not args.no_backup,
        include_metadata=not args.no_metadata
    )
    
    # Run analysis
    try:
        result = analyzer.analyze(
            source_file=args.source_file,
            binary_file=args.binary_file,
            output_dir=args.output_dir
        )
        
        if result.success:
            if result.report_data and result.report_data.verified_line_numbers:
                print(f"\nFound line numbers: {result.report_data.verified_line_numbers}")
            sys.exit(0)
        else:
            print(f"\nError: {result.error_message}", file=sys.stderr)
            sys.exit(1)
            
    except LineTableAnalysisError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()