#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Example usage scripts for the line table analysis system.

This module demonstrates various ways to use the line table analysis
components, both programmatically and through custom workflows.
"""

from pathlib import Path
from typing import List, Dict

from models import (
    AnalysisResult,
    LineVerificationEvidence,
    VerificationResult
)
from line_verifier import DwarfLineTableParser, LLDBLineVerifier, get_llvm_version
from report_generator import VerificationReportGenerator, SourceFileReportWriter
from line_table_analyzer import LineTableAnalyzer


def example_basic_analysis():
    """
    Example 1: Basic line table analysis with default settings.
    
    This example shows the simplest way to analyze a binary and
    generate a verification report.
    """
    print("Example 1: Basic Analysis")
    print("-" * 30)
    
    # Create analyzer with default settings
    analyzer = LineTableAnalyzer()
    
    # Analyze source and binary
    source_file = Path("test_program.c")
    binary_file = Path("test_program")
    
    result = analyzer.analyze(source_file, binary_file)
    
    if result.success:
        print(f"Analysis successful!")
        print(f"Verified {result.verified_count} out of {len(result.line_numbers)} lines")
    else:
        print(f"Analysis failed: {result.error_message}")


def example_custom_settings():
    """
    Example 2: Analysis with custom settings.
    
    This example demonstrates how to customize various analysis
    parameters for specific use cases.
    """
    print("\nExample 2: Custom Settings")
    print("-" * 30)
    
    # Create analyzer with custom settings
    analyzer = LineTableAnalyzer(
        timeout_seconds=60,          # Longer timeout for complex programs
        max_iterations=100,          # More iterations for programs with loops
        comment_style="line",        # Use // comments instead of /* */
        backup_original=True,        # Always backup original files
        include_metadata=True        # Include detailed metadata
    )
    
    # Analyze with output directory for standalone reports
    source_file = Path("complex_program.cpp")
    binary_file = Path("complex_program")
    output_dir = Path("verification_reports")
    
    result = analyzer.analyze(source_file, binary_file, output_dir)
    
    if result.success and result.report_paths:
        print(f"Reports generated:")
        print(f"  - Modified source: {result.report_paths.modified_source}")
        print(f"  - Standalone report: {result.report_paths.standalone_report}")
        print(f"  - JSON summary: {result.report_paths.json_summary}")


def example_separate_components():
    """
    Example 3: Using components separately.
    
    This example shows how to use the individual components
    for custom workflows.
    """
    print("\nExample 3: Separate Components")
    print("-" * 30)
    
    source_file = Path("modular_test.c")
    binary_file = Path("modular_test")
    
    # Get LLVM version
    llvm_version = get_llvm_version()
    print(f"LLVM Version: {llvm_version}")
    
    # Step 1: Parse DWARF information
    print("1. Parsing DWARF information...")
    parser = DwarfLineTableParser(binary_file)
    parser.parse()
    
    # Get line numbers for the source file
    line_numbers = parser.get_line_numbers(str(source_file))
    print(f"   Found {len(line_numbers)} lines with debug info")
    
    # Step 2: Verify specific lines only
    print("2. Verifying lines...")
    verifier = LLDBLineVerifier(timeout_seconds=20)
    
    # Verify only a subset of lines (e.g., first 10)
    lines_to_verify = line_numbers[:10] if len(line_numbers) > 10 else line_numbers
    verification_results = verifier.verify_lines(
        source_file, binary_file, lines_to_verify
    )
    
    # Step 3: Generate custom report
    print("3. Generating report...")
    report_gen = VerificationReportGenerator(include_metadata=False)
    report_data = report_gen.generate_report(
        verification_results,
        binary_name=binary_file.name,
        source_file_path=source_file,
        llvm_version=llvm_version
    )
    
    # Custom report formatting
    print(f"   Success rate: {report_data.success_rate:.1f}%")
    print(f"   Verified lines: {report_data.verified_line_numbers}")
    print(f"   LLVM Version used: {report_data.llvm_version}")" * 30)
    
    source_file = Path("modular_test.c")
    binary_file = Path("modular_test")
    
    # Step 1: Parse DWARF information
    print("1. Parsing DWARF information...")
    parser = DwarfLineTableParser(binary_file)
    parser.parse()
    
    # Get line numbers for the source file
    line_numbers = parser.get_line_numbers(str(source_file))
    print(f"   Found {len(line_numbers)} lines with debug info")
    
    # Step 2: Verify specific lines only
    print("2. Verifying lines...")
    verifier = LLDBLineVerifier(timeout_seconds=20)
    
    # Verify only a subset of lines (e.g., first 10)
    lines_to_verify = line_numbers[:10] if len(line_numbers) > 10 else line_numbers
    verification_results = verifier.verify_lines(
        source_file, binary_file, lines_to_verify
    )
    
    # Step 3: Generate custom report
    print("3. Generating report...")
    report_gen = VerificationReportGenerator(include_metadata=False)
    report_data = report_gen.generate_report(
        verification_results,
        binary_name=binary_file.name,
        source_file_path=source_file
    )
    
    # Custom report formatting
    print(f"   Success rate: {report_data.success_rate:.1f}%")
    print(f"   Verified lines: {report_data.verified_line_numbers}")


def example_batch_analysis():
    """
    Example 4: Batch analysis of multiple files.
    
    This example demonstrates analyzing multiple source/binary
    pairs in a batch operation.
    """
    print("\nExample 4: Batch Analysis")
    print("-" * 30)
    
    # Define files to analyze
    files_to_analyze = [
        ("module1.c", "module1.o"),
        ("module2.c", "module2.o"),
        ("main.c", "main"),
    ]
    
    # Create analyzer
    analyzer = LineTableAnalyzer(timeout_seconds=15)
    
    # Analyze each file pair
    results = []
    for source_name, binary_name in files_to_analyze:
        source_file = Path(source_name)
        binary_file = Path(binary_name)
        
        print(f"\nAnalyzing {source_name}...")
        result = analyzer.analyze(source_file, binary_file)
        results.append(result)
        
        if result.success and result.report_data:
            print(f"  ✓ Success rate: {result.report_data.success_rate:.1f}%")
        else:
            print(f"  ✗ Failed: {result.error_message}")
    
    # Summary
    successful = sum(1 for r in results if r.success)
    print(f"\nBatch complete: {successful}/{len(results)} successful")


def example_custom_verification():
    """
    Example 5: Custom verification workflow.
    
    This example shows how to implement custom verification logic
    for special cases.
    """
    print("\nExample 5: Custom Verification")
    print("-" * 30)
    
    source_file = Path("special_case.c")
    binary_file = Path("special_case")
    
    # Parse and get line numbers
    parser = DwarfLineTableParser(binary_file)
    parser.parse()
    line_numbers = parser.get_line_numbers(str(source_file))
    
    # Custom verification with retries
    verifier = LLDBLineVerifier(timeout_seconds=10)
    max_retries = 3
    
    for attempt in range(max_retries):
        print(f"\nVerification attempt {attempt + 1}/{max_retries}")
        results = verifier.verify_lines(source_file, binary_file, line_numbers)
        
        # Check if we need to retry
        error_count = sum(1 for r in results.values() 
                         if r.result == VerificationResult.ERROR)
        
        if error_count == 0:
            print("  ✓ All lines verified successfully!")
            break
        else:
            print(f"  ⚠ {error_count} errors detected")
            
            if attempt < max_retries - 1:
                print("  Retrying...")
                # Could add delay or change settings here
    
    # Generate report for final results
    report_gen = VerificationReportGenerator()
    report_data = report_gen.generate_report(
        results,
        binary_name=binary_file.name,
        source_file_path=source_file
    )
    
    print(f"\nFinal success rate: {report_data.success_rate:.1f}%")


def example_analysis_with_filters():
    """
    Example 6: Analysis with line filtering.
    
    This example demonstrates filtering which lines to verify
    based on custom criteria.
    """
    print("\nExample 6: Filtered Analysis")
    print("-" * 30)
    
    source_file = Path("filtered_test.c")
    binary_file = Path("filtered_test")
    
    # Parse DWARF info
    parser = DwarfLineTableParser(binary_file)
    parser.parse()
    
    # Get all line numbers
    all_lines = parser.get_line_numbers(str(source_file))
    print(f"Total lines with debug info: {len(all_lines)}")
    
    # Filter lines (example: only verify lines 10-50)
    filtered_lines = [line for line in all_lines if 10 <= line <= 50]
    print(f"Lines after filtering: {len(filtered_lines)}")
    
    # Verify filtered lines only
    verifier = LLDBLineVerifier()
    results = verifier.verify_lines(source_file, binary_file, filtered_lines)
    
    # Generate and write report
    report_gen = VerificationReportGenerator()
    report_data = report_gen.generate_report(
        results,
        binary_name=binary_file.name,
        source_file_path=source_file
    )
    
    report_writer = SourceFileReportWriter()
    report_content = report_gen.format_report(report_data)
    
    # Write with custom output directory
    output_dir = Path("filtered_reports")
    report_paths = report_writer.write_report(
        report_content,
        source_file,
        binary_file,
        report_data.metadata,
        output_dir
    )
    
    print(f"\nFiltered analysis complete!")
    print(f"Report written to: {report_paths.modified_source}")


def example_programmatic_access():
    """
    Example 7: Programmatic access to results.
    
    This example shows how to access and process verification
    results programmatically for integration with other tools.
    """
    print("\nExample 7: Programmatic Access")
    print("-" * 30)
    
    # Run analysis
    analyzer = LineTableAnalyzer()
    result = analyzer.analyze(
        Path("integration_test.c"),
        Path("integration_test")
    )
    
    if not result.success:
        print(f"Analysis failed: {result.error_message}")
        return
    
    # Access verification results programmatically
    print("\nProcessing results programmatically:")
    
    # Group results by status
    verified = []
    errors = []
    not_hit = []
    
    for line_num, evidence in result.verification_results.items():
        if evidence.result == VerificationResult.VERIFIED:
            verified.append(line_num)
        elif evidence.result == VerificationResult.ERROR:
            errors.append((line_num, evidence.error_message))
        elif evidence.result == VerificationResult.NOT_HIT:
            not_hit.append(line_num)
    
    # Process verified lines
    print(f"\nVerified lines: {verified}")
    
    # Process errors
    if errors:
        print("\nErrors detected:")
        for line_num, error_msg in errors[:5]:  # Show first 5
            print(f"  Line {line_num}: {error_msg}")
    
    # Export to custom format (e.g., CSV)
    if result.report_data:
        print("\nExporting to CSV...")
        export_to_csv(result.report_data, Path("verification_results.csv"))


def export_to_csv(report_data, csv_path: Path):
    """Helper function to export results to CSV."""
    import csv
    
    with open(csv_path, 'w', newline='') as csvfile:
        fieldnames = ['line_number', 'status', 'address', 'function', 'error']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for line_num, evidence in report_data.results.items():
            writer.writerow({
                'line_number': line_num,
                'status': evidence.result.value,
                'address': evidence.actual_address or '',
                'function': evidence.function_name or '',
                'error': evidence.error_message or ''
            })
    
    print(f"  Exported to: {csv_path}")


def main():
    """Run all examples."""
    examples = [
        example_basic_analysis,
        example_custom_settings,
        example_separate_components,
        example_batch_analysis,
        example_custom_verification,
        example_analysis_with_filters,
        example_programmatic_access
    ]
    
    print("LINE TABLE ANALYSIS EXAMPLES")
    print("=" * 50)
    print("Note: These examples assume you have compiled test programs")
    print("with debug information (e.g., gcc -g test_program.c)")
    print("=" * 50)
    
    for example_func in examples:
        try:
            example_func()
        except Exception as e:
            print(f"\nExample failed: {e}")
            print("(This is expected if test files don't exist)")
        
        print("\n" + "-" * 50)
    
    print("\nAll examples completed!")


if __name__ == "__main__":
    main()