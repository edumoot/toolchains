#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Line verification module for DWARF line table analysis.

This module provides functionality to parse DWARF debug information
from binaries and verify line numbers using LLDB debugger.
"""

import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from line_models import (
    BinaryParsingError,
    FileTableEntry,
    LineTableEntry,
    LineVerificationEvidence,
    VerificationError,
    VerificationResult
)


class DwarfLineTableParser:
    """
    Parses DWARF debug line information from binaries.
    
    This class uses llvm-dwarfdump to extract and parse line table
    information from compiled binaries with debug symbols.
    
    Attributes:
        binary_path: Path to the binary file to analyze
    """
    
    def __init__(self, binary_path: Path):
        """
        Initialize the parser with a binary file path.
        
        Args:
            binary_path: Path to the binary file containing DWARF info
            
        Raises:
            BinaryParsingError: If binary file doesn't exist
        """
        if not binary_path.exists():
            raise BinaryParsingError(f"Binary file not found: {binary_path}")
        
        self.binary_path = binary_path
        self._file_table: Dict[int, FileTableEntry] = {}
        self._line_entries: List[LineTableEntry] = []
        self._parsed = False
    
    def parse(self) -> None:
        """
        Parse DWARF debug line information from the binary.
        
        Uses llvm-dwarfdump to extract line table information and
        parses it into structured data.
        
        Raises:
            BinaryParsingError: If parsing fails
        """
        try:
            # Run llvm-dwarfdump
            output = self._run_dwarfdump()
            
            # Parse the output
            self._parse_debug_line(output)
            self._parsed = True
            
        except subprocess.CalledProcessError as e:
            raise BinaryParsingError(
                f"Failed to run llvm-dwarfdump on {self.binary_path}: {e}"
            )
        except Exception as e:
            raise BinaryParsingError(
                f"Failed to parse DWARF info from {self.binary_path}: {e}"
            )
    
    def get_line_numbers(self, source_file: str) -> List[int]:
        """
        Extract line numbers for a specific source file.
        
        Args:
            source_file: Name or path of the source file
            
        Returns:
            Sorted list of line numbers that have debug info
            
        Raises:
            BinaryParsingError: If parsing hasn't been done yet
        """
        if not self._parsed:
            self.parse()
        
        # Extract base name for comparison
        source_base = os.path.basename(source_file)
        
        # Collect unique line numbers
        line_numbers: Set[int] = set()
        
        for entry in self._line_entries:
            # Get file info
            file_info = self._file_table.get(entry.file_index)
            if not file_info:
                continue
            
            # Check if this entry is for our source file
            file_name = file_info.name
            if source_base in file_name and entry.is_statement:
                line_numbers.add(entry.line)
        
        return sorted(line_numbers)
    
    def get_file_table(self) -> Dict[int, FileTableEntry]:
        """
        Get the parsed file table.
        
        Returns:
            Dictionary mapping file indices to file entries
        """
        if not self._parsed:
            self.parse()
        return self._file_table.copy()
    
    def get_line_entries(self) -> List[LineTableEntry]:
        """
        Get all parsed line table entries.
        
        Returns:
            List of line table entries
        """
        if not self._parsed:
            self.parse()
        return self._line_entries.copy()
    
    def _run_dwarfdump(self) -> str:
        """
        Execute llvm-dwarfdump to extract debug line information.
        
        Returns:
            Raw output from llvm-dwarfdump
            
        Raises:
            subprocess.CalledProcessError: If dwarfdump fails
        """
        cmd = ["llvm-dwarfdump", "--debug-line", str(self.binary_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    
    def _parse_debug_line(self, output: str) -> None:
        """
        Parse the raw dwarfdump output into structured data.
        
        Args:
            output: Raw text output from llvm-dwarfdump
        """
        # Regular expressions for parsing
        file_table_pattern = re.compile(r'file_names\[\s*(\d+)\]:')
        file_name_pattern = re.compile(r'name: "(.+)"')
        dir_index_pattern = re.compile(r'dir_index: (\d+)')
        line_entry_pattern = re.compile(
            r'0x([0-9a-f]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)'
        )
        
        lines = output.split('\n')
        parsing_file_table = False
        current_file_index = None
        
        for line in lines:
            # Check for file table entry
            if line.startswith("file_names["):
                parsing_file_table = True
                file_match = file_table_pattern.search(line)
                if file_match:
                    current_file_index = int(file_match.group(1))
                    self._file_table[current_file_index] = FileTableEntry(
                        index=current_file_index,
                        name="",
                        dir_index=0
                    )
            
            # Parse file table details
            elif parsing_file_table and current_file_index is not None:
                name_match = file_name_pattern.search(line)
                if name_match:
                    self._file_table[current_file_index].name = name_match.group(1)
                
                dir_match = dir_index_pattern.search(line)
                if dir_match:
                    self._file_table[current_file_index].dir_index = int(dir_match.group(1))
                    parsing_file_table = False
            
            # Check for start of line table
            elif line.startswith("Address"):
                parsing_file_table = False
            
            # Parse line table entries
            else:
                line_match = line_entry_pattern.search(line)
                if line_match:
                    address, line_num, column, file_num, isa, discriminator, flags = line_match.groups()
                    
                    entry = LineTableEntry(
                        address=int(address, 16),
                        line=int(line_num),
                        column=int(column),
                        file_index=int(file_num),
                        isa=int(isa),
                        discriminator=int(discriminator),
                        flags=flags.strip()
                    )
                    self._line_entries.append(entry)


class LLDBLineVerifier:
    """
    Verifies line numbers using LLDB debugger.
    
    This class sets breakpoints at specified line numbers and runs
    the binary under LLDB to verify which lines are actually executed.
    
    Attributes:
        timeout_seconds: Maximum time to wait for verification
        max_iterations: Maximum number of continue operations
    """
    
    def __init__(self, timeout_seconds: int = 30, max_iterations: Optional[int] = None):
        """
        Initialize the verifier with timeout and iteration limits.
        
        Args:
            timeout_seconds: Maximum seconds to wait for verification
            max_iterations: Maximum continue operations (None for automatic)
        """
        self.timeout_seconds = timeout_seconds
        self.max_iterations = max_iterations
        self._lldb = None
        self._load_lldb_interface()
    
    def verify_lines(self, source_file: Path, binary_file: Path,
                    line_numbers: List[int]) -> Dict[int, LineVerificationEvidence]:
        """
        Verify line numbers by setting breakpoints and running the binary.
        
        This method sets breakpoints at each specified line number,
        runs the binary under LLDB, and tracks which breakpoints are hit.
        
        Args:
            source_file: Path to the source file
            binary_file: Path to the binary file
            line_numbers: List of line numbers to verify
            
        Returns:
            Dictionary mapping line numbers to verification evidence
            
        Raises:
            VerificationError: If verification setup fails
        """
        # Validate inputs
        if not source_file.exists():
            raise VerificationError(f"Source file not found: {source_file}")
        
        if not binary_file.exists():
            raise VerificationError(f"Binary file not found: {binary_file}")
        
        # Get absolute paths for consistency
        source_file_abs = source_file.absolute()
        binary_file_abs = binary_file.absolute()
        
        # Initialize results
        results = {
            line_num: LineVerificationEvidence(
                line_number=line_num,
                result=VerificationResult.NOT_HIT,
                source_file=str(source_file_abs)
            )
            for line_num in line_numbers
        }
        
        # Perform verification
        try:
            self._verify_with_lldb(
                source_file_abs,
                binary_file_abs,
                line_numbers,
                results
            )
        except Exception as e:
            # Mark remaining unverified lines as errors
            for line_num in line_numbers:
                if results[line_num].result == VerificationResult.NOT_HIT:
                    results[line_num].result = VerificationResult.ERROR
                    results[line_num].error_message = str(e)
        
        return results
    
    def _load_lldb_interface(self) -> None:
        """
        Load the LLDB Python interface.
        
        Raises:
            VerificationError: If LLDB interface cannot be loaded
        """
        try:
            # Get LLDB Python path
            lldb_executable = "lldb"
            args = [lldb_executable, '-P']
            pythonpath = subprocess.check_output(
                args, stderr=subprocess.STDOUT
            ).rstrip().decode('utf-8')
            
            # Add to Python path and import
            sys.path.append(pythonpath)
            import importlib
            self._lldb = importlib.import_module('lldb')
            
        except subprocess.CalledProcessError as e:
            raise VerificationError(
                f"Error loading LLDB Python interface: {e.output.decode('utf-8')}"
            )
        except Exception as e:
            raise VerificationError(f"Failed to load LLDB: {e}")
    
    def _verify_with_lldb(self, source_file: Path, binary_file: Path,
                         line_numbers: List[int],
                         results: Dict[int, LineVerificationEvidence]) -> None:
        """
        Perform the actual verification using LLDB.
        
        Args:
            source_file: Absolute path to source file
            binary_file: Absolute path to binary file
            line_numbers: Line numbers to verify
            results: Results dictionary to update
        """
        debugger = None
        target = None
        process = None
        active_breakpoints = {}  # breakpoint_id -> (bp_object, line_number)
        
        try:
            # Create debugger
            debugger = self._lldb.SBDebugger.Create()
            debugger.SetAsync(False)
            
            # Create target
            target = debugger.CreateTargetWithFileAndArch(
                str(binary_file),
                self._lldb.LLDB_ARCH_DEFAULT
            )
            
            if not target.IsValid():
                raise VerificationError(f"Could not create target for {binary_file}")
            
            # Set breakpoints
            self._set_breakpoints(
                target, source_file, line_numbers, results, active_breakpoints
            )
            
            if not active_breakpoints:
                return  # No valid breakpoints to verify
            
            # Launch process
            process = target.LaunchSimple(None, None, os.getcwd())
            if not process.IsValid():
                raise VerificationError(f"Could not launch process for {binary_file}")
            
            # Check for immediate exit
            if process.GetState() == self._lldb.eStateExited:
                exit_code = process.GetExitStatus()
                error_msg = f"Process exited immediately with code {exit_code}"
                for line_num in line_numbers:
                    if results[line_num].result == VerificationResult.NOT_HIT:
                        results[line_num].result = VerificationResult.ERROR
                        results[line_num].error_message = error_msg
                return
            
            # Run verification loop
            self._run_verification_loop(
                process, target, source_file, results, active_breakpoints
            )
            
        finally:
            # Clean up resources
            self._cleanup_lldb_resources(process, target, debugger, active_breakpoints)
    
    def _set_breakpoints(self, target, source_file: Path, line_numbers: List[int],
                        results: Dict[int, LineVerificationEvidence],
                        active_breakpoints: Dict[int, Tuple]) -> None:
        """Set breakpoints for all specified line numbers."""
        for line_number in line_numbers:
            bp = target.BreakpointCreateByLocation(str(source_file), line_number)
            
            if bp.IsValid():
                active_breakpoints[bp.GetID()] = (bp, line_number)
                results[line_number].breakpoint_id = bp.GetID()
            else:
                results[line_number].result = VerificationResult.INVALID_BREAKPOINT
                results[line_number].error_message = (
                    f"Unable to set breakpoint at line {line_number} "
                    f"(possible causes: line optimized out, no executable code)"
                )
    
    def _run_verification_loop(self, process, target, source_file: Path,
                              results: Dict[int, LineVerificationEvidence],
                              active_breakpoints: Dict[int, Tuple]) -> None:
        """Run the main verification loop."""
        max_iterations = self.max_iterations or (len(active_breakpoints) * 3)
        iteration_count = 0
        start_time = time.time()
        
        while (process.GetState() == self._lldb.eStateStopped and
               iteration_count < max_iterations and
               time.time() - start_time < self.timeout_seconds and
               active_breakpoints):
            
            iteration_count += 1
            thread = process.GetSelectedThread()
            
            if thread.GetStopReason() == self._lldb.eStopReasonBreakpoint:
                # Process breakpoint hit
                self._process_breakpoint_hit(
                    thread, target, source_file, results, active_breakpoints
                )
            
            # Continue execution
            process.Continue()
        
        # Handle loop termination
        self._handle_loop_termination(
            start_time, iteration_count, max_iterations, results
        )
    
    def _process_breakpoint_hit(self, thread, target, source_file: Path,
                               results: Dict[int, LineVerificationEvidence],
                               active_breakpoints: Dict[int, Tuple]) -> None:
        """Process a breakpoint hit."""
        stop_reason_data = thread.GetStopReasonDataAtIndex(0)  # Breakpoint ID
        
        if stop_reason_data not in active_breakpoints:
            return
        
        bp_object, line_number = active_breakpoints[stop_reason_data]
        
        # Get execution context
        frame = thread.GetFrameAtIndex(0)
        line_entry = frame.GetLineEntry()
        actual_line = line_entry.GetLine()
        
        # Get file information
        file_spec = line_entry.GetFileSpec()
        actual_file = f"{file_spec.GetDirectory()}/{file_spec.GetFilename()}" \
                     if file_spec.GetDirectory() else file_spec.GetFilename()
        actual_filename = file_spec.GetFilename()
        
        # Get function information
        function = frame.GetFunction()
        function_name = function.GetName() if function.IsValid() else "unknown"
        
        # Update evidence
        results[line_number].actual_line_hit = actual_line
        results[line_number].actual_file_hit = actual_file
        results[line_number].function_name = function_name
        
        # Verify line match
        expected_filename = os.path.basename(str(source_file))
        
        if actual_line == line_number and self._files_match(actual_filename, expected_filename):
            # Success
            results[line_number].result = VerificationResult.VERIFIED
            results[line_number].hit_count = bp_object.GetHitCount()
            results[line_number].hit_timestamp = time.time()
            results[line_number].actual_address = f"0x{frame.GetPC():x}"
        else:
            # Mismatch
            if actual_line != line_number:
                results[line_number].result = VerificationResult.ERROR
                results[line_number].error_message = (
                    f"Line mismatch: hit line {actual_line} in {actual_filename}, "
                    f"expected line {line_number}"
                )
            else:
                results[line_number].result = VerificationResult.ERROR
                results[line_number].error_message = (
                    f"File mismatch: hit {actual_filename}, expected {expected_filename}"
                )
        
        # Remove processed breakpoint
        target.BreakpointDelete(stop_reason_data)
        del active_breakpoints[stop_reason_data]
    
    def _files_match(self, actual_filename: str, expected_filename: str) -> bool:
        """Check if two filenames match (handles various naming conventions)."""
        return (actual_filename == expected_filename or
                actual_filename in expected_filename or
                expected_filename in actual_filename)
    
    def _handle_loop_termination(self, start_time: float, iteration_count: int,
                                max_iterations: int,
                                results: Dict[int, LineVerificationEvidence]) -> None:
        """Handle verification loop termination."""
        elapsed_time = time.time() - start_time
        
        if elapsed_time >= self.timeout_seconds:
            error_msg = f"Verification timeout after {self.timeout_seconds}s"
            for evidence in results.values():
                if evidence.result == VerificationResult.NOT_HIT:
                    evidence.result = VerificationResult.ERROR
                    evidence.error_message = error_msg
        
        elif iteration_count >= max_iterations:
            error_msg = f"Iteration limit reached ({max_iterations} iterations)"
            for evidence in results.values():
                if evidence.result == VerificationResult.NOT_HIT:
                    evidence.result = VerificationResult.ERROR
                    evidence.error_message = error_msg
    
    def _cleanup_lldb_resources(self, process, target, debugger,
                               active_breakpoints: Dict[int, Tuple]) -> None:
        """Clean up LLDB resources."""
        cleanup_errors = []
        
        # Clean up process
        try:
            if process and process.IsValid():
                if process.GetState() != self._lldb.eStateExited:
                    process.Kill()
                process.Destroy()
        except Exception as e:
            cleanup_errors.append(f"Process cleanup error: {e}")
        
        # Clean up breakpoints
        try:
            if target and target.IsValid() and active_breakpoints:
                for bp_id in list(active_breakpoints.keys()):
                    try:
                        target.BreakpointDelete(bp_id)
                    except Exception as e:
                        cleanup_errors.append(f"Breakpoint {bp_id} cleanup error: {e}")
        except Exception as e:
            cleanup_errors.append(f"Breakpoint cleanup error: {e}")
        
        # Clean up target
        try:
            if target and target.IsValid() and debugger:
                debugger.DeleteTarget(target)
        except Exception as e:
            cleanup_errors.append(f"Target cleanup error: {e}")
        
        # Clean up debugger
        try:
            if debugger:
                self._lldb.SBDebugger.Destroy(debugger)
        except Exception as e:
            cleanup_errors.append(f"Debugger cleanup error: {e}")
        
        # Report cleanup errors if any
        if cleanup_errors:
            print("Cleanup warnings:")
            for error in cleanup_errors:
                print(f"  - {error}")