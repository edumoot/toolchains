# DWARF Line Table Analyzer

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![LLVM](https://img.shields.io/badge/LLVM-17.0+-green.svg)](https://llvm.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive tool for analyzing and verifying DWARF debug line table information in compiled binaries. This project helps developers identify and diagnose issues with debug information mapping between source code and compiled binaries.

## Features

- **DWARF Line Table Parsing**: Extract and analyze debug line information from compiled binaries
- **Dynamic Verification**: Use LLDB to verify that line numbers map correctly during execution
- **Comprehensive Reporting**: Generate detailed reports with statistics and recommendations
- **Source Code Integration**: Write verification reports directly as comments in source files
- **Modular Architecture**: Use components separately or together for custom workflows
- **Batch Processing**: Analyze multiple files in automated workflows
- **LLVM Version Tracking**: Reports include LLVM version information for reproducibility

## Requirements

- Python 3.8 or higher
- LLVM toolchain (including `llvm-dwarfdump` and `lldb`)
- C/C++ binaries compiled with debug information (`-g` flag)

## Quick Start

### Installation

1. Clone the repository:
```bash
git clone https://github.com/edumoot/lines.git
cd lines
```

2. Ensure LLVM tools are installed:
```bash
# Ubuntu/Debian
sudo apt-get install llvm lldb

# macOS with Homebrew
brew install llvm

# Verify installation
llvm-config --version
lldb --version
```

### Basic Usage

Analyze a simple C program:

```bash
# Compile your program with debug info and an optimization level
clang -g -O3 example.c -o example

# Run the analyzer
python line_analyzer.py example.c example
```

## Documentation

### Command Line Interface

```bash
python line_analyzer.py [OPTIONS] source_file binary_file

Options:
  --timeout SECONDS        Timeout for line verification (default: 30)
  --max-iterations N       Maximum verification iterations (default: auto)
  --comment-style {block,line}  Comment style for reports (default: block)
  --no-backup             Don't create backup of original source file
  --no-metadata           Exclude metadata from reports
  --output-dir DIR        Directory for standalone report files
  --verbose               Enable verbose output
```

### Examples

#### Basic Analysis
```bash
python line_analyzer.py src/main.c build/main
```

#### Analysis with Custom Settings
```bash
python line_analyzer.py \
    --timeout 60 \
    --comment-style line \
    --output-dir reports/ \
    src/complex.cpp build/complex
```

#### Batch Processing
```bash
for src in src/*.c; do
    binary="${src%.c}"
    python line_analyzer.py "$src" "build/$(basename $binary)"
done
```

## Architecture

The project follows a modular, object-oriented design:

```
line-table-analyzer/
├── models.py              # Core data structures and types
├── line_verifier.py       # DWARF parsing and LLDB verification
├── report_generator.py    # Report generation and formatting
├── line_table_analyzer.py # Main orchestrator and CLI
└── example_usage.py       # Usage examples and patterns
```

### Key Components

1. **DwarfLineTableParser**: Parses DWARF debug information using `llvm-dwarfdump`
2. **LLDBLineVerifier**: Verifies line mappings by setting breakpoints and running the binary
3. **VerificationReportGenerator**: Creates structured reports from verification results
4. **SourceFileReportWriter**: Writes reports as comments in source files
5. **LineTableAnalyzer**: Orchestrates the complete analysis workflow

## Report Format

The analyzer generates comprehensive reports including:

- **Executive Summary**: Overview of verification results
- **Verified Line Numbers**: List of successfully verified lines
- **Detailed Results**: Line-by-line verification status
- **Analysis Recommendations**: Suggestions for improving debug information
- **LLVM Version**: Version information for reproducibility

### Example Report

```c
/*
 * ==============================================================================
 * DWARF LINE TABLE VERIFICATION REPORT
 * ==============================================================================
 * 
 * Report Metadata:
 * ------------------
 * Generated: 2024-01-15 14:32:45
 * Binary Name: example
 * LLVM Version: 17.0.6
 * Source File: example.c
 * 
 * Executive Summary:
 * ------------------
 * Total lines tested: 42
 * Successfully verified: 38
 * Invalid breakpoints: 2
 * Errors: 1
 * Not hit: 1
 * Success rate: 90.5%
 * 
 * Verified Line Numbers:
 * -----------------------
 *    10,   12,   13,   15,   18,   20,   22,   25,   27,   30
 *    32,   35,   38,   40,   42,   45,   48,   50,   52,   55
 *    ...
 */
```

## Programmatic Usage

The analyzer can be used as a library in your own Python scripts:

```python
from pathlib import Path
from line_analyzer import LineTableAnalyzer

# Create analyzer
analyzer = LineTableAnalyzer(
    timeout_seconds=45,
    comment_style="block",
    include_metadata=True
)

# Run analysis
result = analyzer.analyze(
    source_file=Path("src/main.c"),
    binary_file=Path("build/main"),
    output_dir=Path("reports/")
)

# Access results
if result.success:
    print(f"Verified {result.verified_count} lines")
    print(f"Success rate: {result.report_data.success_rate:.1f}%")
```

### Using Components Separately

```python
from line_verifier import DwarfLineTableParser, LLDBLineVerifier
from line_report_generator import VerificationReportGenerator

# Parse DWARF information
parser = DwarfLineTableParser(Path("binary"))
parser.parse()
line_numbers = parser.get_line_numbers("source.c")

# Verify specific lines
verifier = LLDBLineVerifier(timeout_seconds=30)
results = verifier.verify_lines(
    Path("source.c"),
    Path("binary"),
    line_numbers[:10]  # Verify first 10 lines only
)

# Generate custom report
generator = VerificationReportGenerator()
report_data = generator.generate_report(
    results,
    binary_name="binary",
    llvm_version="17.0.6"
)
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Coding Standards

- Follow PEP 8 style guidelines
- Add type hints to all function signatures
- Include docstrings for all classes and methods
- Write unit tests for new functionality

## Troubleshooting

### Common Issues

1. **"LLDB Python interface not found"**
   - Ensure LLDB is installed and accessible in PATH
   - Try running `lldb -P` to verify Python support

2. **"No line numbers found in binary"**
   - Verify the binary was compiled with `-g` flag
   - Check that source paths match between compilation and analysis

3. **"Breakpoint creation failed"**
   - Line might be optimized out - try compiling with `-O0`
   - Ensure source file paths are correct

### Debug Tips

- Use `--verbose` flag for detailed output
- Check generated `.backup_*` files if source is modified incorrectly
- Examine JSON summary files for detailed verification data

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- LLVM Project for excellent debugging tools
- DWARF Debugging Standard contributors
- Python community for the amazing ecosystem

## References

- [DWARF Debugging Standard](http://www.dwarfstd.org/)
- [LLVM Documentation](https://llvm.org/docs/)
- [LLDB Python API Reference](https://lldb.llvm.org/python_api.html)

---

**Note**: This tool is designed for debugging and development purposes. Always review generated reports before committing modified source files.