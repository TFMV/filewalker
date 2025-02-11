# filewalker

A high-performance concurrent filesystem traversal library with filtering, progress monitoring, and CLI support.

## Features

- **Concurrent Processing**: Configurable worker pool for parallel file traversal
- **Progress Monitoring**: Real-time statistics including files processed, bytes read, and errors
- **Flexible Filtering**:
  - File size limits
  - Modification time ranges
  - Pattern matching
  - Directory exclusions
  - File type filtering
- **Error Handling Modes**:
  - Continue: Skip errors and continue processing
  - Stop: Halt on first error
  - Skip: Skip problematic files/directories
- **Symlink Handling**:
  - Follow symbolic links
  - Ignore symbolic links
  - Report but don't follow
- **Memory Management**: Configurable soft and hard memory limits
- **Structured Logging**: Built-in zap logger support
- **Context Support**: Cancellation and timeout support

## Benchmark Results

### System Information

- **OS**: macOS (Darwin)
- **Architecture**: arm64
- **CPU**: Apple M3 Pro
- **Package**: `github.com/TFMV/filewalker`

### Performance Comparison

| Benchmark                                   | Iterations | Time (ns/op)    | Memory (B/op) | Allocs (allocs/op) |
|---------------------------------------------|------------|-----------------|---------------|-------------------|
| **Standard `filepath.Walk`**                | 1          | 3,056,450,625  | 4,217,792     | 26,148           |
| **Concurrent `filewalker` (2 workers)**     | 1          | 1,480,638,334  | 4,684,624     | 26,227           |
| **Concurrent `filewalker` (4 workers)**     | 2          | 739,280,271    | 4,684,408     | 26,213           |
| **Concurrent `filewalker` (8 workers)**     | 3          | 366,615,250    | 4,685,226     | 26,215           |

## Usage

### As a Library

Basic usage:

```go
import "github.com/TFMV/filewalker"

// Simple walk with default settings
err := filewalker.Walk(root, walkFn)

// Walk with concurrent workers
err := filewalker.WalkLimit(ctx, root, walkFn, workers)

// Walk with progress monitoring
err := filewalker.WalkLimitWithProgress(ctx, root, walkFn, workers, progressFn)

// Walk with filtering
err := filewalker.WalkLimitWithFilter(ctx, root, walkFn, workers, filterOpts)

// Walk with comprehensive options
opts := filewalker.WalkOptions{
    ErrorHandling:   filewalker.ErrorHandlingContinue,
    Filter: filewalker.FilterOptions{
        MinSize:     1024,
        Pattern:     "*.go",
        ExcludeDir:  []string{"vendor", "node_modules"},
        IncludeTypes: []string{".go", ".mod"},
    },
    Progress:      progressCallback,
    Logger:        zapLogger,
    BufferSize:    100,
    SymlinkHandling: filewalker.SymlinkIgnore,
}
err := filewalker.WalkLimitWithOptions(ctx, root, walkFn, opts)
```

### As a CLI

Basic usage:

```bash
filewalker [options] <path>
```

Available options:

- `-w, --workers`: Number of concurrent workers [default: CPU cores]
- `--format`: Output format (text|json) [default: text]
- `-v, --verbose`: Enable verbose logging
- `--silent`: Disable all output except errors
- `--min-size`: Minimum file size to process
- `--max-size`: Maximum file size to process
- `--pattern`: File pattern to match
- `--exclude-dir`: Directories to exclude (comma-separated)
- `--follow-symlinks`: Follow symbolic links [default: false]
- `--progress`: Show progress updates
- `--error-mode`: Error handling mode (continue|stop|skip) [default: continue]
- `-h, --help`: Show help message
- `--version`: Show version

Examples:

```bash
# Scan with 8 workers and JSON output
filewalker -w 8 --format=json /path/to/scan

# Verbose scan excluding certain directories
filewalker -v --exclude-dir="vendor,node_modules" /path/to/scan

# Process only Go files with progress updates
filewalker --pattern="*.go" --progress /path/to/scan
```

## Author

This package is developed by [TFMV](https://github.com/TFMV).

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
