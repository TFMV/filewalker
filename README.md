# filewalker

A high-performance concurrent filesystem traversal library with filtering, progress monitoring, and CLI support.

## Features

- **Concurrent Processing**:
  - Configurable worker pool for parallel traversal
  - Up to 8x faster than standard `filepath.Walk`
  - Automatic CPU core detection

- **Advanced Statistics**:
  - Files and directories processed
  - Total bytes processed
  - Average file size
  - Processing speed (MB/s)
  - Error counting
  - Elapsed time tracking

- **Flexible Filtering**:
  - File size limits
  - Modification time ranges
  - Pattern matching
  - Directory exclusions
  - File type filtering
  - Parent directory filtering

- **Error Handling**:
  - Continue: Skip errors and continue
  - Stop: Halt on first error
  - Skip: Skip problematic files/dirs
  - Multiple error collection

- **Symlink Safety**:
  - Cycle detection
  - Follow/ignore/report options
  - Thread-safe caching

- **Configurable Logging**:
  - Multiple log levels (ERROR, WARN, INFO, DEBUG)
  - Structured logging with zap
  - Custom logger support

## Performance

| Configuration | Time (ns/op) | Improvement |
|---------------|--------------|-------------|
| filepath.Walk | 3,382,554,791| baseline |
| 2 workers     | 1,633,955,120| 2.1x faster |
| 4 workers     | 787,345,711  | 4.3x faster |
| 8 workers     | 383,809,679  | 8.8x faster |

_Benchmarks run on Apple M2 Pro, processing directory tree with depth=5, 20 files per directory_

## Usage

### Basic Usage

```go
err := filewalker.Walk(root, walkFn)
```

### With Progress Monitoring

```go
progressFn := func(stats filewalker.Stats) {
    fmt.Printf("Processed: %d files, %.2f MB/s\n", 
        stats.FilesProcessed,
        stats.SpeedMBPerSec)
}
err := filewalker.WalkLimitWithProgress(ctx, root, walkFn, workers, progressFn)
```

### With Filtering

```go
filter := filewalker.FilterOptions{
    MinSize: 1024,
    Pattern: "*.go",
    ExcludeDir: []string{"vendor"},
}
err := filewalker.WalkLimitWithFilter(ctx, root, walkFn, workers, filter)
```

### Full Configuration

```go
opts := filewalker.WalkOptions{
    ErrorHandling: filewalker.ErrorHandlingContinue,
    Filter: filewalker.FilterOptions{
        MinSize: 1024,
        Pattern: "*.go",
        ExcludeDir: []string{"vendor"},
    },
    Progress: progressFn,
    LogLevel: filewalker.LogLevelDebug,
    BufferSize: 100,
    SymlinkHandling: filewalker.SymlinkIgnore,
}
err := filewalker.WalkLimitWithOptions(ctx, root, walkFn, opts)
```

## Thread Safety

All operations are thread-safe, using atomic operations and sync.Map for caching.

## Error Handling

Errors are collected and combined using `errors.Join()`, providing comprehensive error reporting.

## License

MIT License - see LICENSE file
