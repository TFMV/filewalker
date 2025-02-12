# filewalker

A high-performance concurrent filesystem traversal library with filtering, progress monitoring, and CLI support.

## 🚀 Features

Who doesn't need to walk a directory tree using a producer-consumer model with industrial-strength error handling, configurable logging, and progress monitoring?

### 🔄 **Fast Parallel Processing**

- Up to **8x faster** than `filepath.Walk`
- Configurable **worker pool** for parallel traversal
- Automatic **CPU core detection** for efficiency

### 📊 **Real-Time Progress Monitoring**

- Tracks **files, directories, and bytes processed**
- **Processing speed (MB/s) & average file size**
- Live **error count & elapsed time**
- Customizable **progress callback**

### 🔍 **Advanced Filtering**

- File size limits: `MinSize`, `MaxSize`
- Modification time ranges: `ModifiedAfter`, `ModifiedBefore`
- **Glob pattern matching**: `Pattern: "*.go"`
- Directory exclusion: `ExcludeDir: []string{"vendor"}`
- File type filtering: `IncludeTypes: []string{".log", ".csv"}`
- Parent directory filtering for deeper control

### ⚠️ **Robust Error Handling**

| Mode    | Behavior |
|---------|--------------------------------------|
| **Continue** | Skip errors, process remaining files. |
| **Stop**     | Halt immediately on first error. |
| **Skip**     | Ignore problematic files & directories. |

Errors are collected using `errors.Join()`, allowing detailed reporting.

### 🔗 **Safe Symlink Handling**

- **Cycle detection** prevents infinite loops
- Configurable: `Follow`, `Ignore`, or `Report`
- **Thread-safe caching** of visited symlinks

### 📝 **Configurable Logging**

- Multiple log levels: **ERROR, WARN, INFO, DEBUG**
- Structured logging with **zap**
- Custom logger support

---

## 📈 Performance

Filewalker significantly outperforms `filepath.Walk` by using concurrent workers.

| Workers  | Time (ns/op)  | Throughput (MB/s) | Speedup |
|----------|-------------|----------------|---------|
| `filepath.Walk` | 3,192,416,229 | ~54 MB/s  | baseline |
| **2 workers**   | 1,557,652,298 | ~110 MB/s | 2.05x faster |
| **4 workers**   | 768,225,614   | ~225 MB/s | 4.21x faster |
| **8 workers**   | 372,091,401   | ~465 MB/s | 8.65x faster |

> Benchmarks run on Apple M2 Pro (10 cores)

### 🛠 **Benchmark Setup**

- **System**: Apple M2 Pro  
- **Test Data**: Directory depth = 5, 20 files per directory  
- **Measurement**: Processing time per file, converted to MB/s  

---

## 🛠 Usage

### 🔹 **Basic Usage**

```go
err := filewalker.Walk(root, walkFn)
progressFn := func(stats filewalker.Stats) {
    fmt.Printf("Files: %d | Speed: %.2f MB/s | Errors: %d | Elapsed: %s\n",
        stats.FilesProcessed,
        stats.SpeedMBPerSec,
        stats.ErrorCount,
        stats.ElapsedTime.Round(time.Millisecond),
    )
}
err := filewalker.WalkLimitWithProgress(ctx, root, walkFn, workers, progressFn)
```

### 🔹 With Progress Monitoring

```go
progressFn := func(stats filewalker.Stats) {
    fmt.Printf("Files: %d | Speed: %.2f MB/s | Errors: %d | Elapsed: %s\n",
        stats.FilesProcessed,
        stats.SpeedMBPerSec,
        stats.ErrorCount,
        stats.ElapsedTime.Round(time.Millisecond),
    )
}
err := filewalker.WalkLimitWithProgress(ctx, root, walkFn, workers, progressFn)
```

### 🔹 With Filtering

```go
filter := filewalker.FilterOptions{
    MinSize: 1 * 1024,          // Min 1 KB
    MaxSize: 100 * 1024 * 1024, // Max 100 MB
    Pattern: "*.go",
    ExcludeDir: []string{"vendor", "node_modules"},
    ModifiedAfter: time.Now().AddDate(-1, 0, 0), // Only files modified in the last year
}
err := filewalker.WalkLimitWithFilter(ctx, root, walkFn, workers, filter)
```

### 🔹 With Logging

```go
filewalker.SetLogger(zap.NewExample())
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

## 🧵 Thread Safety

Filewalker is fully thread-safe, designed for high-performance concurrent traversal:

- Uses atomic counters for real-time statistics tracking.
- Caches results in sync.Map to prevent redundant operations.
- Worker pool model ensures safe concurrent processing.
- Context cancellation cleanly stops all workers.

## 📦 Installation

```bash
go get github.com/TFMV/filewalker
```

## 🏗 Architecture

### Performance Design

Filewalker achieves high performance through several key architectural decisions:

#### 1. Worker Pool Model

```bash
[Directory Tree] → [Task Queue] → [Worker Pool (N workers)] → [Results]
      ↑                 ↑                 ↑
   Producer       Buffered Channel    Concurrent
    (Walk)        (Size = limit)      Processing
```

- **Producer**: A single goroutine recursively walks the directory tree and pushes tasks into the queue.
- **Task Queue**: A buffered channel efficiently controls memory usage and prevents overload.
- **Worker Pool**: N concurrent workers fetch tasks from the queue for parallel processing.
- **Load Balancing**: Dynamic work stealing ensures an even distribution of file-processing tasks.

#### 2. Memory Optimizations

- **Atomic Operations**: Lock-free statistics tracking for performance.
- **Sync.Map Caching**: Thread-safe directory exclusion cache reduces redundant checks.
- **Buffer Control**: Configurable task queue size prevents excessive memory usage.
- **Minimized Allocations**: Reuses walkArgs structs to reduce GC overhead.

#### 3. Concurrency Control

```go
type walkArgs struct {
    path string
    info os.FileInfo
    err  error
}

// Worker Pool Implementation
for i := 0; i < limit; i++ {
    go worker(tasks <-chan walkArgs)
}
```

- Workers efficiently pull tasks from the queue and process files concurrently.
- The number of workers is configurable, scaling with available CPU cores.
- Graceful shutdown ensures clean termination when walking is canceled.

#### 4. Error Management

- **Non-blocking**: Errors don't stop other workers
- **Aggregation**: Combined using errors.Join()
- **Context**: Graceful cancellation support

#### 5. Progress Tracking

```bash
[Workers] → [Atomic Counters] → [Stats Aggregator] → [Progress Callback]
    ↑            ↑                     ↑                    ↑
 Updates    Thread-safe         500ms Intervals      User Interface
```

- Workers update atomic counters in real time.
- A stats aggregator collects periodic updates every 500ms.
- Progress is reported via a customizable callback function.
- Users can monitor:
  - Files Processed
  - Processing Speed (MB/s)
  - Elapsed Time
  - Error Count

## License

MIT License. See the [LICENSE](LICENSE) file for details.

## Author

Built with ❤️ by [TFMV](https://github.com/TFMV)
