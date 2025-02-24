# filewalker

A high-performance concurrent filesystem traversal library with filtering, progress monitoring, and CLI support.

## 🚀 Features

- Concurrency: Parallel traversal for massive speed improvements over filepath.Walk.
- Real-Time Progress: Live tracking of processed files, directories, and throughput.
- Filtering: Control file selection based on size, modification time, patterns, and more.
- Error Handling: Configurable behavior for skipping, continuing, or stopping on errors.
- Symlink Handling: Options to follow, ignore, or report symbolic links.
- Logging: Structured logging via zap with adjustable verbosity.

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

## 🏗 Architecture

### Performance Design

Filewalker achieves high performance through several key architectural decisions.

### 📊 Architecture Diagram

```mermaid
graph TB
    subgraph Input
        Root[Root Directory]
    end

    subgraph Producer
        Walk[filepath.Walk]
        Cache[Directory Cache]
        Walk --> Cache
    end

    subgraph TaskQueue
        Channel[Buffered Channel<br>size=workers]
    end

    subgraph WorkerPool
        W1[Worker 1]
        W2[Worker 2]
        W3[Worker 3]
        WN[Worker N]
    end

    subgraph Statistics
        Atomic[Atomic Counters]
        Progress[Progress Monitor]
        Speed[Speed Calculator]
    end

    subgraph ErrorHandling
        ErrContinue[Continue Mode]
        ErrStop[Stop Mode]
        ErrSkip[Skip Mode]
        ErrCollector[Error Collector]
    end

    Root --> Walk
    Cache --> Channel
    Channel --> W1
    Channel --> W2
    Channel --> W3
    Channel --> WN
    
    W1 --> Atomic
    W2 --> Atomic
    W3 --> Atomic
    WN --> Atomic
    
    Atomic --> Progress
    Progress --> Speed
    
    W1 --> ErrCollector
    W2 --> ErrCollector
    W3 --> ErrCollector
    WN --> ErrCollector
    
    ErrCollector --> ErrContinue
    ErrCollector --> ErrStop
    ErrCollector --> ErrSkip

    classDef default fill:#f9f,stroke:#333,stroke-width:2px;
    classDef producer fill:#bbf,stroke:#333,stroke-width:2px;
    classDef queue fill:#bfb,stroke:#333,stroke-width:2px;
    classDef workers fill:#fbf,stroke:#333,stroke-width:2px;
    classDef stats fill:#ffb,stroke:#333,stroke-width:2px;
    classDef errors fill:#fbb,stroke:#333,stroke-width:2px;

    class Root default;
    class Walk,Cache producer;
    class Channel queue;
    class W1,W2,W3,WN workers;
    class Atomic,Progress,Speed stats;
    class ErrContinue,ErrStop,ErrSkip,ErrCollector errors;
```

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
