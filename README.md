# filewalker

*Inspired by [PowerWalk](https://github.com/stretchr/powerwalk)*

Concurrent filesystem traversal with logging.

Let me know if you find a bug or faster method.

## Benchmark Results

### System Information

- **OS**: macOS (Darwin)
- **Architecture**: arm64
- **CPU**: Apple M3 Pro
- **Package**: `github.com/TFMV/filewalker`

### Performance Comparison

| Benchmark                                   | Iterations | Time per Operation (ns/op) | Memory Usage (B/op) | Allocations (allocs/op) |
|---------------------------------------------|------------|----------------------------|----------------------|--------------------------|
| **Standard `filepath.Walk`**                | 1          | 3,056,450,625              | 4,217,792            | 26,148                   |
| **Concurrent `filewalker` (2 workers)**     | 1          | 1,480,638,334              | 4,684,624            | 26,227                   |
| **Concurrent `filewalker` (4 workers)**     | 2          | 739,280,271                | 4,684,408            | 26,213                   |
| **Concurrent `filewalker` (8 workers)**     | 3          | 366,615,250                | 4,685,226            | 26,215                   |

## Usage

### As a Library

```go
import "github.com/TFMV/filewalker"
// Use default concurrency
err := filewalker.Walk(root, walkFn)
// Or specify concurrent workers
err := filewalker.WalkLimit(ctx, root, walkFn, workers)
```

### As a CLI

Basic usage:

```bash
filewalker --workers=8 --format=json /path/to/scan
```

Available options:

- `-w, --workers`: Number of concurrent workers (default: 4)
- `--format`: Output format (text|json)
- `-v, --verbose`: Enable verbose logging
- `--silent`: Disable all output except errors
- `-h, --help`: Show help message
- `--version`: Show version

Verbose scan with default (4) workers:

```bash
filewalker -v /home/user/projects
```

Silent scan with 16 workers:

```bash
filewalker --silent --workers=16 /path/to/scan
```

## Author

This package is developed by [TFMV](https://github.com/TFMV).

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
