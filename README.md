# filewalker

Concurrent filesystem traversal with logging.

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

## Author

This package is developed by [TFMV](https://github.com/TFMV).

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
