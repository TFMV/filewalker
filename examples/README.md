# Filewalker Examples

This directory contains example applications demonstrating how to use the Filewalker library.

## Real-time File Monitoring Example

The `monitor_example.go` file demonstrates how to use Filewalker's real-time file monitoring capabilities. This example:

1. Creates a temporary directory for testing
2. Sets up a file monitor to watch for changes
3. Creates and modifies files to demonstrate event detection
4. Shows how to handle file events and extract process information

### Running the Example

```bash
go run examples/monitor_example.go
```

### Key Features Demonstrated

- **Real-time file monitoring**: Using fsnotify for cross-platform file system events
- **Process correlation**: Linking file changes to the processes that made them (Linux only)
- **Recursive directory watching**: Monitoring entire directory trees
- **Event filtering**: Processing only relevant file events
- **Suspicious file detection**: Identifying potentially malicious files

### Example Output

```bash
--- File Event Detected ---
Path: /tmp/filewalker-monitor-test12345/test_file.txt
Size: 52 bytes
Modified: 2025-03-03T12:34:56-06:00
Hash: 3260a674b44a0a2d27432b3f6d3c6344384c6dc1a442f7f2e5527ba4661c2ec5
Process: editor (PID: 1234)
Parent Process: terminal (PPID: 1000)
Command Line: /usr/bin/editor /tmp/filewalker-monitor-test12345/test_file.txt
---------------------------
```

### Implementation Details

The example demonstrates:

1. Setting up a custom configuration with appropriate thresholds
2. Creating a file event handler function
3. Starting the monitor with the appropriate options
4. Handling file creation and modification events
5. Graceful shutdown with signal handling

## Other Examples

More examples will be added in the future to demonstrate other Filewalker features.
