package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/docopt/docopt-go"
	"go.uber.org/zap"

	"github.com/TFMV/filewalker"
)

const usage = `filewalker - Concurrent file system traversal utility.

Usage:
  filewalker [options] <path>
  filewalker -h | --help
  filewalker --version

Options:
  -h --help                 Show this help message.
  --version                 Show version.
  -w --workers=<num>        Number of concurrent workers [default: 4].
  -v --verbose             Enable verbose logging.
  --silent                 Disable all output except errors.
  --format=<fmt>           Output format (text|json) [default: text].
  --min-size=<bytes>       Minimum file size to process.
  --max-size=<bytes>       Maximum file size to process.
  --pattern=<glob>         File pattern to match.
  --exclude-dir=<dirs>     Directories to exclude (comma-separated).
  --follow-symlinks        Follow symbolic links [default: false].
  --progress              Show progress updates.
  --error-mode=<mode>     Error handling mode (continue|stop|skip) [default: continue].
`

const version = "v0.1.0"

type config struct {
	path    string
	workers int
	verbose bool
	silent  bool
	format  string
}

func main() {
	// Parse command line arguments
	opts, err := docopt.ParseArgs(usage, os.Args[1:], version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing arguments: %v\n", err)
		os.Exit(1)
	}

	// Setup configuration
	cfg, err := parseConfig(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error in configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	logger := initLogger(cfg)
	defer logger.Sync()

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup file statistics
	var stats struct {
		files int64
		dirs  int64
		size  int64
	}

	var lastUpdate time.Time
	progressFn := func(stats filewalker.Stats) {
		if time.Since(lastUpdate) < 100*time.Millisecond {
			return
		}
		lastUpdate = time.Now()

		fmt.Printf("\r\033[K")

		if cfg.format == "json" {
			fmt.Printf(`{"files":%d,"dirs":%d,"bytes":%d,"speed":"%.2f MB/s","elapsed":"%s"}`,
				stats.FilesProcessed,
				stats.DirsProcessed,
				stats.BytesProcessed,
				stats.SpeedMBPerSec,
				stats.ElapsedTime.Round(time.Millisecond))
		} else {
			fmt.Printf("Files: %d | Dirs: %d | Speed: %.2f MB/s | Elapsed: %s",
				stats.FilesProcessed,
				stats.DirsProcessed,
				stats.SpeedMBPerSec,
				stats.ElapsedTime.Round(time.Millisecond))
		}
	}

	// Create the walk function
	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logger.Error("Error accessing path",
				zap.String("path", path),
				zap.Error(err))
			return err
		}

		// Let filewalker handle the stats - remove our custom stats tracking
		if cfg.verbose {
			logger.Info("Visited",
				zap.String("path", path),
				zap.Bool("is_dir", info.IsDir()),
				zap.Int64("size", info.Size()))
		}

		return nil
	}

	// Create walk options with progress and error handling
	walkOpts := filewalker.WalkOptions{
		Progress:      progressFn,
		BufferSize:    cfg.workers,
		ErrorHandling: filewalker.ErrorHandlingContinue,
		Filter: filewalker.FilterOptions{
			MinSize:    0,          // No minimum size
			MaxSize:    0,          // No maximum size
			Pattern:    "",         // Match all files
			ExcludeDir: []string{}, // Don't exclude any dirs
		},
		SymlinkHandling: filewalker.SymlinkFollow, // Follow symlinks
		Logger:          logger,
		LogLevel:        filewalker.LogLevelInfo,
	}

	// Execute the walk
	logger.Info("Starting file walk",
		zap.String("path", cfg.path),
		zap.Int("workers", cfg.workers))

	if err := filewalker.WalkLimitWithOptions(ctx, cfg.path, walkFn, walkOpts); err != nil {
		fmt.Printf("\n") // New line after progress
		logger.Error("Walk failed", zap.Error(err))
		os.Exit(1)
	}

	fmt.Printf("\n") // New line after progress

	// Output results
	if !cfg.silent {
		outputResults(cfg, stats)
	}
}

func parseConfig(opts docopt.Opts) (config, error) {
	cfg := config{
		path:    opts["<path>"].(string),
		verbose: opts["--verbose"].(bool),
		silent:  opts["--silent"].(bool),
		format:  opts["--format"].(string),
	}

	// Parse workers, defaulting to number of CPUs if not specified
	if w, err := strconv.Atoi(opts["--workers"].(string)); err != nil {
		cfg.workers = runtime.NumCPU()
	} else {
		cfg.workers = w
	}

	// Validate configuration
	if cfg.workers < 1 {
		return cfg, fmt.Errorf("invalid number of workers: %d", cfg.workers)
	}

	if cfg.format != "text" && cfg.format != "json" {
		return cfg, fmt.Errorf("invalid format: %s", cfg.format)
	}

	return cfg, nil
}

func initLogger(cfg config) *zap.Logger {
	var logger *zap.Logger
	var err error

	if cfg.silent {
		logger = zap.NewNop()
	} else if cfg.verbose {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	return logger
}

func outputResults(cfg config, stats struct {
	files int64
	dirs  int64
	size  int64
}) {
	if cfg.format == "json" {
		fmt.Printf(`{
  "files": %d,
  "directories": %d,
  "total_size": %d
}
`, stats.files, stats.dirs, stats.size)
	} else {
		fmt.Printf("Scan complete:\n")
		fmt.Printf("  Files:       %d\n", stats.files)
		fmt.Printf("  Directories: %d\n", stats.dirs)
		fmt.Printf("  Total size:  %d bytes\n", stats.size)
	}
}
