package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
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
  -v --verbose              Enable verbose logging.
  --silent                  Disable all output except errors.
  --format=<fmt>            Output format (text|json) [default: text].
  --min-size=<bytes>        Minimum file size to process.
  --max-size=<bytes>        Maximum file size to process.
  --pattern=<glob>          File pattern to match.
  --exclude-dir=<dirs>      Directories to exclude (comma-separated).
  --follow-symlinks         Follow symbolic links [default: false].
  --progress                Show progress updates.
  --error-mode=<mode>       Error handling mode (continue|stop|skip) [default: continue].
`

const version = "v0.1.0"

type config struct {
	path           string
	workers        int
	verbose        bool
	silent         bool
	format         string
	minSize        int64
	maxSize        int64
	pattern        string
	excludeDirs    []string
	followSymlinks bool
	errorMode      string
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

	// Map errorMode string to ErrorHandling type
	var errorHandling filewalker.ErrorHandling
	switch cfg.errorMode {
	case "continue":
		errorHandling = filewalker.ErrorHandlingContinue
	case "stop":
		errorHandling = filewalker.ErrorHandlingStop
	case "skip":
		errorHandling = filewalker.ErrorHandlingSkip
	default:
		errorHandling = filewalker.ErrorHandlingContinue
	}

	// Map followSymlinks bool to SymlinkHandling type
	var symlinkHandling filewalker.SymlinkHandling
	if cfg.followSymlinks {
		symlinkHandling = filewalker.SymlinkFollow
	} else {
		symlinkHandling = filewalker.SymlinkIgnore
	}

	// Create walk options with progress and error handling
	walkOpts := filewalker.WalkOptions{
		Progress:      progressFn,
		BufferSize:    cfg.workers,
		ErrorHandling: errorHandling,
		Filter: filewalker.FilterOptions{
			MinSize:    cfg.minSize,
			MaxSize:    cfg.maxSize,
			Pattern:    cfg.pattern,
			ExcludeDir: cfg.excludeDirs,
			// Include other filter options as needed
		},
		SymlinkHandling: symlinkHandling,
		Logger:          logger,
		LogLevel:        filewalker.LogLevelInfo,
	}

	// Create the walk function
	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logger.Error("Error accessing path",
				zap.String("path", path),
				zap.Error(err))
			return err
		}

		if cfg.verbose {
			logger.Info("Visited",
				zap.String("path", path),
				zap.Bool("is_dir", info.IsDir()),
				zap.Int64("size", info.Size()))
		}

		return nil
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
		// You can display aggregate stats here if needed
		fmt.Println()
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

	// Parse min-size
	if opts["--min-size"] != nil {
		if minSizeStr, ok := opts["--min-size"].(string); ok && minSizeStr != "" {
			if minSize, err := strconv.ParseInt(minSizeStr, 10, 64); err == nil {
				cfg.minSize = minSize
			} else {
				return cfg, fmt.Errorf("invalid --min-size value: %v", err)
			}
		}
	}

	// Parse max-size
	if opts["--max-size"] != nil {
		if maxSizeStr, ok := opts["--max-size"].(string); ok && maxSizeStr != "" {
			if maxSize, err := strconv.ParseInt(maxSizeStr, 10, 64); err == nil {
				cfg.maxSize = maxSize
			} else {
				return cfg, fmt.Errorf("invalid --max-size value: %v", err)
			}
		}
	}

	// Parse pattern
	if opts["--pattern"] != nil {
		cfg.pattern = opts["--pattern"].(string)
	}

	// Parse exclude-dir
	if opts["--exclude-dir"] != nil {
		cfg.excludeDirs = parseCommaSeparated(opts["--exclude-dir"].(string))
	}

	// Parse follow-symlinks
	cfg.followSymlinks = opts["--follow-symlinks"].(bool)

	// Parse error-mode
	if opts["--error-mode"] != nil {
		cfg.errorMode = opts["--error-mode"].(string)
	} else {
		cfg.errorMode = "continue"
	}

	return cfg, nil
}

func parseCommaSeparated(s string) []string {
	var result []string
	for _, part := range strings.Split(s, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
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
