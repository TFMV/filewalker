// Package filewalker provides concurrent filesystem traversal with filtering and progress reporting.
// It builds upon the standard filepath.Walk functionality while adding concurrency, filtering,
// and monitoring capabilities.
package filewalker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// DefaultConcurrentWalks defines the default number of concurrent workers
// when no specific limit is provided.
const DefaultConcurrentWalks int = 100

// --------------------------------------------------------------------------
// Core types for progress monitoring
// --------------------------------------------------------------------------

// ProgressFn is called periodically with traversal statistics.
// Implementations must be thread-safe as this may be called concurrently.
type ProgressFn func(stats Stats)

// Stats holds traversal statistics that are updated atomically during the walk.
type Stats struct {
	FilesProcessed int64         // Number of files processed
	DirsProcessed  int64         // Number of directories processed
	EmptyDirs      int64         // Number of empty directories
	BytesProcessed int64         // Total bytes processed
	ErrorCount     int64         // Number of errors encountered
	ElapsedTime    time.Duration // Total time elapsed
	AvgFileSize    int64         // Average file size in bytes
	SpeedMBPerSec  float64       // Processing speed in MB/s
}

// updateDerivedStats calculates derived statistics like averages and speeds
func (s *Stats) updateDerivedStats() {
	// Get filesProcessed first to ensure consistent ratio
	filesProcessed := atomic.LoadInt64(&s.FilesProcessed)
	if filesProcessed > 0 {
		// Load bytesProcessed after filesProcessed for accurate average
		bytesProcessed := atomic.LoadInt64(&s.BytesProcessed)
		s.AvgFileSize = bytesProcessed / filesProcessed

		// Calculate speed using the same bytesProcessed value
		elapsedSec := s.ElapsedTime.Seconds()
		if elapsedSec > 0 {
			// Convert bytes to MB/s (1MB = 1024*1024 bytes)
			megabytes := float64(bytesProcessed) / (1024.0 * 1024.0)
			s.SpeedMBPerSec = megabytes / elapsedSec

			// Cap speed at a reasonable maximum (1GB/s)
			if s.SpeedMBPerSec > 1024.0 {
				s.SpeedMBPerSec = 1024.0
			}
		}
	}
}

// --------------------------------------------------------------------------
// Configuration types
// --------------------------------------------------------------------------

// ErrorHandling defines how errors are handled during traversal.
type ErrorHandling int

const (
	ErrorHandlingContinue ErrorHandling = iota // Continue on errors
	ErrorHandlingStop                          // Stop on first error
	ErrorHandlingSkip                          // Skip problematic files/dirs
)

// SymlinkHandling defines how symbolic links are processed.
type SymlinkHandling int

const (
	SymlinkFollow SymlinkHandling = iota // Follow symbolic links
	SymlinkIgnore                        // Ignore symbolic links
	SymlinkReport                        // Report links but don't follow
)

// MemoryLimit sets memory usage boundaries for the traversal.
type MemoryLimit struct {
	SoftLimit int64 // Pause processing when reached
	HardLimit int64 // Stop processing when reached
}

// LogLevel defines the verbosity of logging
type LogLevel int

const (
	LogLevelError LogLevel = iota
	LogLevelWarn
	LogLevelInfo
	LogLevelDebug
)

// WalkOptions provides comprehensive configuration for the walk operation.
type WalkOptions struct {
	ErrorHandling   ErrorHandling
	Filter          FilterOptions
	Progress        ProgressFn
	Logger          *zap.Logger
	LogLevel        LogLevel // New field
	BufferSize      int
	SymlinkHandling SymlinkHandling
	MemoryLimit     MemoryLimit
}

// FilterOptions defines criteria for including/excluding files and directories.
type FilterOptions struct {
	MinSize        int64     // Minimum file size in bytes
	MaxSize        int64     // Maximum file size in bytes
	Pattern        string    // Glob pattern for matching files
	ExcludeDir     []string  // Directory patterns to exclude
	IncludeTypes   []string  // File extensions to include (e.g. ".txt", ".go")
	ModifiedAfter  time.Time // Only include files modified after
	ModifiedBefore time.Time // Only include files modified before
}

// --------------------------------------------------------------------------
// Primary API functions
// --------------------------------------------------------------------------

// Walk traverses a directory tree using the default concurrency limit.
// It's a convenience wrapper around WalkLimit.
func Walk(root string, walkFn filepath.WalkFunc) error {
	return WalkLimit(context.Background(), root, walkFn, DefaultConcurrentWalks)
}

// WalkLimit traverses a directory tree with a specified concurrency limit.
// It distributes work across a pool of goroutines while respecting context cancellation.
func WalkLimit(ctx context.Context, root string, walkFn filepath.WalkFunc, limit int) error {
	if limit < 1 {
		return errors.New("filewalker: concurrency limit must be greater than zero")
	}

	logger := createLogger(LogLevelInfo) // Default to INFO level
	defer logger.Sync()

	logger.Debug("starting walk",
		zap.String("root", root),
		zap.Int("workers", limit),
	)

	tasks := make(chan walkArgs, limit)
	var tasksWg sync.WaitGroup
	var workerWg sync.WaitGroup

	// Error collection
	var walkErrors []error
	var errLock sync.Mutex

	// worker processes items from the tasks channel
	worker := func() {
		defer workerWg.Done()
		for task := range tasks {
			if ctx.Err() != nil {
				logger.Debug("worker canceled",
					zap.String("path", task.path),
				)
				tasksWg.Done()
				continue
			}
			if err := walkFn(task.path, task.info, task.err); err != nil {
				if err != filepath.SkipDir { // Don't collect SkipDir as an error
					errLock.Lock()
					walkErrors = append(walkErrors, fmt.Errorf("path %q: %w", task.path, err))
					errLock.Unlock()
				}
			}
			tasksWg.Done()
		}
	}

	// Launch worker pool
	for i := 0; i < limit; i++ {
		workerWg.Add(1)
		go worker()
	}

	// Producer: walk the directory tree
	var walkerWg sync.WaitGroup
	walkerWg.Add(1)
	go func() {
		defer walkerWg.Done()
		defer close(tasks)
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if ctx.Err() != nil {
				logger.Warn("walk canceled", zap.String("path", path))
				return context.Canceled
			}
			tasksWg.Add(1)
			select {
			case <-ctx.Done():
				tasksWg.Done()
				return context.Canceled
			case tasks <- walkArgs{path: path, info: info, err: err}:
				return nil
			}
		})
		if err != nil && err != filepath.SkipDir { // Don't collect SkipDir as an error
			errLock.Lock()
			walkErrors = append(walkErrors, err)
			errLock.Unlock()
		}
	}()

	// Wait for completion
	walkerWg.Wait()
	tasksWg.Wait()
	workerWg.Wait()

	// Return combined errors if any occurred
	if len(walkErrors) > 0 {
		return errors.Join(walkErrors...)
	}
	return nil
}

// hasFiles checks if a directory contains any entries
func hasFiles(dir string) bool {
	entries, err := os.ReadDir(dir)
	return err == nil && len(entries) > 0
}

// WalkLimitWithProgress adds progress monitoring to the walk operation.
func WalkLimitWithProgress(ctx context.Context, root string, walkFn filepath.WalkFunc, limit int, progressFn ProgressFn) error {
	stats := &Stats{}
	startTime := time.Now()

	// Ensure final progress update happens even on early return
	defer func() {
		stats.ElapsedTime = time.Since(startTime)
		stats.updateDerivedStats()
		progressFn(*stats) // Always report final progress
	}()

	// Launch progress reporter
	doneCh := make(chan struct{})
	var tickerWg sync.WaitGroup
	tickerWg.Add(1)
	go func() {
		defer tickerWg.Done()
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-doneCh:
				return
			case <-ticker.C:
				stats.ElapsedTime = time.Since(startTime)
				stats.updateDerivedStats()
				progressFn(*stats)
			}
		}
	}()

	// Wrap walkFn to update statistics
	wrappedWalkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			atomic.AddInt64(&stats.ErrorCount, 1)
			return err
		}

		// Update stats before calling walkFn
		if info.IsDir() {
			atomic.AddInt64(&stats.DirsProcessed, 1)
			// Count empty directories explicitly
			if !hasFiles(path) {
				atomic.AddInt64(&stats.EmptyDirs, 1)
			}
		} else {
			size := info.Size()
			atomic.AddInt64(&stats.FilesProcessed, 1)
			atomic.AddInt64(&stats.BytesProcessed, size)
		}

		// Call original walkFn
		err = walkFn(path, info, nil)
		if err != nil {
			atomic.AddInt64(&stats.ErrorCount, 1)
		}
		return err
	}

	err := WalkLimit(ctx, root, wrappedWalkFn, limit)
	close(doneCh)
	tickerWg.Wait()

	return err // Final progress update handled by defer
}

// Thread-safe maps for caching
var (
	excludedDirs    sync.Map // Cache of excluded directories
	visitedSymlinks sync.Map // Cache of visited symlinks to detect cycles
	symlinkLock     sync.Mutex
)

// isCyclicSymlink checks if following a symlink would create a cycle
func isCyclicSymlink(path string) bool {
	// Check cache before resolving the real path
	if _, seen := visitedSymlinks.Load(path); seen {
		return true
	}

	// Lock during path resolution to prevent duplicate work
	symlinkLock.Lock()
	defer symlinkLock.Unlock()

	// Double-check after acquiring lock
	if _, seen := visitedSymlinks.Load(path); seen {
		return true
	}

	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}

	// If we've seen this resolved path before, it's a cycle
	if _, seen := visitedSymlinks.Load(realPath); seen {
		return true
	}

	// Store both original and resolved paths
	visitedSymlinks.Store(path, struct{}{})
	visitedSymlinks.Store(realPath, struct{}{})
	return false
}

// shouldSkipDir checks if a directory should be excluded, using cached results
func shouldSkipDir(path, root string, excludes []string) bool {
	if len(excludes) == 0 {
		return false
	}

	// Check cache first
	if _, found := excludedDirs.Load(path); found {
		return true
	}

	// Check each parent directory
	dir := path
	for dir != root && dir != "." {
		for _, exclude := range excludes {
			if matched, _ := filepath.Match(exclude, filepath.Base(dir)); matched {
				excludedDirs.Store(path, struct{}{}) // Cache result
				return true
			}
		}
		dir = filepath.Dir(dir)
	}
	return false
}

// WalkLimitWithFilter adds file filtering capabilities to the walk operation.
func WalkLimitWithFilter(ctx context.Context, root string, walkFn filepath.WalkFunc, limit int, filter FilterOptions) error {
	root = filepath.Clean(root)

	filteredWalkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if err == filepath.SkipDir {
				return err // Propagate SkipDir from filepath.Walk
			}
			return err
		}

		// Directory handling
		if info.IsDir() {
			if shouldSkipDir(path, root, filter.ExcludeDir) {
				return filepath.SkipDir
			}
		} else {
			// Check if parent directory is excluded
			parent := filepath.Dir(path)
			if shouldSkipDir(parent, root, filter.ExcludeDir) {
				return nil
			}

			// File filtering
			if !filePassesFilter(info, filter, SymlinkFollow) {
				return nil
			}
		}

		// Call the original walkFn with nil error since we've handled filtering
		return walkFn(path, info, nil)
	}

	// Don't convert SkipDir to error at the top level
	return WalkLimit(ctx, root, filteredWalkFn, limit)
}

// WalkLimitWithOptions provides the most flexible walk configuration,
// combining error handling, filtering, progress reporting, and (optionally)
// custom logger and symlink handling.
func WalkLimitWithOptions(ctx context.Context, root string, walkFn filepath.WalkFunc, opts WalkOptions) error {
	if opts.BufferSize < 1 {
		opts.BufferSize = DefaultConcurrentWalks
	}

	// Use provided logger or create one with specified level
	logger := opts.Logger
	if logger == nil {
		logger = createLogger(opts.LogLevel)
		defer logger.Sync()
	}

	logger.Debug("starting walk with options",
		zap.String("root", root),
		zap.Int("buffer_size", opts.BufferSize),
		zap.Any("error_handling", opts.ErrorHandling),
		zap.Any("symlink_handling", opts.SymlinkHandling),
	)

	stats := &Stats{}
	startTime := time.Now()

	// Clear symlink cache at start of walk
	visitedSymlinks = sync.Map{}

	wrappedWalkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if opts.Progress != nil {
				atomic.AddInt64(&stats.ErrorCount, 1)
				stats.ElapsedTime = time.Since(startTime)
				opts.Progress(*stats)
			}
			switch opts.ErrorHandling {
			case ErrorHandlingContinue, ErrorHandlingSkip:
				return nil
			default:
				return err
			}
		}

		// Use optimized directory exclusion
		if info.IsDir() {
			if shouldSkipDir(path, root, opts.Filter.ExcludeDir) {
				return filepath.SkipDir
			}
		} else {
			parent := filepath.Dir(path)
			if shouldSkipDir(parent, root, opts.Filter.ExcludeDir) {
				return nil
			}
			if !filePassesFilter(info, opts.Filter, opts.SymlinkHandling) {
				return nil
			}
		}

		// Update progress if a callback is provided.
		if opts.Progress != nil {
			if info.IsDir() {
				atomic.AddInt64(&stats.DirsProcessed, 1)
			} else {
				atomic.AddInt64(&stats.FilesProcessed, 1)
				atomic.AddInt64(&stats.BytesProcessed, info.Size())
			}
			stats.ElapsedTime = time.Since(startTime)
			opts.Progress(*stats)
		}

		err = walkFn(path, info, nil)
		if err != nil {
			if opts.Progress != nil {
				atomic.AddInt64(&stats.ErrorCount, 1)
				stats.ElapsedTime = time.Since(startTime)
				opts.Progress(*stats)
			}
			switch opts.ErrorHandling {
			case ErrorHandlingContinue, ErrorHandlingSkip:
				return nil
			default:
				return err
			}
		}
		return nil
	}

	err := WalkLimit(ctx, root, wrappedWalkFn, opts.BufferSize)
	if err == filepath.SkipDir {
		return nil
	}
	return err
}

// --------------------------------------------------------------------------
// Internal helper types and functions
// --------------------------------------------------------------------------

// walkArgs holds the parameters passed to workers.
type walkArgs struct {
	path string
	info os.FileInfo
	err  error
}

// filePassesFilter returns true if the file meets the filtering criteria.
// It considers file size, modification time, glob pattern, file extension,
// and (if applicable) symlink handling.
func filePassesFilter(info os.FileInfo, filter FilterOptions, symlinkHandling SymlinkHandling) bool {
	// Check symlink handling first
	if info.Mode()&os.ModeSymlink != 0 {
		switch symlinkHandling {
		case SymlinkIgnore:
			return false
		case SymlinkFollow:
			if isCyclicSymlink(info.Name()) {
				return false // Skip cyclic symlinks
			}
		case SymlinkReport:
			// Just report the symlink without following
			return true
		}
	}

	if filter.MinSize > 0 && info.Size() < filter.MinSize {
		return false
	}
	if filter.MaxSize > 0 && info.Size() > filter.MaxSize {
		return false
	}
	if !filter.ModifiedAfter.IsZero() && info.ModTime().Before(filter.ModifiedAfter) {
		return false
	}
	if !filter.ModifiedBefore.IsZero() && info.ModTime().After(filter.ModifiedBefore) {
		return false
	}
	if filter.Pattern != "" {
		matched, err := filepath.Match(filter.Pattern, info.Name())
		if err != nil || !matched {
			return false
		}
	}
	// If IncludeTypes is specified, check file extension.
	if len(filter.IncludeTypes) > 0 {
		ext := filepath.Ext(info.Name())
		var found bool
		for _, typ := range filter.IncludeTypes {
			if ext == typ {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// createLogger creates a zap logger with the specified log level
func createLogger(level LogLevel) *zap.Logger {
	config := zap.NewProductionConfig()

	// Map our levels to zap levels
	switch level {
	case LogLevelError:
		config.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	case LogLevelWarn:
		config.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case LogLevelInfo:
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	case LogLevelDebug:
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	default:
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	logger, _ := config.Build()
	return logger
}

// clearSymlinkCache resets the symlink tracking cache
func clearSymlinkCache() {
	visitedSymlinks = sync.Map{}
}
