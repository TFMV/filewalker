// Package filewalker provides concurrent filesystem traversal with filtering and progress reporting.
// It builds upon the standard filepath.Walk functionality while adding concurrency, filtering,
// and monitoring capabilities.
package filewalker

import (
	"context"
	"errors"
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
	BytesProcessed int64         // Total bytes processed
	ErrorCount     int64         // Number of errors encountered
	ElapsedTime    time.Duration // Total time elapsed
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

// WalkOptions provides comprehensive configuration for the walk operation.
type WalkOptions struct {
	ErrorHandling   ErrorHandling
	Filter          FilterOptions
	Progress        ProgressFn
	Logger          *zap.Logger
	BufferSize      int // Channel buffer size for worker queue
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

	// Use provided logger if available; otherwise create a production logger.
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	// tasks is the channel where discovered filesystem entries are sent.
	tasks := make(chan walkArgs, limit)
	var tasksWg sync.WaitGroup  // counts outstanding tasks
	var workerWg sync.WaitGroup // waits for worker goroutines
	var walkErr error
	var errOnce sync.Once

	// worker processes items from the tasks channel.
	worker := func() {
		defer workerWg.Done()
		for task := range tasks {
			// If the context was cancelled, simply mark the task done.
			if ctx.Err() != nil {
				tasksWg.Done()
				continue
			}
			if err := walkFn(task.path, task.info, task.err); err != nil {
				errOnce.Do(func() { walkErr = err })
			}
			tasksWg.Done()
		}
	}

	// Launch the worker pool.
	for i := 0; i < limit; i++ {
		workerWg.Add(1)
		go worker()
	}

	// Producer: walk the directory tree.
	var walkerWg sync.WaitGroup
	walkerWg.Add(1)
	go func() {
		defer walkerWg.Done()
		defer close(tasks) // signal workers when done
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
		if err != nil && walkErr == nil {
			errOnce.Do(func() { walkErr = err })
		}
	}()

	// Wait for the producer to finish, then for all tasks and workers.
	walkerWg.Wait()
	tasksWg.Wait()
	workerWg.Wait()

	return walkErr
}

// WalkLimitWithProgress adds progress monitoring to the walk operation.
// A separate goroutine calls progressFn periodically with updated statistics.
func WalkLimitWithProgress(ctx context.Context, root string, walkFn filepath.WalkFunc, limit int, progressFn ProgressFn) error {
	stats := &Stats{}
	startTime := time.Now()

	// Launch a goroutine to report progress periodically.
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
				progressFn(*stats)
			}
		}
	}()

	// Wrap walkFn to update statistics.
	wrappedWalkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			atomic.AddInt64(&stats.ErrorCount, 1)
			return err
		}
		if info.IsDir() {
			atomic.AddInt64(&stats.DirsProcessed, 1)
		} else {
			atomic.AddInt64(&stats.FilesProcessed, 1)
			atomic.AddInt64(&stats.BytesProcessed, info.Size())
		}
		return walkFn(path, info, err)
	}

	err := WalkLimit(ctx, root, wrappedWalkFn, limit)
	close(doneCh)
	tickerWg.Wait()
	// One final progress update.
	stats.ElapsedTime = time.Since(startTime)
	progressFn(*stats)
	return err
}

// WalkLimitWithFilter adds file filtering capabilities to the walk operation.
// Files and directories not matching the criteria are skipped.
func WalkLimitWithFilter(ctx context.Context, root string, walkFn filepath.WalkFunc, limit int, filter FilterOptions) error {
	// Normalize the root path.
	root = filepath.Clean(root)

	filteredWalkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Directory filtering: if the directory (by its basename) matches any exclusion,
		// signal to skip this directory.
		if info.IsDir() {
			for _, pattern := range filter.ExcludeDir {
				if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
					return filepath.SkipDir
				}
			}
		} else {
			// Also check if any parent directory should be excluded.
			dir := filepath.Dir(path)
			for dir != root && dir != "." {
				for _, pattern := range filter.ExcludeDir {
					if matched, _ := filepath.Match(pattern, filepath.Base(dir)); matched {
						return nil
					}
				}
				dir = filepath.Dir(dir)
			}
			// Apply file-specific filtering.
			if !filePassesFilter(info, filter, SymlinkFollow) {
				return nil
			}
		}
		return walkFn(path, info, err)
	}

	err := WalkLimit(ctx, root, filteredWalkFn, limit)
	if err == filepath.SkipDir {
		return nil
	}
	return err
}

// WalkLimitWithOptions provides the most flexible walk configuration,
// combining error handling, filtering, progress reporting, and (optionally)
// custom logger and symlink handling.
func WalkLimitWithOptions(ctx context.Context, root string, walkFn filepath.WalkFunc, opts WalkOptions) error {
	if opts.BufferSize < 1 {
		opts.BufferSize = DefaultConcurrentWalks
	}
	stats := &Stats{}
	startTime := time.Now()

	// Use the provided logger if set.
	logger := opts.Logger
	if logger == nil {
		logger, _ = zap.NewProduction()
		defer logger.Sync()
	}

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

		// Filtering: for directories check for exclusion; for files check filter criteria.
		if info.IsDir() {
			for _, pattern := range opts.Filter.ExcludeDir {
				if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
					return filepath.SkipDir
				}
			}
		} else {
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
	// Check symlink handling.
	if info.Mode()&os.ModeSymlink != 0 {
		if symlinkHandling == SymlinkIgnore {
			return false
		}
		// For SymlinkFollow or SymlinkReport, treat the file as usual.
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

// shouldSkipDir is a helper (currently unused) to check if a directory should be skipped.
func shouldSkipDir(path, root string, excludes []string) bool {
	if len(excludes) == 0 {
		return false
	}
	dir := path
	for dir != root && dir != "." {
		for _, exclude := range excludes {
			if matched, _ := filepath.Match(exclude, filepath.Base(dir)); matched {
				return true
			}
		}
		dir = filepath.Dir(dir)
	}
	return false
}
