package filewalker_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TFMV/filewalker"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// setupTestDir creates a temporary directory structure for testing.
func setupTestDir(t *testing.T) string {
	t.Helper()

	tempDir, err := os.MkdirTemp("", "filewalker_test")
	require.NoError(t, err)

	// Create a nested structure
	dirs := []string{
		"subdir1",
		"subdir2",
		"subdir1/nested",
	}
	files := []string{
		"file1.txt",
		"subdir1/file2.txt",
		"subdir1/nested/file3.txt",
		"subdir2/file4.txt",
	}

	for _, dir := range dirs {
		err := os.Mkdir(filepath.Join(tempDir, dir), 0755)
		require.NoError(t, err)
	}

	for _, file := range files {
		f, err := os.Create(filepath.Join(tempDir, file))
		require.NoError(t, err)
		f.Close()
	}

	return tempDir
}

// TestWalkLimitBasic verifies basic file traversal.
func TestWalkLimitBasic(t *testing.T) {
	tempDir := setupTestDir(t)
	defer os.RemoveAll(tempDir)

	var fileCount int32
	walkFn := func(path string, info os.FileInfo, err error) error {
		require.NoError(t, err)
		atomic.AddInt32(&fileCount, 1)
		return nil
	}

	err := filewalker.WalkLimit(context.Background(), tempDir, walkFn, 5)
	require.NoError(t, err)

	// Ensure all files are visited
	assert.GreaterOrEqual(t, fileCount, int32(5))
}

// TestWalkLimitConcurrency verifies that WalkLimit processes files concurrently.
func TestWalkLimitConcurrency(t *testing.T) {
	tempDir := setupTestDir(t)
	defer os.RemoveAll(tempDir)

	var fileCount int32
	walkFn := func(path string, info os.FileInfo, err error) error {
		require.NoError(t, err)
		atomic.AddInt32(&fileCount, 1)
		time.Sleep(50 * time.Millisecond) // Simulate work
		return nil
	}

	start := time.Now()
	err := filewalker.WalkLimit(context.Background(), tempDir, walkFn, 3)
	require.NoError(t, err)
	duration := time.Since(start)

	assert.Less(t, duration, 500*time.Millisecond, "Concurrency should improve performance")
	assert.GreaterOrEqual(t, fileCount, int32(5))
}

// TestWalkLimitCancellation verifies cancellation using context.
func TestWalkLimitCancellation(t *testing.T) {
	tempDir := setupTestDir(t)
	defer os.RemoveAll(tempDir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Add defer to ensure cleanup

	var fileCount int32
	walkFn := func(path string, info os.FileInfo, err error) error {
		require.NoError(t, err)
		count := atomic.AddInt32(&fileCount, 1)
		if count == 2 {
			cancel()
			time.Sleep(10 * time.Millisecond) // Give time for cancellation to propagate
		}
		return nil
	}

	err := filewalker.WalkLimit(ctx, tempDir, walkFn, 2)
	assert.ErrorIs(t, err, context.Canceled, "Expected context cancellation error")
	assert.LessOrEqual(t, fileCount, int32(3), "File count should be low due to cancellation")
}

// TestWalkLimitErrorHandling verifies that WalkLimit properly reports errors.
func TestWalkLimitErrorHandling(t *testing.T) {
	tempDir := setupTestDir(t)
	defer os.RemoveAll(tempDir)

	expectedErr := errors.New("mock error")
	walkFn := func(path string, info os.FileInfo, err error) error {
		require.NoError(t, err)
		if filepath.Base(path) == "file2.txt" {
			return expectedErr
		}
		return nil
	}

	err := filewalker.WalkLimit(context.Background(), tempDir, walkFn, 5)
	assert.ErrorIs(t, err, expectedErr, "Expected WalkLimit to propagate errors")
}

// TestWalkLimitInvalidLimit verifies error handling when an invalid limit is provided.
func TestWalkLimitInvalidLimit(t *testing.T) {
	tempDir := setupTestDir(t)
	defer os.RemoveAll(tempDir)

	err := filewalker.WalkLimit(context.Background(), tempDir, func(string, os.FileInfo, error) error {
		return nil
	}, 0)

	assert.Error(t, err, "Expected error for invalid limit")
}

// TestWalkLimitWithFilter verifies file filtering functionality
func TestWalkLimitWithFilter(t *testing.T) {
	tempDir := setupTestDir(t)
	defer os.RemoveAll(tempDir)

	tests := []struct {
		name     string
		filter   filewalker.FilterOptions
		expected int32
	}{
		{
			name: "Pattern filter",
			filter: filewalker.FilterOptions{
				Pattern: "file[1-2].txt",
			},
			expected: 2,
		},
		{
			name: "Exclude directory",
			filter: filewalker.FilterOptions{
				ExcludeDir: []string{"subdir1"},
			},
			expected: 2, // Only file1.txt and subdir2/file4.txt
		},
		{
			name: "Size filter",
			filter: filewalker.FilterOptions{
				MinSize: 1000,
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fileCount int32
			walkFn := func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() {
					atomic.AddInt32(&fileCount, 1)
				}
				return nil
			}

			err := filewalker.WalkLimitWithFilter(context.Background(), tempDir, walkFn, 2, tt.filter)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, fileCount, "File count mismatch for %s", tt.name)
		})
	}
}

// TestWalkLimitWithProgress verifies progress reporting
func TestWalkLimitWithProgress(t *testing.T) {
	tempDir := setupTestDir(t)
	defer os.RemoveAll(tempDir)

	var lastStats filewalker.Stats
	progressChan := make(chan struct{})
	var once sync.Once
	progressFn := func(stats filewalker.Stats) {
		lastStats = stats
		once.Do(func() {
			close(progressChan) // Only close once
		})
	}

	walkFn := func(path string, info os.FileInfo, err error) error {
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond)
		return nil
	}

	err := filewalker.WalkLimitWithProgress(context.Background(), tempDir, walkFn, 2, progressFn)
	require.NoError(t, err)

	select {
	case <-progressChan:
		assert.True(t, lastStats.FilesProcessed > 0)
		assert.True(t, lastStats.DirsProcessed > 0)
	case <-time.After(time.Second):
		t.Fatal("Timeout waiting for progress update")
	}
}

// TestWalkLimitWithOptions verifies WalkOptions functionality
func TestWalkLimitWithOptions(t *testing.T) {
	tempDir := setupTestDir(t)
	defer os.RemoveAll(tempDir)

	var stats filewalker.Stats
	progressChan := make(chan struct{})
	var once sync.Once
	opts := filewalker.WalkOptions{
		ErrorHandling: filewalker.ErrorHandlingContinue,
		Filter: filewalker.FilterOptions{
			Pattern: "*.txt",
		},
		Progress: func(s filewalker.Stats) {
			stats = s
			if s.ErrorCount > 0 {
				once.Do(func() {
					close(progressChan)
				})
			}
		},
		BufferSize: 10,
	}

	walkFn := func(path string, info os.FileInfo, err error) error {
		if filepath.Base(path) == "file2.txt" {
			return errors.New("test error")
		}
		return nil
	}

	err := filewalker.WalkLimitWithOptions(context.Background(), tempDir, walkFn, opts)
	require.NoError(t, err) // Should continue on errors

	select {
	case <-progressChan:
		assert.True(t, stats.ErrorCount > 0, "Expected error count to be greater than 0")
	case <-time.After(time.Second):
		t.Fatal("Timeout waiting for error to be reported")
	}
}

func BenchmarkWalk(b *testing.B) {
	tempDir := setupBenchmarkDir(b)
	defer os.RemoveAll(tempDir)

	// Simulate some I/O work
	processFile := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			// Simulate file processing work
			time.Sleep(1 * time.Millisecond)

			// Read a small portion of the file to simulate real I/O
			if _, err := os.ReadFile(path); err != nil {
				return err
			}
		}
		return nil
	}

	b.Run("Standard filepath.Walk", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err := filepath.Walk(tempDir, processFile)
			require.NoError(b, err)
		}
	})

	b.Run("Concurrent filewalker (2 workers)", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err := filewalker.WalkLimit(context.Background(), tempDir, processFile, 2)
			require.NoError(b, err)
		}
	})

	b.Run("Concurrent filewalker (4 workers)", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err := filewalker.WalkLimit(context.Background(), tempDir, processFile, 4)
			require.NoError(b, err)
		}
	})

	b.Run("Concurrent filewalker (8 workers)", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err := filewalker.WalkLimit(context.Background(), tempDir, processFile, 8)
			require.NoError(b, err)
		}
	})
}

// setupBenchmarkDir creates a larger directory structure for benchmarking
func setupBenchmarkDir(b *testing.B) string {
	b.Helper()

	tempDir, err := os.MkdirTemp("", "filewalker_bench")
	require.NoError(b, err)

	// Create a larger structure
	depth := 5        // Increased depth
	filesPerDir := 20 // More files per directory
	createNestedDirs(b, tempDir, depth, filesPerDir)

	return tempDir
}

func createNestedDirs(b *testing.B, dir string, depth int, filesPerDir int) {
	if depth <= 0 {
		return
	}

	// Create files in current directory
	for i := 0; i < filesPerDir; i++ {
		filename := filepath.Join(dir, fmt.Sprintf("file%d.txt", i))
		err := os.WriteFile(filename, []byte("test content"), 0644)
		require.NoError(b, err)
	}

	// Create and recurse into subdirectories
	for i := 0; i < 3; i++ {
		subdir := filepath.Join(dir, fmt.Sprintf("subdir%d", i))
		err := os.Mkdir(subdir, 0755)
		require.NoError(b, err)
		createNestedDirs(b, subdir, depth-1, filesPerDir)
	}
}

func TestSymlinkCycleDetection(t *testing.T) {
	tempDir := setupTestDir(t)
	defer os.RemoveAll(tempDir)

	// Create a cyclic symlink structure
	err := os.Symlink(filepath.Join(tempDir, "link2"), filepath.Join(tempDir, "link1"))
	require.NoError(t, err)
	err = os.Symlink(filepath.Join(tempDir, "link1"), filepath.Join(tempDir, "link2"))
	require.NoError(t, err)

	var visitedPaths []string
	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		visitedPaths = append(visitedPaths, path)
		return nil
	}

	opts := filewalker.WalkOptions{
		SymlinkHandling: filewalker.SymlinkFollow,
		ErrorHandling:   filewalker.ErrorHandlingContinue,
	}

	err = filewalker.WalkLimitWithOptions(context.Background(), tempDir, walkFn, opts)
	require.NoError(t, err)

	// Verify we didn't get stuck in a cycle
	for _, path := range visitedPaths {
		count := 0
		for _, p := range visitedPaths {
			if p == path {
				count++
			}
		}
		assert.LessOrEqual(t, count, 1, "Path visited multiple times: %s", path)
	}
}

func TestWalkLimitMultipleErrors(t *testing.T) {
	tempDir := setupTestDir(t)
	defer os.RemoveAll(tempDir)

	// Create walkFn that generates multiple errors
	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			base := filepath.Base(path)
			switch base {
			case "file1.txt":
				return errors.New("error1")
			case "file2.txt":
				return errors.New("error2")
			}
		}
		return nil
	}

	err := filewalker.WalkLimit(context.Background(), tempDir, walkFn, 2)
	require.Error(t, err)

	// Verify both errors are present
	errStr := err.Error()
	assert.Contains(t, errStr, "error1")
	assert.Contains(t, errStr, "error2")
}

func TestLogLevels(t *testing.T) {
	tempDir := setupTestDir(t)
	defer os.RemoveAll(tempDir)

	// Create an in-memory logger for testing
	core, recorded := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	opts := filewalker.WalkOptions{
		Logger:   logger,
		LogLevel: filewalker.LogLevelDebug,
		Progress: func(stats filewalker.Stats) {},
		Filter: filewalker.FilterOptions{
			Pattern: "*.txt",
		},
	}

	err := filewalker.WalkLimitWithOptions(context.Background(), tempDir, func(path string, info os.FileInfo, err error) error {
		return nil
	}, opts)
	require.NoError(t, err)

	// Verify debug logs were recorded
	entries := recorded.All()
	assert.Greater(t, len(entries), 0, "Expected debug logs to be recorded")
	assert.Contains(t, entries[0].Message, "starting walk with options")
}

func TestWalkLimitWithProgressExtendedStats(t *testing.T) {
	tempDir := setupTestDir(t)
	defer os.RemoveAll(tempDir)

	// Clean the directory first
	err := os.RemoveAll(tempDir)
	require.NoError(t, err)
	err = os.MkdirAll(tempDir, 0755)
	require.NoError(t, err)

	// Create exactly 5 files with known sizes
	for i := 0; i < 5; i++ {
		filename := filepath.Join(tempDir, fmt.Sprintf("testfile%d.dat", i))
		data := make([]byte, 1024*1024) // 1MB files
		err := os.WriteFile(filename, data, 0644)
		require.NoError(t, err)
	}

	var lastStats filewalker.Stats
	progressChan := make(chan struct{})
	var once sync.Once
	progressFn := func(stats filewalker.Stats) {
		lastStats = stats
		if stats.FilesProcessed == 5 { // Wait for exactly 5 files
			once.Do(func() {
				close(progressChan)
			})
		}
	}

	walkFn := func(path string, info os.FileInfo, err error) error {
		require.NoError(t, err)
		if !info.IsDir() {
			require.Equal(t, int64(1024*1024), info.Size(), "All test files should be exactly 1MB")
			time.Sleep(10 * time.Millisecond) // Ensure we have measurable elapsed time
		}
		return nil
	}

	err = filewalker.WalkLimitWithProgress(context.Background(), tempDir, walkFn, 2, progressFn)
	require.NoError(t, err)

	select {
	case <-progressChan:
		assert.Equal(t, int64(5), lastStats.FilesProcessed, "Should process exactly 5 files")
		assert.Equal(t, int64(1024*1024), lastStats.AvgFileSize, "Expected average file size of 1MB")
		assert.Greater(t, lastStats.SpeedMBPerSec, float64(0), "Expected non-zero processing speed")
		assert.LessOrEqual(t, lastStats.SpeedMBPerSec, float64(1024), "Speed should not exceed 1GB/s")
	case <-time.After(time.Second):
		t.Fatal("Timeout waiting for progress update")
	}
}

// TestWalkLimitEmptyDir ensures traversal works with an empty directory
func TestWalkLimitEmptyDir(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "empty_dir")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	var fileCount int32
	walkFn := func(path string, info os.FileInfo, err error) error {
		require.NoError(t, err)
		atomic.AddInt32(&fileCount, 1)
		return nil
	}

	err = filewalker.WalkLimit(context.Background(), tempDir, walkFn, 5)
	require.NoError(t, err)

	// Should only process the root directory itself
	assert.Equal(t, int32(1), fileCount)
}

// TestWalkLimitHiddenFiles ensures hidden files are included in traversal
func TestWalkLimitHiddenFiles(t *testing.T) {
	tempDir := setupTestDir(t)
	defer os.RemoveAll(tempDir)

	// Create a hidden file
	hiddenFile := filepath.Join(tempDir, ".hidden.txt")
	err := os.WriteFile(hiddenFile, []byte("test"), 0644)
	require.NoError(t, err)

	var mu sync.Mutex
	var visitedFiles []string
	walkFn := func(path string, info os.FileInfo, err error) error {
		require.NoError(t, err)
		if !info.IsDir() {
			mu.Lock()
			visitedFiles = append(visitedFiles, filepath.Base(path))
			mu.Unlock()
		}
		return nil
	}

	err = filewalker.WalkLimit(context.Background(), tempDir, walkFn, 5)
	require.NoError(t, err)

	// Ensure hidden file is visited
	assert.Contains(t, visitedFiles, ".hidden.txt", "Hidden file should be included in traversal")
}

// TestWalkLimitDeepNesting ensures deep directory structures are fully traversed
func TestWalkLimitDeepNesting(t *testing.T) {
	tempDir := setupTestDir(t)
	defer os.RemoveAll(tempDir)

	// Create deeply nested structure
	deepDir := tempDir
	for i := 0; i < 10; i++ {
		deepDir = filepath.Join(deepDir, "nested")
		err := os.Mkdir(deepDir, 0755)
		require.NoError(t, err)
	}

	var dirCount int32
	walkFn := func(path string, info os.FileInfo, err error) error {
		require.NoError(t, err)
		if info.IsDir() {
			atomic.AddInt32(&dirCount, 1)
		}
		return nil
	}

	err := filewalker.WalkLimit(context.Background(), tempDir, walkFn, 5)
	require.NoError(t, err)

	// Expecting all nested directories to be visited
	assert.GreaterOrEqual(t, dirCount, int32(10))
}

// TestWalkLimitHighConcurrency ensures high worker counts do not deadlock
func TestWalkLimitHighConcurrency(t *testing.T) {
	tempDir := setupTestDir(t)
	defer os.RemoveAll(tempDir)

	var fileCount int32
	walkFn := func(path string, info os.FileInfo, err error) error {
		require.NoError(t, err)
		atomic.AddInt32(&fileCount, 1)
		return nil
	}

	err := filewalker.WalkLimit(context.Background(), tempDir, walkFn, 1000) // Extreme concurrency
	require.NoError(t, err)

	// Ensure all files are visited
	assert.GreaterOrEqual(t, fileCount, int32(5))
}

// TestWalkLimitLargeFiles ensures traversal works with large files
func TestWalkLimitLargeFiles(t *testing.T) {
	tempDir := setupTestDir(t)
	defer os.RemoveAll(tempDir)

	largeFile := filepath.Join(tempDir, "large.dat")
	largeData := make([]byte, 100*1024*1024) // 100MB
	err := os.WriteFile(largeFile, largeData, 0644)
	require.NoError(t, err)

	var fileSize int64
	walkFn := func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			atomic.AddInt64(&fileSize, info.Size())
		}
		return nil
	}

	err = filewalker.WalkLimit(context.Background(), tempDir, walkFn, 5)
	require.NoError(t, err)

	assert.Equal(t, int64(100*1024*1024), fileSize, "Expected total size of processed files to match large file size")
}

// TestWalkLimitSkipDir ensures SkipDir is respected
func TestWalkLimitSkipDir(t *testing.T) {
	tempDir := setupTestDir(t)
	defer os.RemoveAll(tempDir)

	var visitedPaths []string
	var mu sync.Mutex

	// Create a map to track skipped directories
	skippedDirs := make(map[string]bool)
	skippedDirs[filepath.Join(tempDir, "subdir1")] = true

	walkFn := func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			absPath, _ := filepath.Abs(path)
			if skippedDirs[absPath] {
				return filepath.SkipDir
			}
		}

		mu.Lock()
		visitedPaths = append(visitedPaths, path)
		mu.Unlock()
		return nil
	}

	err := filewalker.WalkLimit(context.Background(), tempDir, walkFn, 5)
	require.NoError(t, err)

	// Verify no paths under subdir1 were visited
	for _, path := range visitedPaths {
		absPath, err := filepath.Abs(path)
		require.NoError(t, err)
		for skipDir := range skippedDirs {
			assert.False(t, strings.HasPrefix(absPath, skipDir),
				"Path %s should not be under skipped directory %s", path, skipDir)
		}
	}
}

// TestWalkLimitSymlinkReport ensures symlinks are reported but not followed
func TestWalkLimitSymlinkReport(t *testing.T) {
	tempDir := setupTestDir(t)
	defer os.RemoveAll(tempDir)

	target := filepath.Join(tempDir, "file1.txt")
	link := filepath.Join(tempDir, "symlink")
	err := os.Symlink(target, link)
	require.NoError(t, err)

	var visitedFiles []string
	walkFn := func(path string, info os.FileInfo, err error) error {
		require.NoError(t, err)
		if !info.IsDir() {
			visitedFiles = append(visitedFiles, filepath.Base(path))
		}
		return nil
	}

	opts := filewalker.WalkOptions{
		SymlinkHandling: filewalker.SymlinkReport,
		ErrorHandling:   filewalker.ErrorHandlingContinue,
	}

	err = filewalker.WalkLimitWithOptions(context.Background(), tempDir, walkFn, opts)
	require.NoError(t, err)

	// Ensure symlink is reported but not followed
	assert.Contains(t, visitedFiles, "symlink")
}

// TestWalkLimitLargeDirectory ensures large directories do not cause excessive memory use
func TestWalkLimitLargeDirectory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "filewalker_large_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create exactly 10000 files
	for i := 0; i < 10000; i++ {
		f, err := os.Create(filepath.Join(tempDir, fmt.Sprintf("file%d.txt", i)))
		require.NoError(t, err)
		f.Close()
	}

	var fileCount int32
	walkFn := func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			atomic.AddInt32(&fileCount, 1)
		}
		return nil
	}

	err = filewalker.WalkLimit(context.Background(), tempDir, walkFn, 10)
	require.NoError(t, err)

	assert.Equal(t, int32(10000), fileCount, "Should process exactly 10000 files")
}
