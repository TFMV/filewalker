package filewalker_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TFMV/filewalker"
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
