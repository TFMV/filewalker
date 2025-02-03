// Package filewalker provides a concurrent filesystem traversal utility.
//
// It allows you to traverse a directory tree concurrently, with a configurable
// limit on the number of concurrent operations. It also supports context cancellation,
// so you can stop the traversal early if needed.
//
// The package uses a worker pool to process the files, and a channel to distribute

package filewalker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"go.uber.org/zap"
)

// DefaultConcurrentWalks defines the default concurrency limit.
const DefaultConcurrentWalks int = 100

// Walk traverses the file tree at root with a default concurrency limit.
func Walk(root string, walkFn filepath.WalkFunc) error {
	return WalkLimit(context.Background(), root, walkFn, DefaultConcurrentWalks)
}

// WalkLimit traverses the file tree at root with a specified concurrency limit.
func WalkLimit(ctx context.Context, root string, walkFn filepath.WalkFunc, limit int) error {
	if limit < 1 {
		return errors.New("filewalker: concurrency limit must be greater than zero")
	}

	logger, _ := zap.NewProduction()
	defer logger.Sync()

	files := make(chan walkArgs, limit)
	var filesWg sync.WaitGroup
	var walkErr error
	var errOnce sync.Once

	// Worker pool
	var workerWg sync.WaitGroup
	for i := 0; i < limit; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for file := range files {
				select {
				case <-ctx.Done():
					errOnce.Do(func() {
						walkErr = context.Canceled
					})
					filesWg.Done()
					continue
				default:
					if err := walkFn(file.path, file.info, file.err); err != nil {
						errOnce.Do(func() {
							walkErr = err
						})
					}
					filesWg.Done()
				}
			}
		}()
	}

	// Walking the file tree
	walkerWg := sync.WaitGroup{}
	walkerWg.Add(1)
	go func() {
		defer walkerWg.Done()
		defer close(files)

		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if ctx.Err() != nil {
				logger.Warn("Walk canceled", zap.String("path", path))
				return context.Canceled
			}

			filesWg.Add(1)
			select {
			case <-ctx.Done():
				filesWg.Done()
				return context.Canceled
			case files <- walkArgs{path: path, info: info, err: err}:
				return nil
			}
		})

		if err != nil && walkErr == nil {
			errOnce.Do(func() {
				walkErr = err
			})
		}
	}()

	// Wait for completion
	walkerWg.Wait()
	filesWg.Wait()
	workerWg.Wait()

	return walkErr
}

// walkArgs holds the parameters passed to Walk functions.
type walkArgs struct {
	path string
	info os.FileInfo
	err  error
}
