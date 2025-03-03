package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/TFMV/filewalker"
	"go.uber.org/zap"
)

func main() {
	// Create a logger
	logger, err := zap.NewDevelopment()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	// Create a test directory to monitor
	tempDir, err := os.MkdirTemp("", "filewalker-monitor-test")
	if err != nil {
		logger.Fatal("Failed to create test directory", zap.Error(err))
	}
	defer os.RemoveAll(tempDir) // Clean up when done

	logger.Info("Created test directory", zap.String("path", tempDir))

	// Create a context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("Received signal, shutting down", zap.String("signal", sig.String()))
		cancel()
	}()

	// Set a custom configuration with a higher file size threshold
	customConfig := filewalker.Config{
		MaxSizeThreshold: 1024 * 1024, // 1MB threshold instead of the default
		SuspiciousExtensions: []string{
			".exe", ".dll", ".bat", ".sh", ".py", ".js",
		},
	}
	filewalker.SetConfigForTest(customConfig)

	// Define a handler for file events
	eventHandler := func(event filewalker.FileEvent) {
		fmt.Printf("\n--- File Event Detected ---\n")
		fmt.Printf("Path: %s\n", event.Path)
		fmt.Printf("Size: %d bytes\n", event.Size)
		fmt.Printf("Modified: %s\n", event.ModTime.Format(time.RFC3339))
		fmt.Printf("Hash: %s\n", event.Hash)

		if event.Process != "" {
			fmt.Printf("Process: %s (PID: %d)\n", event.Process, event.PID)
			if event.ParentProcess != "" {
				fmt.Printf("Parent Process: %s (PPID: %d)\n", event.ParentProcess, event.PPID)
			}
			if event.CmdLine != "" {
				fmt.Printf("Command Line: %s\n", event.CmdLine)
			}
			if len(event.NetConnections) > 0 {
				fmt.Printf("Network Connections:\n")
				for _, conn := range event.NetConnections {
					fmt.Printf("  - %s\n", conn)
				}
			}
		}

		if event.Suspicious {
			fmt.Printf("⚠️ SUSPICIOUS: %s\n", event.Reason)
		}
		fmt.Printf("---------------------------\n")
	}

	// Start monitoring
	logger.Info("Starting file monitor", zap.String("directory", tempDir))
	monitor, err := filewalker.MonitorDirectories(
		ctx,
		[]string{tempDir},
		true, // Watch recursively
		eventHandler,
		logger,
	)
	if err != nil {
		logger.Fatal("Failed to start file monitor", zap.Error(err))
	}
	defer monitor.Stop()

	// Create a test file to demonstrate monitoring
	go func() {
		// Wait a moment for the monitor to start
		time.Sleep(1 * time.Second)

		testFilePath := filepath.Join(tempDir, "test_file.txt")
		logger.Info("Creating test file", zap.String("path", testFilePath))

		// Create the file
		file, err := os.Create(testFilePath)
		if err != nil {
			logger.Error("Failed to create test file", zap.Error(err))
			return
		}

		// Write some data
		_, err = file.WriteString("This is a test file created by the monitor example.\n")
		if err != nil {
			logger.Error("Failed to write to test file", zap.Error(err))
			file.Close()
			return
		}
		file.Close()

		// Wait a moment and modify the file
		time.Sleep(2 * time.Second)
		logger.Info("Modifying test file", zap.String("path", testFilePath))

		file, err = os.OpenFile(testFilePath, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			logger.Error("Failed to open test file for modification", zap.Error(err))
			return
		}

		_, err = file.WriteString("This line was added in a second write operation.\n")
		if err != nil {
			logger.Error("Failed to append to test file", zap.Error(err))
		}
		file.Close()

		// Create a subdirectory and a file in it
		time.Sleep(1 * time.Second)
		subDir := filepath.Join(tempDir, "subdir")
		logger.Info("Creating subdirectory", zap.String("path", subDir))
		if err := os.Mkdir(subDir, 0755); err != nil {
			logger.Error("Failed to create subdirectory", zap.Error(err))
			return
		}

		// Create a file in the subdirectory
		time.Sleep(1 * time.Second)
		subFilePath := filepath.Join(subDir, "subdir_file.txt")
		logger.Info("Creating file in subdirectory", zap.String("path", subFilePath))
		file, err = os.Create(subFilePath)
		if err != nil {
			logger.Error("Failed to create file in subdirectory", zap.Error(err))
			return
		}
		_, err = file.WriteString("This file is in a subdirectory.\n")
		if err != nil {
			logger.Error("Failed to write to file in subdirectory", zap.Error(err))
		}
		file.Close()
	}()

	// Print instructions
	fmt.Println("\nFile monitor is running. Monitoring test directory for file events.")
	fmt.Println("Press Ctrl+C to exit.")

	// Wait for context cancellation
	<-ctx.Done()
	logger.Info("File monitor stopped")
}
