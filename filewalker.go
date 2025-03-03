package filewalker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// --------------------------------------------------------------------------
// Threat Detection Types and Global Alert Store
// --------------------------------------------------------------------------

type FileEvent struct {
	Path           string      `json:"path"`
	Hash           string      `json:"hash"`
	Size           int64       `json:"size"`
	Mode           os.FileMode `json:"mode"`
	ModTime        time.Time   `json:"mod_time"`
	Suspicious     bool        `json:"suspicious"`
	Reason         string      `json:"reason"`
	Timestamp      time.Time   `json:"timestamp"`
	User           string      `json:"user,omitempty"`            // User who owns the file (if available)
	Process        string      `json:"process,omitempty"`         // Process associated to the file (if available) - Requires more advanced monitoring
	ParentProcess  string      `json:"parent_process,omitempty"`  // Useful in advanced investigations
	PID            int         `json:"pid,omitempty"`             // Process ID that modified the file
	PPID           int         `json:"ppid,omitempty"`            // Parent Process ID
	CmdLine        string      `json:"cmdline,omitempty"`         // Full command line of the process
	NetConnections []string    `json:"net_connections,omitempty"` // Network connections associated with the process
}

// Global alert store (with improved concurrency handling).
var (
	alerts atomic.Value // Use atomic.Value for safe concurrent access
)

func init() {
	alerts.Store([]FileEvent{}) // Initialize with an empty slice
}

// addAlert safely appends a new alert.
func addAlert(event FileEvent) {
	currentAlerts := alerts.Load().([]FileEvent) // Load the current slice
	newAlerts := append(currentAlerts, event)    // Create a new slice
	alerts.Store(newAlerts)                      // Atomically update
}

// getAlerts returns a copy the alert list (read-only).
func getAllAlerts() []FileEvent {
	return alerts.Load().([]FileEvent)
}

// --------------------------------------------------------------------------
//
//	Configuration and External Data
//
// --------------------------------------------------------------------------
type Config struct {
	MaliciousHashes      map[string]bool `json:"malicious_hashes"`
	SuspiciousExtensions []string        `json:"suspicious_extensions"`
	MaxSizeThreshold     int64           `json:"max_size_threshold"` // In bytes
	YaraRules            []string        // Add Yara rules support
	ThreatFeedURL        string          `json:"threat_feed_url"`      // URL for dynamic threat feed
	ThreatFeedInterval   time.Duration   `json:"threat_feed_interval"` // How often to refresh
	LogFilePath          string          `json:"log_file_path"`        // Path for log file
}

var (
	globalConfig Config
	configMutex  = &sync.RWMutex{}
)

// Load configuration from external sources (file, env, etc.) - Good for production.
func LoadConfig(configPath string) error {
	configMutex.Lock()
	defer configMutex.Unlock()

	file, err := os.Open(configPath)
	if err != nil {
		//if the config file doesnt exist return without error
		if errors.Is(err, os.ErrNotExist) {
			globalConfig = Config{
				MaliciousHashes:      make(map[string]bool),
				SuspiciousExtensions: []string{".exe", ".dll", ".bat", ".ps1", ".vbs"}, // Common suspicious extensions
				MaxSizeThreshold:     100 * 1024 * 1024,                                // Default: 100MB
				ThreatFeedURL:        "",                                               // No default - requires user config
				ThreatFeedInterval:   24 * time.Hour,                                   // Default once a day
			}
			return nil
		}
		return fmt.Errorf("error opening config file: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&globalConfig); err != nil {
		return fmt.Errorf("error decoding config file: %w", err)
	}

	// Initialize malicious hashes map if it's nil (important for first run/empty config)
	if globalConfig.MaliciousHashes == nil {
		globalConfig.MaliciousHashes = make(map[string]bool)
	}
	return nil
}

// GetConfig returns a *copy* of the current configuration (thread-safe).
func GetConfig() Config {
	configMutex.RLock()
	defer configMutex.RUnlock()
	// Create a deep copy to prevent modification of the global config
	cfgCopy := globalConfig
	cfgCopy.MaliciousHashes = make(map[string]bool)
	for k, v := range globalConfig.MaliciousHashes {
		cfgCopy.MaliciousHashes[k] = v
	}

	// Create a deep copy of the yara rules
	cfgCopy.YaraRules = make([]string, len(globalConfig.YaraRules))
	copy(cfgCopy.YaraRules, globalConfig.YaraRules)

	//Create a deep copy of suspicious extensions
	copy(cfgCopy.SuspiciousExtensions, globalConfig.SuspiciousExtensions)
	return cfgCopy
}

// SetConfigForTest sets the global configuration for testing purposes.
// This function should only be used in tests.
func SetConfigForTest(cfg Config) {
	configMutex.Lock()
	defer configMutex.Unlock()

	// Make a deep copy of the config
	globalConfig = cfg

	// Initialize maps if they're nil
	if globalConfig.MaliciousHashes == nil {
		globalConfig.MaliciousHashes = make(map[string]bool)
	}

	// Copy slices
	if len(cfg.YaraRules) > 0 {
		globalConfig.YaraRules = make([]string, len(cfg.YaraRules))
		copy(globalConfig.YaraRules, cfg.YaraRules)
	}

	if len(cfg.SuspiciousExtensions) > 0 {
		globalConfig.SuspiciousExtensions = make([]string, len(cfg.SuspiciousExtensions))
		copy(globalConfig.SuspiciousExtensions, cfg.SuspiciousExtensions)
	}
}

// HTTPClientInterface defines the interface for HTTP clients
type HTTPClientInterface interface {
	Get(url string) (*http.Response, error)
}

// HTTPClient is the client used for HTTP requests, can be mocked in tests
var HTTPClient HTTPClientInterface = http.DefaultClient

// UpdateThreatFeed fetches and updates the malicious hashes from a threat feed.
// Exported for testing.
func UpdateThreatFeed(logger *zap.Logger) error {
	return updateThreatFeed(logger)
}

// updateThreatFeed fetches and updates the malicious hashes from a threat feed.
func updateThreatFeed(logger *zap.Logger) error {
	config := GetConfig()

	if config.ThreatFeedURL == "" {
		logger.Info("Threat feed URL not configured. Skipping update.")
		return nil // Not an error condition
	}

	resp, err := HTTPClient.Get(config.ThreatFeedURL)
	if err != nil {
		return fmt.Errorf("error fetching threat feed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("threat feed returned non-200 status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading threat feed response: %w", err)
	}

	// Simple format:  one hash per line.  Adapt to your threat feed's format.
	newHashes := make(map[string]bool)
	hashPattern := regexp.MustCompile(`^[a-f0-9]{64}$`)
	lines := regexp.MustCompile(`\r?\n`).Split(string(body), -1)

	logger.Info("Processing threat feed", zap.Int("line_count", len(lines)))

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" {
			continue
		}

		// Basic validation - does it look like a SHA256 hash?
		if hashPattern.MatchString(trimmedLine) {
			newHashes[trimmedLine] = true
			logger.Info("Valid hash found",
				zap.String("hash", trimmedLine),
				zap.Int("length", len(trimmedLine)))
		} else {
			logger.Warn("Invalid hash format in threat feed",
				zap.String("line", trimmedLine),
				zap.Int("length", len(trimmedLine)),
				zap.Bool("matches_pattern", hashPattern.MatchString(trimmedLine)))
		}
	}

	logger.Info("Processed threat feed", zap.Int("valid_hashes", len(newHashes)))

	configMutex.Lock()
	defer configMutex.Unlock()

	// Initialize malicious hashes map if it's nil
	if globalConfig.MaliciousHashes == nil {
		globalConfig.MaliciousHashes = make(map[string]bool)
	}

	// Merge with existing hashes.  New feed entries overwrite existing ones.
	for k, v := range newHashes {
		globalConfig.MaliciousHashes[k] = v
	}

	logger.Info("Threat feed updated",
		zap.Int("new_hashes", len(newHashes)),
		zap.Int("total_hashes", len(globalConfig.MaliciousHashes)))

	return nil
}

// --------------------------------------------------------------------------
// File Hashing & Analysis Functions
// --------------------------------------------------------------------------

func computeFileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err // Don't wrap here; original error is more useful
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err // Don't wrap; io.Copy could be interrupted, etc.
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// computeFastFileHash computes a SHA-256 hash of the first and last 1MB chunks of a file
// This is much faster than hashing the entire file while still providing good detection capabilities
func computeFastFileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	buf := make([]byte, 1024*1024) // 1MB buffer

	// Read first chunk
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return "", err
	}
	if n > 0 {
		h.Write(buf[:n])
	}

	// Seek to last chunk if file is larger than 1MB
	stat, err := f.Stat()
	if err != nil {
		return "", err
	}
	if stat.Size() > int64(n) {
		_, err = f.Seek(-int64(len(buf)), io.SeekEnd)
		// If seeking from end fails (e.g., file is smaller than buffer),
		// we've already read the whole file in the first chunk
		if err == nil {
			n, err = io.ReadFull(f, buf)
			if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
				return "", err
			}
			if n > 0 {
				h.Write(buf[:n])
			}
		}
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// isMaliciousHash checks against the *current* set of malicious hashes.
func isMaliciousHash(hash string) bool {
	config := GetConfig() // Get a *copy* of the config
	return config.MaliciousHashes[hash]
}

// analyzeFile performs comprehensive file analysis.
func analyzeFile(ctx context.Context, path string, info os.FileInfo, logger *zap.Logger) (FileEvent, error) {
	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return FileEvent{}, ctx.Err()
	default:
	}

	// Get the current configuration
	config := GetConfig()

	event := FileEvent{
		Path:      path,
		Size:      info.Size(),
		Mode:      info.Mode(),
		ModTime:   info.ModTime(),
		Timestamp: time.Now(),
		User:      getUser(info),
	}

	// Check if the file is suspicious based on extension
	ext := strings.ToLower(filepath.Ext(path))
	for _, suspiciousExt := range config.SuspiciousExtensions {
		if ext == suspiciousExt {
			event.Suspicious = true
			event.Reason = fmt.Sprintf("Suspicious file extension: %s", ext)
			break
		}
	}

	// Check if the file is suspicious based on size
	if config.MaxSizeThreshold > 0 && info.Size() > config.MaxSizeThreshold {
		event.Suspicious = true
		event.Reason = "File size exceeds configured threshold."
	}

	// Get process information (Linux only)
	if runtime.GOOS == "linux" {
		procInfo, err := getProcessForFile(path)
		if err == nil {
			event.Process = procInfo.ProcessName
			event.ParentProcess = procInfo.ProcessName
			event.PID = procInfo.PID
			event.PPID = procInfo.PPID
			event.CmdLine = procInfo.CmdLine
			event.NetConnections = procInfo.NetConnections
			logger.Debug("Found process information for file",
				zap.String("path", path),
				zap.String("process", event.Process),
				zap.Int("pid", event.PID))
		}
	}

	// Compute file hash (use fast hashing for large files)
	var hash string
	var hashErr error

	// Use fast hashing for files larger than 10MB
	if info.Size() > 10*1024*1024 {
		logger.Debug("Using fast hash for large file",
			zap.String("path", path),
			zap.Int64("size_bytes", info.Size()))

		hash, hashErr = computeFastFileHash(path)
		if hashErr != nil {
			logger.Debug("Failed to compute fast hash, falling back to regular hash",
				zap.String("path", path),
				zap.Error(hashErr))

			// Fall back to regular hashing if fast hashing fails
			hash, hashErr = computeFileHash(path)
		}
	} else {
		hash, hashErr = computeFileHash(path)
	}

	if hashErr != nil {
		logger.Debug("Failed to compute hash",
			zap.String("path", path),
			zap.Error(hashErr))

		// Set a placeholder hash value
		hash = "hash_computation_failed"
	} else {
		// Check if the hash is in the malicious hashes list
		if isMaliciousHash(hash) {
			event.Suspicious = true
			event.Reason = "File hash matches known malicious hash."
			logger.Warn("Malicious file detected",
				zap.String("path", path),
				zap.String("hash", hash))
		}
	}

	event.Hash = hash

	return event, nil
}

// --------------------------------------------------------------------------
// HTTP API for Alert Retrieval (Enhanced with basic auth)
// --------------------------------------------------------------------------

// BasicAuthMiddleware provides basic authentication.  In production, use a *real* auth system.
func BasicAuthMiddleware(next http.HandlerFunc, username, password string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != username || pass != password {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// alertsHandler returns a JSON list of all detected alerts.
func alertsHandler(w http.ResponseWriter, r *http.Request) {
	alerts := getAllAlerts() // Get the alerts.
	w.Header().Set("Content-Type", "application/json")
	// Encode will work fine here because alerts is a copy.
	json.NewEncoder(w).Encode(alerts)
}

// --------------------------------------------------------------------------
// Filewalker Core Types and Functions (Enhanced)
// --------------------------------------------------------------------------

type ProgressFn func(stats Stats)

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

func (s *Stats) updateDerivedStats() {
	filesProcessed := atomic.LoadInt64(&s.FilesProcessed)
	bytesProcessed := atomic.LoadInt64(&s.BytesProcessed)

	if filesProcessed > 0 {
		s.AvgFileSize = bytesProcessed / filesProcessed
	}

	elapsedSec := s.ElapsedTime.Seconds()
	if elapsedSec > 0 && bytesProcessed > 0 {
		megabytes := float64(bytesProcessed) / (1024.0 * 1024.0)
		s.SpeedMBPerSec = megabytes / elapsedSec
	} else {
		s.SpeedMBPerSec = 0
	}
}

type ErrorHandling int

const (
	ErrorHandlingContinue ErrorHandling = iota
	ErrorHandlingStop
	ErrorHandlingSkip
)

type SymlinkHandling int

const (
	SymlinkFollow SymlinkHandling = iota
	SymlinkIgnore
	SymlinkReport
)

type MemoryLimit struct {
	SoftLimit int64 // Pause processing
	HardLimit int64 // Stop processing
}

// LogLevel uses zapcore.Level for better integration with zap.
type LogLevel zapcore.Level

const (
	LogLevelError LogLevel = LogLevel(zapcore.ErrorLevel)
	LogLevelWarn  LogLevel = LogLevel(zapcore.WarnLevel)
	LogLevelInfo  LogLevel = LogLevel(zapcore.InfoLevel)
	LogLevelDebug LogLevel = LogLevel(zapcore.DebugLevel)
)

type WalkOptions struct {
	ErrorHandling   ErrorHandling
	Filter          FilterOptions
	Progress        ProgressFn
	Logger          *zap.Logger
	LogLevel        LogLevel
	BufferSize      int
	SymlinkHandling SymlinkHandling
	MemoryLimit     MemoryLimit
}
type FilterOptions struct {
	MinSize        int64
	MaxSize        int64
	Pattern        string
	ExcludeDir     []string
	IncludeTypes   []string
	ModifiedAfter  time.Time
	ModifiedBefore time.Time
}

// --------------------------------------------------------------------------
//  Core Filewalker Functions (Concurrent Traversal)
// --------------------------------------------------------------------------

type walkArgs struct {
	path string
	info os.FileInfo
	err  error
}

// WalkLimit provides controlled concurrency.
func WalkLimit(ctx context.Context, root string, walkFn filepath.WalkFunc, limit int) error {
	if limit < 1 {
		return errors.New("concurrency limit must be greater than zero")
	}

	// Default options in case WalkWithOptions is not used
	logger := createLogger(LogLevelInfo, "")
	defer logger.Sync()

	tasks := make(chan walkArgs, limit)
	var tasksWg sync.WaitGroup
	var workerWg sync.WaitGroup

	// Error collection.
	var walkErrors []error
	var errLock sync.Mutex

	// Context cancellation check is now in *one* place.

	worker := func() {
		defer workerWg.Done()
		for task := range tasks {
			// Centralized context check
			if ctx.Err() != nil {
				tasksWg.Done() // Complete the task.
				continue       // Skip processing
			}
			if err := walkFn(task.path, task.info, task.err); err != nil {
				// Context cancellation should *not* be treated as an error by default
				if errors.Is(err, context.Canceled) {
					continue
				}

				if !errors.Is(err, filepath.SkipDir) {
					errLock.Lock()
					walkErrors = append(walkErrors, fmt.Errorf("path %q: %w", task.path, err))
					errLock.Unlock()
				}
			}
			tasksWg.Done()
		}
	}

	// Launch worker pool.
	for i := 0; i < limit; i++ {
		workerWg.Add(1)
		go worker()
	}
	// Producer: traverse the directory tree, handling context.
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {

		if ctx.Err() != nil {
			return context.Canceled // Clean termination signal
		}

		if info == nil {
			// This can happen if the file/directory is removed during traversal
			return nil
		}
		if info.IsDir() {
			// If directory visit returns SkipDir, respect it immediately
			ret := walkFn(path, info, err)
			if errors.Is(ret, filepath.SkipDir) {
				return filepath.SkipDir
			}
			if ret != nil {
				if errors.Is(ret, context.Canceled) {
					return context.Canceled
				}
				errLock.Lock()
				walkErrors = append(walkErrors, ret)
				errLock.Unlock()
			}
		} else {
			tasksWg.Add(1)
			select {
			case <-ctx.Done():
				tasksWg.Done()
				return context.Canceled // Consistent cancellation
			case tasks <- walkArgs{path: path, info: info, err: err}: // Send the task to the worker

			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, filepath.SkipDir) && !errors.Is(err, context.Canceled) {
		errLock.Lock()
		walkErrors = append(walkErrors, err) // Initial walk error
		errLock.Unlock()
	}

	close(tasks)
	tasksWg.Wait()
	workerWg.Wait()

	if len(walkErrors) > 0 {
		//Consistent error wrapping
		return errors.Join(walkErrors...)
	}

	// Check if the context was canceled and return that error
	if ctx.Err() != nil {
		return ctx.Err()
	}

	return nil
}

// WalkLimitWithOptions provides flexible, enterprise-grade traversal.
func WalkLimitWithOptions(ctx context.Context, root string, walkFn filepath.WalkFunc, opts WalkOptions) error {
	if opts.BufferSize < 1 {
		opts.BufferSize = 100 // Default buffer size
	}

	logger := opts.Logger
	if logger == nil {
		logger = createLogger(opts.LogLevel, GetConfig().LogFilePath)
		defer logger.Sync()
	}

	// Log the start of the walk operation
	logger.Debug("starting walk with options",
		zap.String("root", root),
		zap.Int("buffer_size", opts.BufferSize),
		zap.Any("filter", opts.Filter))

	stats := &Stats{}
	startTime := time.Now()

	// Clear symlink cache to prevent issues across multiple calls.
	visitedSymlinks = sync.Map{}

	wrappedWalkFn := func(path string, info os.FileInfo, err error) error {
		// Context cancellation takes highest priority.
		if ctx.Err() != nil {
			return context.Canceled // Consistent return
		}

		if err != nil {
			if opts.Progress != nil {
				atomic.AddInt64(&stats.ErrorCount, 1)
				stats.ElapsedTime = time.Since(startTime)
				stats.updateDerivedStats()
				opts.Progress(*stats)
			}
			switch opts.ErrorHandling {
			case ErrorHandlingContinue, ErrorHandlingSkip:
				return nil
			default: // ErrorHandlingStop
				return err // Return the wrapped error
			}
		}

		// Check for nil info *after* error handling
		if info == nil {
			return nil // Nothing to do if info is nil
		}

		// Directories: Process synchronously for filtering and recursion control
		if info.IsDir() {
			if shouldSkipDir(path, root, opts.Filter.ExcludeDir) {
				return filepath.SkipDir
			}
		} else {
			// ------ Core Threat Detection ------
			parent := filepath.Dir(path)
			if shouldSkipDir(parent, root, opts.Filter.ExcludeDir) {
				return nil //Skip files within excluded directories
			}
			if !filePassesFilter(path, info, opts.Filter, opts.SymlinkHandling) {
				return nil
			}

			// Check Memory limits

			if opts.MemoryLimit.SoftLimit > 0 {
				currentMemory := getMemoryUsage() // Implement this function
				if currentMemory >= opts.MemoryLimit.SoftLimit {

					logger.Warn("Soft memory limit reached, pausing...", zap.Int64("current_memory", currentMemory), zap.Int64("limit", opts.MemoryLimit.SoftLimit))
					for currentMemory >= opts.MemoryLimit.SoftLimit {
						time.Sleep(1 * time.Second)      // Adjust sleep duration
						currentMemory = getMemoryUsage() // Update current memory usage
					}
					logger.Info("Resuming processing...")

				}
			}
			if opts.MemoryLimit.HardLimit > 0 {
				currentMemory := getMemoryUsage()
				if currentMemory >= opts.MemoryLimit.HardLimit {
					logger.Error("Hard memory limit reached... Aborting", zap.Int64("current_memory", currentMemory), zap.Int64("limit", opts.MemoryLimit.HardLimit))
					return errors.New("hard memory limit exceeded")
				}
			}

			event, analysisErr := analyzeFile(ctx, path, info, logger) // Pass context and logger
			if analysisErr != nil {
				logger.Error("failed to analyze file", zap.String("path", path), zap.Error(analysisErr))
			} else if event.Suspicious {
				logger.Warn("suspicious file detected", zap.String("path", path), zap.String("reason", event.Reason), zap.String("user", event.User))
				addAlert(event)
			}
		}
		// ------ End Threat Detection ------

		// Progress reporting (atomic updates for concurrency safety)
		if opts.Progress != nil {
			if info.IsDir() {
				atomic.AddInt64(&stats.DirsProcessed, 1)
				if !hasFiles(path) {
					atomic.AddInt64(&stats.EmptyDirs, 1)
				}
			} else {
				atomic.AddInt64(&stats.FilesProcessed, 1)
				atomic.AddInt64(&stats.BytesProcessed, info.Size()) // Safe: Size() is valid for files
			}
			stats.ElapsedTime = time.Since(startTime) // Accurate elapsed time
			stats.updateDerivedStats()                // Compute derived stats
			opts.Progress(*stats)                     // Report progress
		}

		err = walkFn(path, info, nil) // Consistent: always nil error
		if err != nil {
			if opts.Progress != nil {
				atomic.AddInt64(&stats.ErrorCount, 1)
				stats.ElapsedTime = time.Since(startTime)
				stats.updateDerivedStats()
				opts.Progress(*stats)
			}
			switch opts.ErrorHandling {
			case ErrorHandlingContinue, ErrorHandlingSkip:
				return nil
			case ErrorHandlingStop:
				return err
			}
		}
		return nil
	}

	// Perform the actual walk operation
	err := WalkLimit(ctx, root, wrappedWalkFn, opts.BufferSize)
	if errors.Is(err, filepath.SkipDir) {
		return nil // SkipDir at the root is not an error
	}
	return err // Return the error (possibly nil) from WalkLimit
}

// WalkLimitWithFilter walks the file tree with a limit on concurrency and applies filtering.
// Exported for testing.
func WalkLimitWithFilter(ctx context.Context, root string, walkFn filepath.WalkFunc, limit int, filter FilterOptions) error {
	opts := WalkOptions{
		Filter: filter,
	}
	return WalkLimitWithOptions(ctx, root, walkFn, opts)
}

// WalkLimitWithProgress walks the file tree with a limit on concurrency and reports progress.
// Exported for testing.
func WalkLimitWithProgress(ctx context.Context, root string, walkFn filepath.WalkFunc, limit int, progressFn ProgressFn) error {
	opts := WalkOptions{
		Progress: progressFn,
	}
	return WalkLimitWithOptions(ctx, root, walkFn, opts)
}

// --------------------------------------------------------------------------
// Internal Helper Functions (Filtering, Symlink Handling, Logging, User)
// --------------------------------------------------------------------------
var (
	excludedDirs    sync.Map // Cache for excluded directories
	visitedSymlinks sync.Map
	symlinkLock     sync.Mutex
)

func isCyclicSymlink(path string) bool {
	if _, seen := visitedSymlinks.Load(path); seen {
		return true // Already seen this path
	}
	symlinkLock.Lock()
	defer symlinkLock.Unlock()
	if _, seen := visitedSymlinks.Load(path); seen {

		return true
	}

	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false // Can't resolve; treat as non-cyclic
	}

	// Check if resolved path was already visited
	if _, seen := visitedSymlinks.Load(realPath); seen {
		return true
	}

	visitedSymlinks.Store(path, struct{}{})     // Mark original path
	visitedSymlinks.Store(realPath, struct{}{}) // Mark *resolved* path.

	return false
}

func shouldSkipDir(path, root string, excludes []string) bool {
	if len(excludes) == 0 {
		return false
	}
	if _, found := excludedDirs.Load(path); found {
		return true // Already decided to skip
	}

	dir := path
	for dir != root && dir != "." { // Safer loop condition
		for _, exclude := range excludes {
			if matched, _ := filepath.Match(exclude, filepath.Base(dir)); matched {
				excludedDirs.Store(path, struct{}{}) // Cache decision
				return true                          // Skip
			}
		}
		dir = filepath.Dir(dir) // Go up one level
		if dir == "" || dir == string(os.PathSeparator) {
			break // Stop at root or invalid path
		}

	}
	return false
}

func filePassesFilter(path string, info os.FileInfo, filter FilterOptions, symlinkHandling SymlinkHandling) bool {
	if info.Mode()&os.ModeSymlink != 0 {
		switch symlinkHandling {
		case SymlinkIgnore:
			return false
		case SymlinkFollow:
			if isCyclicSymlink(path) {
				return false // Avoid cycles
			}
		case SymlinkReport:
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
			return false // Invalid pattern or no match
		}
	}
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

func createLogger(level LogLevel, logFilePath string) *zap.Logger {
	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zapcore.Level(level))

	// Enable file output if a path is provided
	if logFilePath != "" {
		config.OutputPaths = []string{logFilePath, "stderr"} // Log to file AND console
		config.ErrorOutputPaths = []string{logFilePath, "stderr"}
	}

	logger, err := config.Build()
	if err != nil {
		panic(fmt.Sprintf("failed to initialize logger: %v", err)) // Fatal error
	}
	return logger
}

// hasFiles checks if dir contains any entries at all.
func hasFiles(dir string) bool {
	entries, err := os.ReadDir(dir)
	return err == nil && len(entries) > 0
}

// ------- OS Specific Helpers -----
// getUser retrieves the file owner (platform-specific).  Implemented in os_specific.go
func getUser(info os.FileInfo) string {
	return getOSUser(info) // os_specific.go
}

// getMemoryUsage retrieves current memory usage (platform-specific). Implemented in os_specific.go
func getMemoryUsage() int64 {
	return getOSMemoryUsage() // os_specific.go,
}

// matchYaraRules performs YARA rule matching (platform-specific). Implemented in os_specific.go
func matchYaraRules(path string, yaraRules []string) ([]string, error) {
	return matchOSYaraRules(path, yaraRules) // os_specific.go
}

// --------------------------------------------------------------------------
// Process Tracking Functions
// --------------------------------------------------------------------------

// ProcessInfo contains information about a process
type ProcessInfo struct {
	PID            int
	PPID           int
	ProcessName    string
	CmdLine        string
	NetConnections []string
}

// getProcessForFile attempts to find which process has the file open
// This works on Linux systems by examining /proc/[pid]/fd
func getProcessForFile(path string) (ProcessInfo, error) {
	result := ProcessInfo{}

	// This only works on Linux
	if runtime.GOOS != "linux" {
		return result, fmt.Errorf("process tracking only supported on Linux")
	}

	// Get absolute path for comparison
	absPath, err := filepath.Abs(path)
	if err != nil {
		return result, err
	}

	f, err := os.Open("/proc")
	if err != nil {
		return result, err
	}
	defer f.Close()

	files, err := f.Readdirnames(0)
	if err != nil {
		return result, err
	}

	for _, file := range files {
		// Only look at directories that are numbers (PIDs)
		pid, err := strconv.Atoi(file)
		if err != nil {
			continue
		}

		// Check if this process has the file open
		fdPath := fmt.Sprintf("/proc/%s/fd", file)
		fds, err := filepath.Glob(fdPath + "/*")
		if err != nil {
			continue
		}

		for _, fd := range fds {
			target, err := os.Readlink(fd)
			if err != nil {
				continue
			}

			// If this process has the file open
			if target == absPath {
				result.PID = pid

				// Get process name from /proc/[pid]/comm
				if commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%s/comm", file)); err == nil {
					result.ProcessName = strings.TrimSpace(string(commBytes))
				}

				// Get command line from /proc/[pid]/cmdline
				if cmdlineBytes, err := os.ReadFile(fmt.Sprintf("/proc/%s/cmdline", file)); err == nil {
					// cmdline uses null bytes as separators, replace with spaces for readability
					cmdline := strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")
					result.CmdLine = strings.TrimSpace(cmdline)
				}

				// Get parent PID from /proc/[pid]/status
				if statusBytes, err := os.ReadFile(fmt.Sprintf("/proc/%s/status", file)); err == nil {
					statusLines := strings.Split(string(statusBytes), "\n")
					for _, line := range statusLines {
						if strings.HasPrefix(line, "PPid:") {
							ppidStr := strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
							if ppid, err := strconv.Atoi(ppidStr); err == nil {
								result.PPID = ppid
							}
							break
						}
					}
				}

				// Get network connections from /proc/[pid]/net/tcp and /proc/[pid]/net/udp
				// This is a simplified version - a real implementation would parse these files
				// to extract actual connection information
				result.NetConnections = getNetworkConnections(pid)

				return result, nil
			}
		}
	}

	return result, fmt.Errorf("no process found for file")
}

// getNetworkConnections returns a list of network connections for a process
func getNetworkConnections(pid int) []string {
	var connections []string

	// Read TCP connections
	if tcpBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/tcp", pid)); err == nil {
		tcpLines := strings.Split(string(tcpBytes), "\n")
		// Skip header line
		for i := 1; i < len(tcpLines); i++ {
			line := strings.TrimSpace(tcpLines[i])
			if line == "" {
				continue
			}

			// Parse the line to extract connection information
			// Format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}

			// Extract local and remote addresses
			localAddr := parseHexAddress(fields[1])
			remoteAddr := parseHexAddress(fields[2])

			connections = append(connections, fmt.Sprintf("TCP %s -> %s", localAddr, remoteAddr))
		}
	}

	// Read UDP connections
	if udpBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/udp", pid)); err == nil {
		udpLines := strings.Split(string(udpBytes), "\n")
		// Skip header line
		for i := 1; i < len(udpLines); i++ {
			line := strings.TrimSpace(udpLines[i])
			if line == "" {
				continue
			}

			// Parse the line to extract connection information
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}

			// Extract local and remote addresses
			localAddr := parseHexAddress(fields[1])

			connections = append(connections, fmt.Sprintf("UDP %s", localAddr))
		}
	}

	return connections
}

// parseHexAddress converts a hex address from /proc/net/tcp or /proc/net/udp to a human-readable format
func parseHexAddress(hexAddr string) string {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return hexAddr
	}

	// Convert hex IP to decimal
	ipHex := parts[0]
	if len(ipHex) != 8 {
		return hexAddr
	}

	// IP address is stored in little-endian format
	ip := net.IP{
		byte(mustParseUint(ipHex[6:8], 16)),
		byte(mustParseUint(ipHex[4:6], 16)),
		byte(mustParseUint(ipHex[2:4], 16)),
		byte(mustParseUint(ipHex[0:2], 16)),
	}

	// Convert hex port to decimal
	port := mustParseUint(parts[1], 16)

	return fmt.Sprintf("%s:%d", ip.String(), port)
}

// mustParseUint parses a hex string to uint64 or returns 0 if there's an error
func mustParseUint(s string, base int) uint64 {
	v, err := strconv.ParseUint(s, base, 64)
	if err != nil {
		return 0
	}
	return v
}

// --------------------------------------------------------------------------
// Real-time File Monitoring
// --------------------------------------------------------------------------

// FileMonitorOptions contains options for real-time file monitoring
type FileMonitorOptions struct {
	Paths           []string        // Paths to monitor
	RecursiveWatch  bool            // Whether to watch directories recursively
	EventHandler    func(FileEvent) // Function to call when a file event is detected
	ExcludePaths    []string        // Paths to exclude from monitoring
	IncludePatterns []string        // File patterns to include (e.g., "*.exe")
	ExcludePatterns []string        // File patterns to exclude
	Logger          *zap.Logger     // Logger to use
}

// FileMonitor represents a real-time file monitor
type FileMonitor struct {
	watcher       *fsnotify.Watcher
	options       FileMonitorOptions
	watchedPaths  map[string]bool
	excludedPaths map[string]bool
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	logger        *zap.Logger
}

// NewFileMonitor creates a new file monitor
func NewFileMonitor(options FileMonitorOptions) (*FileMonitor, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create watcher: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	logger := options.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	monitor := &FileMonitor{
		watcher:       watcher,
		options:       options,
		watchedPaths:  make(map[string]bool),
		excludedPaths: make(map[string]bool),
		ctx:           ctx,
		cancel:        cancel,
		logger:        logger,
	}

	// Precompute excluded paths
	for _, path := range options.ExcludePaths {
		absPath, err := filepath.Abs(path)
		if err == nil {
			monitor.excludedPaths[absPath] = true
		}
	}

	return monitor, nil
}

// Start starts the file monitor
func (m *FileMonitor) Start() error {
	// Add initial paths to watch
	for _, path := range m.options.Paths {
		if err := m.addWatchPath(path); err != nil {
			return err
		}
	}

	// Start the event processing goroutine
	m.wg.Add(1)
	go m.processEvents()

	return nil
}

// Stop stops the file monitor
func (m *FileMonitor) Stop() {
	m.cancel()
	m.watcher.Close()
	m.wg.Wait()
}

// addWatchPath adds a path to the watcher
func (m *FileMonitor) addWatchPath(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Skip if already watched or excluded
	if m.watchedPaths[absPath] || m.excludedPaths[absPath] {
		return nil
	}

	// Check if the path exists
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("failed to stat path: %w", err)
	}

	// If it's a directory and recursive watching is enabled, add all subdirectories
	if info.IsDir() && m.options.RecursiveWatch {
		err := filepath.Walk(absPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				dirPath, err := filepath.Abs(path)
				if err != nil {
					return err
				}

				// Skip if excluded
				if m.excludedPaths[dirPath] {
					return filepath.SkipDir
				}

				// Skip if already watched
				if m.watchedPaths[dirPath] {
					return nil
				}

				// Add to watcher
				if err := m.watcher.Add(dirPath); err != nil {
					m.logger.Error("Failed to watch directory",
						zap.String("path", dirPath),
						zap.Error(err))
					return nil // Continue even if we can't watch this directory
				}

				m.watchedPaths[dirPath] = true
				m.logger.Debug("Watching directory", zap.String("path", dirPath))
			}

			return nil
		})

		if err != nil {
			return fmt.Errorf("failed to walk directory: %w", err)
		}
	} else {
		// Add the path to the watcher
		if err := m.watcher.Add(absPath); err != nil {
			return fmt.Errorf("failed to watch path: %w", err)
		}

		m.watchedPaths[absPath] = true
		m.logger.Debug("Watching path", zap.String("path", absPath))
	}

	return nil
}

// processEvents processes events from the watcher
func (m *FileMonitor) processEvents() {
	defer m.wg.Done()

	for {
		select {
		case <-m.ctx.Done():
			return

		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}

			// Skip directories for file operations
			info, err := os.Stat(event.Name)
			if err == nil && info.IsDir() {
				// If a new directory is created and we're watching recursively, add it
				if event.Op&fsnotify.Create == fsnotify.Create && m.options.RecursiveWatch {
					m.addWatchPath(event.Name)
				}
				continue
			}

			// Check if the file matches include/exclude patterns
			if !m.shouldProcessFile(event.Name) {
				continue
			}

			// Process the file event
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				m.logger.Debug("File modified or created",
					zap.String("path", event.Name),
					zap.String("operation", event.Op.String()))

				// Analyze the file
				if info != nil {
					fileEvent, err := analyzeFile(m.ctx, event.Name, info, m.logger)
					if err != nil {
						m.logger.Error("Failed to analyze file",
							zap.String("path", event.Name),
							zap.Error(err))
						continue
					}

					// Perform behavioral analysis
					AnalyzeBehavior(fileEvent, m.logger)

					// Call the event handler if provided
					if m.options.EventHandler != nil {
						m.options.EventHandler(fileEvent)
					}

					// If the file is suspicious, add it to the alerts
					if fileEvent.Suspicious {
						addAlert(fileEvent)
						m.logger.Warn("Suspicious file detected",
							zap.String("path", fileEvent.Path),
							zap.String("reason", fileEvent.Reason),
							zap.String("process", fileEvent.Process),
							zap.Int("pid", fileEvent.PID))
					}
				}
			}

		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			m.logger.Error("Watcher error", zap.Error(err))
		}
	}
}

// shouldProcessFile checks if a file should be processed based on include/exclude patterns
func (m *FileMonitor) shouldProcessFile(path string) bool {
	// Check exclude paths
	absPath, err := filepath.Abs(path)
	if err == nil && m.excludedPaths[absPath] {
		return false
	}

	// Check exclude patterns
	for _, pattern := range m.options.ExcludePatterns {
		matched, err := filepath.Match(pattern, filepath.Base(path))
		if err == nil && matched {
			return false
		}
	}

	// If include patterns are specified, check if the file matches any
	if len(m.options.IncludePatterns) > 0 {
		for _, pattern := range m.options.IncludePatterns {
			matched, err := filepath.Match(pattern, filepath.Base(path))
			if err == nil && matched {
				return true
			}
		}
		return false // No include pattern matched
	}

	// No include patterns specified, so include all files that weren't excluded
	return true
}

// MonitorDirectories starts real-time monitoring of directories
func MonitorDirectories(ctx context.Context, paths []string, recursive bool, eventHandler func(FileEvent), logger *zap.Logger) (*FileMonitor, error) {
	options := FileMonitorOptions{
		Paths:          paths,
		RecursiveWatch: recursive,
		EventHandler:   eventHandler,
		Logger:         logger,
	}

	monitor, err := NewFileMonitor(options)
	if err != nil {
		return nil, err
	}

	if err := monitor.Start(); err != nil {
		monitor.Stop()
		return nil, err
	}

	// Stop the monitor when the context is done
	go func() {
		<-ctx.Done()
		monitor.Stop()
	}()

	return monitor, nil
}

// -------- Main Function & Startup Logic ---------

func Start(rootDir, configFile, httpAddr, authUser, authPassword string, concurrency int) {
	// Initialize logger
	logger := createLogger(LogLevelInfo, "")
	defer logger.Sync()

	// Load configuration
	if configFile != "" {
		if err := LoadConfig(configFile); err != nil {
			logger.Fatal("Failed to load configuration", zap.Error(err))
		}
	}

	// Start behavioral monitoring
	StartBehavioralMonitoring(logger)
	logger.Info("Behavioral monitoring initialized")

	// Start threat feed updates (if configured)
	if GetConfig().ThreatFeedURL != "" {
		go func() {
			// Initial fetch
			if err := updateThreatFeed(logger); err != nil {
				logger.Error("Error updating threat feed", zap.Error(err))
			}
			ticker := time.NewTicker(GetConfig().ThreatFeedInterval)
			defer ticker.Stop()
			for range ticker.C {
				if err := updateThreatFeed(logger); err != nil {
					logger.Error("Error updating threat feed", zap.Error(err))
				}
			}
		}()
	}

	// Start HTTP server if address is provided
	if httpAddr != "" {
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc("/alerts", BasicAuthMiddleware(alertsHandler, authUser, authPassword))

			// Add behavioral alerts endpoint
			mux.HandleFunc("/behavioral-alerts", BasicAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
				alerts := GetBehavioralAlerts()
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(alerts); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
			}, authUser, authPassword))

			logger.Info("Starting HTTP server", zap.String("address", httpAddr))
			if err := http.ListenAndServe(httpAddr, mux); err != nil {
				logger.Fatal("HTTP server failed", zap.Error(err))
			}
		}()
	}

	// Set up signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info("Received shutdown signal")
		cancel()
	}()

	// Start the file walker
	logger.Info("Starting file walker", zap.String("root", rootDir), zap.Int("concurrency", concurrency))

	// Create a progress function to log statistics
	progressFn := func(stats Stats) {
		logger.Info("Progress",
			zap.Int64("files", stats.FilesProcessed),
			zap.Int64("dirs", stats.DirsProcessed),
			zap.Int64("bytes", stats.BytesProcessed),
			zap.Float64("MB/s", stats.SpeedMBPerSec),
			zap.Duration("elapsed", stats.ElapsedTime))
	}

	// Create options for the walker
	opts := WalkOptions{
		ErrorHandling:   ErrorHandlingContinue,
		Progress:        progressFn,
		Logger:          logger,
		LogLevel:        LogLevelInfo,
		BufferSize:      concurrency * 100, // Buffer 100 items per worker
		SymlinkHandling: SymlinkReport,
	}

	// Define the walk function
	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logger.Error("Error accessing path", zap.String("path", path), zap.Error(err))
			return nil // Continue on error
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Analyze the file
		fileEvent, err := analyzeFile(ctx, path, info, logger)
		if err != nil {
			logger.Error("Failed to analyze file", zap.String("path", path), zap.Error(err))
			return nil
		}

		// Perform behavioral analysis on the file event
		AnalyzeBehavior(fileEvent, logger)

		// If the file is suspicious, add it to the alerts
		if fileEvent.Suspicious {
			addAlert(fileEvent)
			logger.Warn("Suspicious file detected",
				zap.String("path", fileEvent.Path),
				zap.String("reason", fileEvent.Reason))
		}

		return nil
	}

	// Start the walk
	if err := WalkLimitWithOptions(ctx, rootDir, walkFn, opts); err != nil && err != context.Canceled {
		logger.Error("Walk failed", zap.Error(err))
	}

	logger.Info("File walker completed")
}
