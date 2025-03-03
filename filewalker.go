package filewalker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// --------------------------------------------------------------------------
// Threat Detection Types and Global Alert Store
// --------------------------------------------------------------------------

type FileEvent struct {
	Path          string      `json:"path"`
	Hash          string      `json:"hash"`
	Size          int64       `json:"size"`
	Mode          os.FileMode `json:"mode"`
	ModTime       time.Time   `json:"mod_time"`
	Suspicious    bool        `json:"suspicious"`
	Reason        string      `json:"reason"`
	Timestamp     time.Time   `json:"timestamp"`
	User          string      `json:"user,omitempty"`           // User who owns the file (if available)
	Process       string      `json:"process,omitempty"`        // Process associated to the file (if available) - Requires more advanced monitoring
	ParentProcess string      `json:"parent_process,omitempty"` // Useful in advanced investigations
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

// isMaliciousHash checks against the *current* set of malicious hashes.
func isMaliciousHash(hash string) bool {
	config := GetConfig() // Get a *copy* of the config
	return config.MaliciousHashes[hash]
}

// analyzeFile performs comprehensive file analysis.
func analyzeFile(ctx context.Context, path string, info os.FileInfo, logger *zap.Logger) (FileEvent, error) {
	config := GetConfig() // Thread-safe copy of config

	event := FileEvent{
		Path:      path,
		Size:      info.Size(),
		Mode:      info.Mode(),
		ModTime:   info.ModTime(),
		Timestamp: time.Now(),
	}

	// Get user information if possible
	event.User = getUser(info)

	hash, err := computeFileHash(path)
	if err != nil {
		return event, err
	}
	event.Hash = hash
	select {
	case <-ctx.Done():
		return event, ctx.Err()
	default:
	}

	// Check against known malicious hashes.
	if isMaliciousHash(hash) {
		event.Suspicious = true
		event.Reason = "File hash matches known malicious signature."
		return event, nil // Early return for clear malicious match
	}
	select {
	case <-ctx.Done():
		return event, ctx.Err()
	default:
	}

	// Check file extension.
	ext := filepath.Ext(path)
	for _, suspiciousExt := range config.SuspiciousExtensions {
		if ext == suspiciousExt {
			event.Suspicious = true
			if event.Reason != "" {
				event.Reason += " and "
			}
			event.Reason += "File has a suspicious extension."
			break
		}
	}
	select {
	case <-ctx.Done():
		return event, ctx.Err()
	default:
	}

	// Check file size.
	if info.Size() > config.MaxSizeThreshold {
		event.Suspicious = true
		if event.Reason != "" {
			event.Reason += " and "
		}
		event.Reason += "File size exceeds configured threshold."
	}

	// YARA rule matching (if configured).
	if len(config.YaraRules) > 0 {
		if yaraMatches, err := matchYaraRules(path, config.YaraRules); err != nil {
			logger.Error("Error during yara scan", zap.Error(err))
		} else if len(yaraMatches) > 0 {
			event.Suspicious = true
			if event.Reason != "" {

				event.Reason += " and "
			}
			event.Reason += fmt.Sprintf("File matches YARA rules: %v", yaraMatches)
		}
	}

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

// -------- Main Function & Startup Logic ---------

func Start(rootDir, configFile, httpAddr, authUser, authPassword string, concurrency int) {

	// Load configuration
	if err := LoadConfig(configFile); err != nil {
		//if no config is loaded exit
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	//Create the application logger
	logger := createLogger(LogLevelInfo, GetConfig().LogFilePath)
	defer logger.Sync()

	// Start threat feed updates (if configured).  Run in background.

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

	// Set up context for graceful shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start file system traversal
	go func() {
		opts := WalkOptions{
			BufferSize:      concurrency,
			ErrorHandling:   ErrorHandlingContinue,
			Filter:          FilterOptions{}, // Add any default filters
			Logger:          logger,
			LogLevel:        LogLevelInfo,
			SymlinkHandling: SymlinkFollow, // Or your preferred default
		}

		err := WalkLimitWithOptions(ctx, rootDir, func(path string, info os.FileInfo, err error) error {
			// This walk function is now *very* minimal - just logging.
			if err == nil && info != nil && !info.IsDir() {
				//Removed the file processing
				logger.Debug("Processed file", zap.String("path", path))
			}
			return nil
		}, opts) // Now using options

		if err != nil {
			logger.Error("File traversal error", zap.Error(err))
		}
	}()

	// Start HTTP server (with basic auth)
	http.HandleFunc("/alerts", BasicAuthMiddleware(alertsHandler, authUser, authPassword))
	server := &http.Server{Addr: httpAddr}

	go func() {
		logger.Info("Starting HTTP server", zap.String("address", httpAddr))
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			logger.Error("HTTP server error", zap.Error(err))
		}
	}()

	// Block until interrupt (Ctrl+C)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt) // More portable signal handling

	<-sigChan // Block until signal received
	logger.Info("Shutting down...")

	// Graceful shutdown of HTTP server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second) // Timeout for graceful shutdown
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("Error during server shutdown", zap.Error(err))
	}

	cancel() // Signal file traversal to stop
	logger.Info("Shutdown complete.")

}
