package filewalker

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// BehavioralAlert represents a suspicious behavior detected by the system
type BehavioralAlert struct {
	Timestamp    time.Time   `json:"timestamp"`
	Type         string      `json:"type"`
	Description  string      `json:"description"`
	Severity     string      `json:"severity"` // "low", "medium", "high", "critical"
	ProcessInfo  ProcessInfo `json:"process_info,omitempty"`
	FileEvent    *FileEvent  `json:"file_event,omitempty"`
	RelatedPaths []string    `json:"related_paths,omitempty"`
}

// Global store for behavioral alerts
var (
	behavioralAlerts []BehavioralAlert
	behavioralMutex  sync.RWMutex
)

// AddBehavioralAlert adds a new behavioral alert to the global store
func AddBehavioralAlert(alert BehavioralAlert) {
	behavioralMutex.Lock()
	defer behavioralMutex.Unlock()
	behavioralAlerts = append(behavioralAlerts, alert)
}

// GetBehavioralAlerts returns all behavioral alerts
func GetBehavioralAlerts() []BehavioralAlert {
	behavioralMutex.RLock()
	defer behavioralMutex.RUnlock()

	// Return a copy to prevent race conditions
	alertsCopy := make([]BehavioralAlert, len(behavioralAlerts))
	copy(alertsCopy, behavioralAlerts)
	return alertsCopy
}

// SuspiciousPaths contains paths that are sensitive and should be monitored for modifications
var SuspiciousPaths = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/sudoers",
	"/etc/ssh",
	"/etc/crontab",
	"/etc/cron.d",
	"/boot",
	"/sbin",
	"/bin",
	"/usr/bin",
	"/usr/sbin",
	"/usr/local/bin",
	"/lib",
	"/lib64",
	"/usr/lib",
	"/usr/lib64",
	"/System/Library",         // macOS
	"/Library/StartupItems",   // macOS
	"/Library/LaunchAgents",   // macOS
	"/Library/LaunchDaemons",  // macOS
	"C:\\Windows\\System32",   // Windows
	"C:\\Windows\\SysWOW64",   // Windows
	"C:\\Program Files",       // Windows
	"C:\\Program Files (x86)", // Windows
	"C:\\Windows\\Tasks",      // Windows
	"C:\\Windows\\Temp",       // Windows
}

// SuspiciousExecutionPaths contains paths that are suspicious for executing files from
var SuspiciousExecutionPaths = []string{
	"/tmp",
	"/var/tmp",
	"/dev/shm",
	"/run",
	"/var/run",
	"/proc",
	"C:\\Windows\\Temp",
	"C:\\Temp",
	"C:\\Users\\Public",
}

// SuspiciousProcessNames contains process names that are commonly associated with malicious activity
var SuspiciousProcessNames = []string{
	"nc", "netcat", "ncat", // Network utilities often used maliciously
	"socat", "cryptcat",
	"nmap", "zenmap", // Network scanning
	"wireshark", "tcpdump", // Network sniffing
	"mimikatz",           // Password stealing
	"psexec",             // Remote execution
	"powershell", "pwsh", // Often used in attacks
	"cmd.exe",           // Often used in attacks on Windows
	"bash", "sh", "zsh", // Shell access
	"python", "python3", "perl", "ruby", // Scripting languages
	"wget", "curl", // Download utilities
	"ssh", "telnet", "rdesktop", // Remote access
}

// StartBehavioralMonitoring initializes behavioral monitoring
func StartBehavioralMonitoring(logger *zap.Logger) {
	if runtime.GOOS == "linux" {
		go monitorSystemWithAudit(logger)
	}

	logger.Info("Started behavioral monitoring")
}

// monitorSystemWithAudit sets up Linux audit rules to monitor suspicious activities
func monitorSystemWithAudit(logger *zap.Logger) {
	// Check if auditctl is available
	_, err := exec.LookPath("auditctl")
	if err != nil {
		logger.Warn("auditctl not found, advanced behavioral monitoring disabled", zap.Error(err))
		return
	}

	// Monitor writes to executable paths
	execPaths := []string{"/usr/bin", "/bin", "/sbin", "/usr/sbin", "/usr/local/bin"}
	for _, path := range execPaths {
		cmd := exec.Command("auditctl", "-a", "always,exit", "-F", "path="+path, "-S", "write", "-k", "suspicious_write")
		if err := cmd.Run(); err != nil {
			logger.Error("Failed to set audit rule", zap.String("path", path), zap.Error(err))
		} else {
			logger.Info("Set audit rule for executable path", zap.String("path", path))
		}
	}

	// Monitor modifications to sensitive configuration files
	configPaths := []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config"}
	for _, path := range configPaths {
		cmd := exec.Command("auditctl", "-a", "always,exit", "-F", "path="+path, "-S", "write", "-k", "config_modification")
		if err := cmd.Run(); err != nil {
			logger.Error("Failed to set audit rule", zap.String("path", path), zap.Error(err))
		} else {
			logger.Info("Set audit rule for config file", zap.String("path", path))
		}
	}

	// Start a goroutine to read audit logs
	go readAuditLogs(logger)
}

// readAuditLogs reads and processes Linux audit logs
func readAuditLogs(logger *zap.Logger) {
	cmd := exec.Command("ausearch", "-k", "suspicious_write", "-k", "config_modification", "-i", "-ts", "recent")

	// Run the command every minute
	for {
		output, err := cmd.Output()
		if err != nil {
			logger.Error("Failed to read audit logs", zap.Error(err))
		} else {
			processAuditOutput(string(output), logger)
		}

		time.Sleep(1 * time.Minute)
	}
}

// processAuditOutput processes the output from ausearch
func processAuditOutput(output string, logger *zap.Logger) {
	lines := strings.Split(output, "\n")

	var currentAlert *BehavioralAlert

	for _, line := range lines {
		if strings.Contains(line, "type=SYSCALL") {
			// New audit record
			if currentAlert != nil {
				AddBehavioralAlert(*currentAlert)
			}

			currentAlert = &BehavioralAlert{
				Timestamp:    time.Now(),
				Type:         "file_modification",
				Severity:     "high",
				RelatedPaths: []string{},
			}
		}

		if currentAlert != nil {
			// Extract process info
			if strings.Contains(line, "pid=") {
				pidStr := extractValue(line, "pid=")
				if pid, err := parseInt(pidStr); err == nil {
					currentAlert.ProcessInfo.PID = pid
				}
			}

			if strings.Contains(line, "ppid=") {
				ppidStr := extractValue(line, "ppid=")
				if ppid, err := parseInt(ppidStr); err == nil {
					currentAlert.ProcessInfo.PPID = ppid
				}
			}

			if strings.Contains(line, "exe=") {
				exe := extractValue(line, "exe=")
				currentAlert.ProcessInfo.CmdLine = exe
				currentAlert.ProcessInfo.ProcessName = filepath.Base(exe)
			}

			// Extract file path
			if strings.Contains(line, "path=") {
				path := extractValue(line, "path=")
				currentAlert.RelatedPaths = append(currentAlert.RelatedPaths, path)

				// Set description based on the path
				if isExecutablePath(path) {
					currentAlert.Description = "Modification to executable file detected"
					currentAlert.Severity = "critical"
				} else if isConfigPath(path) {
					currentAlert.Description = "Modification to system configuration detected"
					currentAlert.Severity = "high"
				}
			}
		}
	}

	// Add the last alert if it exists
	if currentAlert != nil {
		AddBehavioralAlert(*currentAlert)
	}
}

// AnalyzeBehavior analyzes a file event for suspicious behavior
func AnalyzeBehavior(event FileEvent, logger *zap.Logger) {
	// Check for suspicious paths
	for _, path := range SuspiciousPaths {
		if strings.HasPrefix(event.Path, path) {
			alert := BehavioralAlert{
				Timestamp:    time.Now(),
				Type:         "suspicious_path_modification",
				Description:  fmt.Sprintf("Modification to sensitive path: %s", path),
				Severity:     "high",
				FileEvent:    &event,
				RelatedPaths: []string{event.Path},
			}

			if event.Process != "" {
				alert.ProcessInfo = ProcessInfo{
					PID:         event.PID,
					PPID:        event.PPID,
					ProcessName: event.Process,
					CmdLine:     event.CmdLine,
				}

				// Check if the process is running from a suspicious location
				for _, suspPath := range SuspiciousExecutionPaths {
					if strings.HasPrefix(event.CmdLine, suspPath) {
						alert.Type = "suspicious_execution_path"
						alert.Description = fmt.Sprintf("Process running from suspicious location: %s", suspPath)
						alert.Severity = "critical"
						break
					}
				}

				// Check if the process name is suspicious
				for _, suspProc := range SuspiciousProcessNames {
					if event.Process == suspProc {
						alert.Type = "suspicious_process"
						alert.Description = fmt.Sprintf("Suspicious process detected: %s", suspProc)
						alert.Severity = "medium"
						break
					}
				}

				// Check for root/admin execution
				if isRootOrAdmin(event) {
					alert.Type = "privileged_execution"
					alert.Description = "Process running with elevated privileges"
					alert.Severity = "high"
				}
			}

			AddBehavioralAlert(alert)
			logger.Warn("Behavioral alert triggered",
				zap.String("path", event.Path),
				zap.String("type", alert.Type),
				zap.String("severity", alert.Severity),
				zap.String("description", alert.Description))

			break
		}
	}

	// Check for script modifying binary
	if isScriptModifyingBinary(event) {
		alert := BehavioralAlert{
			Timestamp:    time.Now(),
			Type:         "script_modifying_binary",
			Description:  "Script process modifying binary file",
			Severity:     "critical",
			FileEvent:    &event,
			RelatedPaths: []string{event.Path},
		}

		if event.Process != "" {
			alert.ProcessInfo = ProcessInfo{
				PID:         event.PID,
				PPID:        event.PPID,
				ProcessName: event.Process,
				CmdLine:     event.CmdLine,
			}
		}

		AddBehavioralAlert(alert)
		logger.Warn("Script modifying binary detected",
			zap.String("script", event.Process),
			zap.String("binary", event.Path),
			zap.Int("pid", event.PID))
	}
}

// isScriptModifyingBinary checks if a script process is modifying a binary file
func isScriptModifyingBinary(event FileEvent) bool {
	// Check if the process is a script interpreter
	scriptInterpreters := []string{"python", "python3", "perl", "ruby", "bash", "sh", "zsh", "powershell", "pwsh", "cmd.exe"}
	isScript := false

	for _, interpreter := range scriptInterpreters {
		if strings.HasPrefix(event.Process, interpreter) {
			isScript = true
			break
		}
	}

	if !isScript {
		return false
	}

	// Check if the file being modified is a binary
	ext := strings.ToLower(filepath.Ext(event.Path))
	executableExts := []string{"", ".exe", ".dll", ".so", ".dylib", ".bin"}
	isBinary := false

	for _, execExt := range executableExts {
		if ext == execExt {
			isBinary = true
			break
		}
	}

	// On Unix-like systems, check if the file has execute permission
	if runtime.GOOS != "windows" && !isBinary {
		isBinary = (event.Mode & 0111) != 0 // Check for execute permission
	}

	return isScript && isBinary
}

// isRootOrAdmin checks if a process is running as root/admin
func isRootOrAdmin(event FileEvent) bool {
	if runtime.GOOS == "windows" {
		// On Windows, check if the process has admin privileges
		// This is a simplified check - in a real implementation, you would use Windows API
		return strings.Contains(strings.ToLower(event.CmdLine), "system32") ||
			strings.Contains(strings.ToLower(event.CmdLine), "syswow64")
	} else {
		// On Unix-like systems, check if the process is running as root (UID 0)
		return os.Geteuid() == 0
	}
}

// Helper functions
func extractValue(line, key string) string {
	parts := strings.Split(line, key)
	if len(parts) < 2 {
		return ""
	}

	valuePart := parts[1]
	endIdx := strings.IndexAny(valuePart, " \t\n")
	if endIdx == -1 {
		return valuePart
	}

	return valuePart[:endIdx]
}

func parseInt(s string) (int, error) {
	var result int
	_, err := fmt.Sscanf(s, "%d", &result)
	return result, err
}

func isExecutablePath(path string) bool {
	execPaths := []string{"/usr/bin/", "/bin/", "/sbin/", "/usr/sbin/", "/usr/local/bin/"}
	for _, execPath := range execPaths {
		if strings.HasPrefix(path, execPath) {
			return true
		}
	}
	return false
}

func isConfigPath(path string) bool {
	configPaths := []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/"}
	for _, configPath := range configPaths {
		if strings.HasPrefix(path, configPath) {
			return true
		}
	}
	return false
}
