package filewalker

import (
	"os"
	"os/user"
	"runtime"
	"strconv"
	"syscall"
)

// getOSUser retrieves the file owner on Unix/Linux systems
func getOSUser(info os.FileInfo) string {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if u, err := user.LookupId(strconv.FormatUint(uint64(stat.Uid), 10)); err == nil {
			return u.Username
		}
	}
	return "unknown" // Fallback
}

// getOSMemoryUsage retrieves current process memory usage
func getOSMemoryUsage() int64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.Alloc)
}

// matchOSYaraRules is a placeholder for YARA rule matching
// In a real implementation, this would use a YARA library
func matchOSYaraRules(path string, yaraRules []string) ([]string, error) {
	// Placeholder implementation
	// In production, integrate with a YARA library like github.com/hillu/go-yara
	return []string{}, nil
}
