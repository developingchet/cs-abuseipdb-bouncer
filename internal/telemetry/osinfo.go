package telemetry

import (
	"os"
	"runtime"
	"strings"
	"sync"
)

// unknownOSVersion is reported when the OS version cannot be determined.
const unknownOSVersion = "unknown"

// osReleasePaths are the os-release(5) locations, in lookup order.
var osReleasePaths = []string{"/etc/os-release", "/usr/lib/os-release"}

// readFile reads an os-release candidate; tests replace it.
var readFile = os.ReadFile

// hostOS is detected once: the OS does not change while the process runs.
var hostOS = sync.OnceValue(detectOS)

// detectOS reports the distribution ID and VERSION_ID from os-release, the
// same values CrowdSec's own components send (for example "debian" and "12"
// in the distroless image). Without a usable os-release file (Windows, macOS,
// minimal images) it reports the Go OS name and an unknown version.
func detectOS() OSInfo {
	for _, path := range osReleasePaths {
		data, err := readFile(path)
		if err != nil {
			continue
		}
		fields := parseOSRelease(string(data))
		if fields["ID"] == "" {
			continue
		}
		version := fields["VERSION_ID"]
		if version == "" {
			version = unknownOSVersion
		}
		return OSInfo{Name: fields["ID"], Version: version}
	}
	return OSInfo{Name: runtime.GOOS, Version: unknownOSVersion}
}

// parseOSRelease parses the KEY=value lines of an os-release file and strips
// the optional quotes around values. Comments and malformed lines are ignored.
func parseOSRelease(content string) map[string]string {
	fields := make(map[string]string)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		fields[key] = strings.Trim(value, `"'`)
	}
	return fields
}
