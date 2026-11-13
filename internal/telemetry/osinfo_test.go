package telemetry

import (
	"errors"
	"io/fs"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

// stubOSRelease serves os-release content from files for the test's duration.
func stubOSRelease(t *testing.T, files map[string]string) {
	t.Helper()
	origRead, origPaths := readFile, osReleasePaths
	t.Cleanup(func() { readFile, osReleasePaths = origRead, origPaths })

	osReleasePaths = []string{"/etc/os-release", "/usr/lib/os-release"}
	readFile = func(path string) ([]byte, error) {
		content, ok := files[path]
		if !ok {
			return nil, fs.ErrNotExist
		}
		return []byte(content), nil
	}
}

func TestParseOSRelease(t *testing.T) {
	fields := parseOSRelease("# comment\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n\nID=debian\nVERSION_ID='12'\nmalformed line\n")

	assert.Equal(t, map[string]string{
		"PRETTY_NAME": "Debian GNU/Linux 12 (bookworm)",
		"ID":          "debian",
		"VERSION_ID":  "12",
	}, fields)
}

func TestDetectOS(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  OSInfo
	}{
		{
			name:  "etc os-release",
			files: map[string]string{"/etc/os-release": "ID=debian\nVERSION_ID=\"12\"\n"},
			want:  OSInfo{Name: "debian", Version: "12"},
		},
		{
			name:  "falls back to usr lib os-release",
			files: map[string]string{"/usr/lib/os-release": "ID=alpine\nVERSION_ID=3.22.1\n"},
			want:  OSInfo{Name: "alpine", Version: "3.22.1"},
		},
		{
			name: "file without ID is skipped",
			files: map[string]string{
				"/etc/os-release":     "NAME=Custom\n",
				"/usr/lib/os-release": "ID=ubuntu\nVERSION_ID=24.04\n",
			},
			want: OSInfo{Name: "ubuntu", Version: "24.04"},
		},
		{
			name:  "rolling release without VERSION_ID",
			files: map[string]string{"/etc/os-release": "ID=arch\n"},
			want:  OSInfo{Name: "arch", Version: unknownOSVersion},
		},
		{
			name:  "no os-release",
			files: map[string]string{},
			want:  OSInfo{Name: runtime.GOOS, Version: unknownOSVersion},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubOSRelease(t, tt.files)
			assert.Equal(t, tt.want, detectOS())
		})
	}
}

func TestDetectOS_ReadErrorFallsBack(t *testing.T) {
	stubOSRelease(t, nil)
	readFile = func(string) ([]byte, error) { return nil, errors.New("permission denied") }

	assert.Equal(t, OSInfo{Name: runtime.GOOS, Version: unknownOSVersion}, detectOS())
}
