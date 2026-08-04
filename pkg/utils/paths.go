// File: pkg/utils/paths.go

package utils

import (
	"fmt"
	"path"
	"strings"
)

// SanitizeServerFilename turns a filename chosen by the API into a bare file
// name that can only be created inside the directory the CLI is writing to.
//
// The batch-report endpoint returns a `filename` field which used to be handed
// straight to os.MkdirAll + os.WriteFile. A malicious, compromised or redirected
// backend answering {"filename": "../../../../.ssh/authorized_keys"} could
// therefore write server-controlled bytes anywhere the user can write.
//
// Every directory component is dropped (both / and \, so a Windows-shaped name
// cannot slip past path.Base on Unix) and anything that does not leave a usable
// file name behind — empty, "." , "..", a trailing separator, a control
// character — is rejected instead of being silently repaired.
func SanitizeServerFilename(name string) (string, error) {
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("filename contains a control character")
		}
	}

	trimmed := strings.Trim(name, " ")
	if trimmed == "" {
		return "", fmt.Errorf("filename is empty")
	}

	// Normalise Windows separators first: path.Base does not treat "\" as a
	// separator, so `..\..\evil` would otherwise survive as a single element.
	normalized := strings.ReplaceAll(trimmed, `\`, "/")
	if strings.HasSuffix(normalized, "/") {
		return "", fmt.Errorf("filename %q designates a directory, not a file", name)
	}

	base := path.Base(normalized)
	switch base {
	case "", ".", "..", "/":
		return "", fmt.Errorf("filename %q has no usable base name", name)
	}
	if strings.ContainsAny(base, `/\`) {
		return "", fmt.Errorf("filename %q still contains a path separator", name)
	}

	return base, nil
}
