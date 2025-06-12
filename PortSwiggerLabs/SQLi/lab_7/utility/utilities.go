package utility

import (
	"io"
	"strings"

	"github.io/kinasr/pen_payloads/PortSwiggerLabs/SQLi/lab_7/logger"
)

// normalizeURL ensures the URL has a scheme and no trailing slash.
func NormalizeURL(rawURL string) string {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL // Default to https for labs
	}

	// Remove trailing slash if present
	url := strings.TrimSuffix(rawURL, "/")
	logger.Debugf("Raw URL: %s", rawURL)

	return url
}

// safeClose attempts to close an io.Closer and logs any error.
func SafeClose(closer io.Closer) {
	if closer == nil {
		return
	}
	if err := closer.Close(); err != nil {
		logger.Fatalf("Error closing resource: %s", err.Error())
	}
}

// URLEncode encodes a string for use in a URL query.
func URLEncode(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, " ", "+"), "'", "%27")
}
