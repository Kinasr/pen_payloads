package utility

import (
	"errors"
	"flag"

	"github.io/kinasr/pen_payloads/PortSwiggerLabs/SQLi/lab_7/logger"
)

// Config holds application configuration parsed from command-line flags.
type Config struct {
	LabURL   string
	ProxyURL string
	LogLevel string
}


// parseArgs parses command-line arguments and returns Config or an error.
func ParseArgs() (Config, error) {
	config := Config{}

	flag.StringVar(&config.LabURL, "u", "", "Target URL of the PortSwigger Lab (required)")
	flag.StringVar(&config.ProxyURL, "proxy", "", "Optional proxy URL (e.g., http://127.0.0.1:8080)")
	flag.StringVar(&config.LogLevel, "log-level", "info", "Set log level (debug, info, action, warning, fatal, success)")
	flag.Parse() // Parse flags defined above

	if config.LabURL == "" {
		logger.Warning("Usage: ")
		flag.PrintDefaults() // Print default usage information
		return config, errors.New("missing target URL")
	}
	return config, nil
}