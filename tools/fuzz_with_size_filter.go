package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Result struct {
	URL        string
	StatusCode int
	Size       int64
	Error      error
}

func main() {
	var (
		host     = flag.String("u", "", "Target host (required)")
		wordlist = flag.String("w", "", "Wordlist file (.txt only, required)")
		threads  = flag.Int("t", 10, "Number of parallel requests")
		minSize  = flag.Int64("min-size", 0, "Minimum response size filter (optional)")
		maxSize  = flag.Int64("max-size", 0, "Maximum response size filter (optional)")
	)
	flag.Parse()

	// Validate required flags
	if *host == "" {
		fmt.Fprintf(os.Stderr, "Error: Host (-u) is required\n")
		flag.Usage()
		os.Exit(1)
	}

	if *wordlist == "" {
		fmt.Fprintf(os.Stderr, "Error: Wordlist (-w) is required\n")
		flag.Usage()
		os.Exit(1)
	}

	// Validate wordlist file extension
	if !strings.HasSuffix(*wordlist, ".txt") {
		fmt.Fprintf(os.Stderr, "Error: Wordlist must be a .txt file\n")
		os.Exit(1)
	}

	// Ensure host has proper protocol
	if !strings.HasPrefix(*host, "http://") && !strings.HasPrefix(*host, "https://") {
		*host = "http://" + *host
	}

	// Remove trailing slash from host
	*host = strings.TrimSuffix(*host, "/")

	// Read wordlist
	words, err := readWordlist(*wordlist)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading wordlist: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Starting URL checker with %d threads\n", *threads)
	fmt.Printf("Target: %s\n", *host)
	fmt.Printf("Wordlist: %s (%d entries)\n", *wordlist, len(words))
	if *minSize > 0 {
		fmt.Printf("Min size filter: %d bytes\n", *minSize)
	}
	if *maxSize > 0 {
		fmt.Printf("Max size filter: %d bytes\n", *maxSize)
	}
	fmt.Println(strings.Repeat("-", 50))

	// Create channels
	jobs := make(chan string, len(words))
	results := make(chan Result, len(words))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go worker(*host, jobs, results, &wg)
	}

	// Send jobs
	go func() {
		for _, word := range words {
			jobs <- word
		}
		close(jobs)
	}()

	// Wait for workers to finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Process results
	var validResults []Result
	for result := range results {
		if result.Error != nil {
			continue
		}

		// Apply size filters
		if *minSize > 0 && result.Size < *minSize {
			continue
		}
		if *maxSize > 0 && result.Size > *maxSize {
			continue
		}

		// Only show successful responses
		if result.StatusCode >= 200 && result.StatusCode < 400 {
			validResults = append(validResults, result)
			fmt.Printf("[%d] %s (%d bytes)\n", result.StatusCode, result.URL, result.Size)
		}
	}

	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("Found %d valid URLs\n", len(validResults))
}

func readWordlist(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			words = append(words, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return words, nil
}

func worker(host string, jobs <-chan string, results chan<- Result, wg *sync.WaitGroup) {
	defer wg.Done()

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow up to 5 redirects
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	for word := range jobs {
		url := host + "/" + strings.TrimPrefix(word, "/")

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			results <- Result{URL: url, Error: err}
			continue
		}

		// Set user agent
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; URLChecker/1.0)")

		resp, err := client.Do(req)
		if err != nil {
			results <- Result{URL: url, Error: err}
			continue
		}

		// Read response body to get size
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil {
			results <- Result{URL: url, StatusCode: resp.StatusCode, Error: err}
			continue
		}

		results <- Result{
			URL:        url,
			StatusCode: resp.StatusCode,
			Size:       int64(len(body)),
			Error:      nil,
		}
	}
}
