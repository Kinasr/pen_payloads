package utility

import (
	"fmt"
	"net/http"
	"net/url"

	"github.io/kinasr/pen_payloads/PortSwiggerLabs/SQLi/lab_7/logger"
)

type HTTPClient struct{
	client    *http.Client
}

func NewClient(proxyURL string) (*HTTPClient, error){
	transport := &http.Transport{}

	if proxyURL != "" {
		parsedProxyURL, err := url.Parse(proxyURL)
		if err != nil {
			// Return error instead of exiting
			logger.Warningf("Invalid proxy URL: %s, error: %s", proxyURL, err.Error())
		} else {
			// Set the proxy URL in the transport
			logger.Debugf("Setting up proxy transport with URL: %s", parsedProxyURL.String())
			transport.Proxy = http.ProxyURL(parsedProxyURL)
		}
	}

	return &HTTPClient{client: &http.Client{Transport: transport}}, nil
}

// sendRequest sends a GET request to the specified URL (including payload).
func (httpClient *HTTPClient) SendGetRequest(fullURL string) (*http.Response, error) {
	logger.Infof("Sending request to: %s", fullURL)

	req, err := http.NewRequest(http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for %s: %w", fullURL, err)
	}

	resp, err := httpClient.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed for %s: %w", fullURL, err)
	}

	return resp, nil
}