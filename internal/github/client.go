package github

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/go-github/v67/github"
	"golang.org/x/time/rate"
)

// ProgressCallback is called to report progress
type ProgressCallback func(message string)

// Client wraps the GitHub API client with rate limiting and retries
type Client struct {
	client       *github.Client
	limiter      *rate.Limiter
	maxRetries   int
	retryDelay   time.Duration
	onProgress   ProgressCallback
	mu           sync.Mutex
	requestsMade int
}

// ClientOption configures the Client
type ClientOption func(*Client)

// WithRateLimit sets the rate limit (requests per second)
func WithRateLimit(rps float64) ClientOption {
	return func(c *Client) {
		c.limiter = rate.NewLimiter(rate.Limit(rps), 1)
	}
}

// WithMaxRetries sets the maximum number of retries for failed requests
func WithMaxRetries(n int) ClientOption {
	return func(c *Client) {
		c.maxRetries = n
	}
}

// WithProgressCallback sets the progress callback function
func WithProgressCallback(cb ProgressCallback) ClientOption {
	return func(c *Client) {
		c.onProgress = cb
	}
}

// NewClient creates a new GitHub client with the given token
func NewClient(token string, opts ...ClientOption) *Client {
	httpClient := &http.Client{}
	ghClient := github.NewClient(httpClient).WithAuthToken(token)

	c := &Client{
		client:     ghClient,
		limiter:    rate.NewLimiter(rate.Limit(1.0), 1), // Default: 1 request per second
		maxRetries: 5,
		retryDelay: 5 * time.Second,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// NewClientFromEnv creates a new GitHub client using GITHUB_TOKEN environment variable
func NewClientFromEnv(opts ...ClientOption) (*Client, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN environment variable is not set")
	}
	return NewClient(token, opts...), nil
}

// progress reports progress if a callback is set
func (c *Client) progress(format string, args ...interface{}) {
	if c.onProgress != nil {
		c.onProgress(fmt.Sprintf(format, args...))
	}
}

// wait waits for rate limiter and handles retries
func (c *Client) wait(ctx context.Context) error {
	return c.limiter.Wait(ctx)
}

// handleRateLimit checks response for rate limiting and waits if necessary
func (c *Client) handleRateLimit(resp *github.Response) {
	if resp == nil {
		return
	}

	c.mu.Lock()
	c.requestsMade++
	c.mu.Unlock()

	// Check if we're close to hitting rate limits
	if resp.Rate.Remaining < 100 {
		resetTime := resp.Rate.Reset.Time
		waitDuration := time.Until(resetTime)
		if waitDuration > 0 {
			c.progress("⏳ Rate limit low (%d remaining), waiting %v until reset...", resp.Rate.Remaining, waitDuration.Round(time.Second))
			time.Sleep(waitDuration)
		}
	}
}

// GetRequestsMade returns the number of API requests made
func (c *Client) GetRequestsMade() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requestsMade
}

// Inner returns the underlying go-github client for direct access
func (c *Client) Inner() *github.Client {
	return c.client
}

// WaitForRateLimit waits for the rate limiter
func (c *Client) WaitForRateLimit(ctx context.Context) error {
	return c.wait(ctx)
}

// HandleResponse handles rate limit tracking from a response
func (c *Client) HandleResponse(resp *github.Response) {
	c.handleRateLimit(resp)
}
