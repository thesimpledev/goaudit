// Package feed fetches remote IOC feeds over HTTP and caches them on disk.
package feed

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// maxFeedBytes caps how much feed data is read, as a guard against a
// misconfigured URL streaming unbounded data. Sized well above the OSV
// ecosystem export (~10 MiB) so growth doesn't hit the limit for years.
const maxFeedBytes = 64 << 20

const defaultTimeout = 30 * time.Second

// fetchAttempts is how many times a transient failure is retried.
const fetchAttempts = 3

// Client fetches feed data over HTTP with optional bearer-token auth.
type Client struct {
	// HTTP is the client used for requests. A default with a 30 second
	// timeout is used when nil.
	HTTP *http.Client
	// Token, when set, is sent as an "Authorization: Bearer" header.
	Token string
	// RetryDelay is the base backoff between retries; one second when
	// zero. Tests set it low.
	RetryDelay time.Duration
}

// Result holds the outcome of a feed fetch.
type Result struct {
	Data        []byte
	ETag        string
	NotModified bool
}

// Fetch downloads the feed at url, retrying transient failures (transport
// errors and 5xx responses) with a short backoff. When etag is non-empty
// it is sent as If-None-Match, and a 304 response yields
// Result.NotModified so the caller can keep using its cached copy.
func (c *Client) Fetch(ctx context.Context, url, etag string) (*Result, error) {
	var lastErr error
	for attempt := 1; attempt <= fetchAttempts; attempt++ {
		res, retryable, err := c.fetchOnce(ctx, url, etag)
		if err == nil {
			return res, nil
		}
		if !retryable {
			return nil, err
		}
		lastErr = err
		if attempt < fetchAttempts {
			time.Sleep(time.Duration(attempt) * c.retryDelay())
		}
	}
	return nil, fmt.Errorf("%w (failure persisted through %d attempts)", lastErr, fetchAttempts)
}

func (c *Client) retryDelay() time.Duration {
	if c.RetryDelay > 0 {
		return c.RetryDelay
	}
	return time.Second
}

// fetchOnce performs one request. retryable reports whether the failure is
// worth another attempt.
func (c *Client) fetchOnce(ctx context.Context, url, etag string) (res *Result, retryable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, fmt.Errorf("build feed request: %w", err)
	}
	req.Header.Set("User-Agent", "goaudit/1.0")
	req.Header.Set("Accept", "application/json, text/csv, text/plain, application/zip, */*")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultTimeout}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("fetch feed %s: %w", url, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	switch {
	case resp.StatusCode == http.StatusNotModified:
		return &Result{ETag: etag, NotModified: true}, false, nil
	case resp.StatusCode >= 500:
		return nil, true, fmt.Errorf("fetch feed %s: server returned %s", url, resp.Status)
	case resp.StatusCode != http.StatusOK:
		return nil, false, fmt.Errorf("fetch feed %s: server returned %s", url, resp.Status)
	}

	// Read one byte past the cap so an oversized feed is an explicit
	// error, not a silent truncation (a truncated zip loses its central
	// directory and would fail parsing in a confusing way).
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		return nil, true, fmt.Errorf("read feed %s: %w", url, err)
	}
	if len(data) > maxFeedBytes {
		return nil, false, fmt.Errorf("feed %s exceeds the %d MiB size limit", url, maxFeedBytes>>20)
	}
	return &Result{Data: data, ETag: resp.Header.Get("Etag")}, false, nil
}
