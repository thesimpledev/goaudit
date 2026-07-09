package feed

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Meta records where and when the cached feed was fetched.
type Meta struct {
	URL       string    `json:"url"`
	ETag      string    `json:"etag,omitempty"`
	FetchedAt time.Time `json:"fetched_at"`
}

// Fresh reports whether the cached feed is younger than ttl.
func (m *Meta) Fresh(ttl time.Duration, now time.Time) bool {
	return now.Sub(m.FetchedAt) < ttl
}

// Age formats how old the cached feed is, rounded for display.
func (m *Meta) Age(now time.Time) string {
	return now.Sub(m.FetchedAt).Round(time.Minute).String()
}

// Cache stores one feed on disk: the raw bytes plus a metadata sidecar.
type Cache struct {
	Dir string
}

// DefaultDir returns the per-user cache directory for goaudit.
func DefaultDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate user cache dir: %w", err)
	}
	return filepath.Join(base, "goaudit"), nil
}

func (c *Cache) dataPath() string { return filepath.Join(c.Dir, "feed.data") }
func (c *Cache) metaPath() string { return filepath.Join(c.Dir, "feed.meta.json") }

// Load returns the cached feed bytes and metadata, or (nil, nil) when no
// usable cache exists. A corrupt or partial cache is treated as missing so
// the caller simply refetches.
func (c *Cache) Load() ([]byte, *Meta) {
	metaRaw, err := os.ReadFile(c.metaPath()) // #nosec G304 -- path is built from the user's own --cache-dir flag
	if err != nil {
		return nil, nil
	}
	var meta Meta
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		return nil, nil
	}
	data, err := os.ReadFile(c.dataPath()) // #nosec G304 -- path is built from the user's own --cache-dir flag
	if err != nil {
		return nil, nil
	}
	return data, &meta
}

// Store writes the feed bytes and metadata to disk.
func (c *Cache) Store(data []byte, meta Meta) error {
	if err := os.MkdirAll(c.Dir, 0o750); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	if err := os.WriteFile(c.dataPath(), data, 0o600); err != nil {
		return fmt.Errorf("write feed cache: %w", err)
	}
	return c.WriteMeta(meta)
}

// WriteMeta rewrites only the metadata sidecar. It is used to bump the
// fetch time after the server answers 304 Not Modified.
func (c *Cache) WriteMeta(meta Meta) error {
	if err := os.MkdirAll(c.Dir, 0o750); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("encode cache metadata: %w", err)
	}
	if err := os.WriteFile(c.metaPath(), raw, 0o600); err != nil {
		return fmt.Errorf("write cache metadata: %w", err)
	}
	return nil
}
