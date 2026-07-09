package feed

import (
	"path/filepath"
	"testing"
	"time"
)

func TestCacheRoundTrip(t *testing.T) {
	c := &Cache{Dir: filepath.Join(t.TempDir(), "cache")}
	if data, meta := c.Load(); data != nil || meta != nil {
		t.Fatal("expected an empty cache before Store")
	}
	want := Meta{URL: "https://example.com/feed", ETag: `"abc"`, FetchedAt: time.Now().UTC()}
	if err := c.Store([]byte("hello"), want); err != nil {
		t.Fatalf("Store: %v", err)
	}
	data, got := c.Load()
	if string(data) != "hello" {
		t.Errorf("data = %q, want hello", data)
	}
	if got == nil || got.URL != want.URL || got.ETag != want.ETag {
		t.Errorf("meta = %+v, want %+v", got, want)
	}
}

func TestCacheWriteMeta(t *testing.T) {
	c := &Cache{Dir: filepath.Join(t.TempDir(), "cache")}
	if err := c.Store([]byte("data"), Meta{URL: "u", FetchedAt: time.Now()}); err != nil {
		t.Fatalf("Store: %v", err)
	}
	later := time.Now().Add(time.Hour).UTC()
	if err := c.WriteMeta(Meta{URL: "u", FetchedAt: later}); err != nil {
		t.Fatalf("WriteMeta: %v", err)
	}
	_, meta := c.Load()
	if meta == nil || !meta.FetchedAt.Equal(later) {
		t.Errorf("meta not updated: %+v", meta)
	}
}

func TestMetaFresh(t *testing.T) {
	now := time.Now()
	m := &Meta{FetchedAt: now.Add(-time.Hour)}
	if !m.Fresh(2*time.Hour, now) {
		t.Error("1h-old cache should be fresh with a 2h TTL")
	}
	if m.Fresh(30*time.Minute, now) {
		t.Error("1h-old cache should be stale with a 30m TTL")
	}
}
