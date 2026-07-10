package feed

import (
	"path/filepath"
	"runtime"
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

func TestCacheKeyFileNames(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	legacy := &Cache{Dir: dir}
	if got := filepath.Base(legacy.dataPath()); got != "feed.data" {
		t.Errorf("empty key data file = %q, want feed.data", got)
	}
	if got := filepath.Base(legacy.metaPath()); got != "feed.meta.json" {
		t.Errorf("empty key meta file = %q, want feed.meta.json", got)
	}
	keyed := &Cache{Dir: dir, Key: "osv"}
	if got := filepath.Base(keyed.dataPath()); got != "feed-osv.data" {
		t.Errorf("keyed data file = %q, want feed-osv.data", got)
	}
	if got := filepath.Base(keyed.metaPath()); got != "feed-osv.meta.json" {
		t.Errorf("keyed meta file = %q, want feed-osv.meta.json", got)
	}
}

func TestCacheKeysDoNotCollide(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	a := &Cache{Dir: dir}
	b := &Cache{Dir: dir, Key: "osv"}
	if err := a.Store([]byte("socket"), Meta{URL: "u1", FetchedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := b.Store([]byte("osv"), Meta{URL: "u2", FetchedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	dataA, metaA := a.Load()
	dataB, metaB := b.Load()
	if string(dataA) != "socket" || metaA.URL != "u1" {
		t.Errorf("legacy cache clobbered: %q %+v", dataA, metaA)
	}
	if string(dataB) != "osv" || metaB.URL != "u2" {
		t.Errorf("keyed cache clobbered: %q %+v", dataB, metaB)
	}
}

func TestDefaultDirHonorsXDGDataHome(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		t.Skip("XDG applies to unix-like systems only")
	}
	t.Setenv("XDG_DATA_HOME", "/custom/data")
	dir, err := DefaultDir()
	if err != nil {
		t.Fatal(err)
	}
	if dir != filepath.Join("/custom/data", "goaudit") {
		t.Errorf("dir = %q", dir)
	}

	t.Setenv("XDG_DATA_HOME", "")
	dir, err = DefaultDir()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(filepath.Dir(dir)) != "share" {
		t.Errorf("without XDG_DATA_HOME dir should be under .local/share, got %q", dir)
	}
}
