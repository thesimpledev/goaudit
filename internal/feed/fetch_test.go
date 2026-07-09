package feed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchSendsAuthAndETag(t *testing.T) {
	var gotAuth, gotETag string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotETag = r.Header.Get("If-None-Match")
		w.Header().Set("Etag", `"v2"`)
		_, _ = w.Write([]byte(`{"entries":[]}`))
	}))
	defer srv.Close()

	c := &Client{Token: "sekrit"}
	res, err := c.Fetch(context.Background(), srv.URL, `"v1"`)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if gotAuth != "Bearer sekrit" {
		t.Errorf("Authorization = %q, want Bearer sekrit", gotAuth)
	}
	if gotETag != `"v1"` {
		t.Errorf("If-None-Match = %q, want \"v1\"", gotETag)
	}
	if res.ETag != `"v2"` {
		t.Errorf("res.ETag = %q, want \"v2\"", res.ETag)
	}
	if string(res.Data) != `{"entries":[]}` {
		t.Errorf("res.Data = %q", res.Data)
	}
}

func TestFetchNotModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	c := &Client{}
	res, err := c.Fetch(context.Background(), srv.URL, `"v1"`)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !res.NotModified {
		t.Error("expected NotModified for a 304 response")
	}
}

func TestFetchRetriesServerErrorThenGivesUp(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := &Client{RetryDelay: time.Millisecond}
	_, err := c.Fetch(context.Background(), srv.URL, "")
	if err == nil {
		t.Fatal("expected an error for persistent 500 responses")
	}
	if requests != 3 {
		t.Errorf("requests = %d, want 3 (retry twice then give up)", requests)
	}
	if !strings.Contains(err.Error(), "3 attempts") {
		t.Errorf("error should mention the attempts: %v", err)
	}
}

func TestFetchRetriesThenSucceeds(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		if requests < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"entries":[]}`))
	}))
	defer srv.Close()

	c := &Client{RetryDelay: time.Millisecond}
	res, err := c.Fetch(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatalf("Fetch should succeed on the third attempt: %v", err)
	}
	if requests != 3 {
		t.Errorf("requests = %d, want 3", requests)
	}
	if string(res.Data) != `{"entries":[]}` {
		t.Errorf("res.Data = %q", res.Data)
	}
}

func TestFetchDoesNotRetryClientError(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := &Client{RetryDelay: time.Millisecond}
	if _, err := c.Fetch(context.Background(), srv.URL, ""); err == nil {
		t.Fatal("expected an error for a 404 response")
	}
	if requests != 1 {
		t.Errorf("requests = %d, want 1 (4xx must not be retried)", requests)
	}
}
