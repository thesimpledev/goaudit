package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// progress renders a single self-overwriting status line on stderr during
// interactive runs, so long scans are never silent. It stays disabled when
// stderr is not a terminal or when the CI environment variable is set, so
// piped output and CI logs never contain progress bytes.
type progress struct {
	mu      sync.Mutex
	w       io.Writer
	enabled bool
	total   int
	done    int
	width   int
}

func newProgress(w io.Writer) *progress {
	enabled := false
	if f, ok := w.(*os.File); ok && os.Getenv("CI") == "" {
		if st, err := f.Stat(); err == nil {
			enabled = st.Mode()&os.ModeCharDevice != 0
		}
	}
	return &progress{w: w, enabled: enabled}
}

// setTotal records how many projects the counter will count up to.
func (p *progress) setTotal(total int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.total = total
}

// announce replaces the status line with a free-form message.
func (p *progress) announce(msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.write(msg)
}

// step records one finished project and redraws the counter line.
func (p *progress) step(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done++
	p.write(progressLine(p.done, p.total, name))
}

// finish clears the status line so the report starts on clean ground.
func (p *progress) finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.enabled || p.width == 0 {
		return
	}
	printf(p.w, "\r%s\r", strings.Repeat(" ", p.width))
	p.width = 0
}

// write repaints the status line, padding over any longer previous line.
// Callers must hold the mutex.
func (p *progress) write(msg string) {
	if !p.enabled {
		return
	}
	pad := max(p.width-len(msg), 0)
	p.width = max(p.width, len(msg))
	printf(p.w, "\r%s%s", msg, strings.Repeat(" ", pad))
}

// progressLine formats the counter shown while projects complete.
func progressLine(done, total int, name string) string {
	return fmt.Sprintf("auditing [%d/%d] %s", done, total, name)
}
