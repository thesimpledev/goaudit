package match

import "testing"

func TestDistance(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "", 3},
		{"", "abc", 3},
		{"same", "same", 0},
		{"kitten", "sitting", 3},
		{"stretchr", "strechr", 1},
		{"sirupsen", "Sirupsen", 1},
		{"héllo", "hello", 1},
	}
	for _, tt := range tests {
		if got := Distance(tt.a, tt.b); got != tt.want {
			t.Errorf("Distance(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}
