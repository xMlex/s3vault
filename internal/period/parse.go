package period

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Parse accepts Go durations plus day and week suffixes: 7d, 24h, 30d, 1w.
func Parse(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}

	i := 0
	for i < len(s) && (unicode.IsDigit(rune(s[i])) || s[i] == '.') {
		i++
	}
	if i == 0 || i == len(s) {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	n, err := strconv.ParseFloat(s[:i], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", s, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("negative duration %q", s)
	}

	switch strings.ToLower(s[i:]) {
	case "d", "day", "days":
		return time.Duration(n * float64(24*time.Hour)), nil
	case "w", "week", "weeks":
		return time.Duration(n * float64(7*24*time.Hour)), nil
	default:
		return 0, fmt.Errorf("invalid duration %q", s)
	}
}
