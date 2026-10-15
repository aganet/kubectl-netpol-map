package tui

import (
	"testing"
	"unicode/utf8"
)

// Every glyph row must have the same width, or the assembled logo drifts.
func TestLogoRowsAlign(t *testing.T) {
	for r, g := range figletStandard {
		w := utf8.RuneCountInString(g[0])
		for i, row := range g {
			if utf8.RuneCountInString(row) != w {
				t.Errorf("glyph %q row %d has width %d, want %d", r, i, utf8.RuneCountInString(row), w)
			}
		}
	}
	if len(logo) != headerRows {
		t.Errorf("logo has %d rows, header reserves %d", len(logo), headerRows)
	}
	w := utf8.RuneCountInString(logo[0])
	for i, row := range logo {
		if utf8.RuneCountInString(row) != w {
			t.Errorf("logo row %d has width %d, want %d", i, utf8.RuneCountInString(row), w)
		}
	}
}
