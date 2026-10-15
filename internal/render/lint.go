package render

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/aganet/kubectl-npmap/internal/lint"
)

// Lint renders a flat table of findings, grouped by severity, plus a short
// summary. Empty input prints a clean-bill message.
func Lint(w io.Writer, findings []lint.Finding) error {
	if len(findings) == 0 {
		fmt.Fprintln(w, color.GreenString("✓ no policy lint findings — nothing to flag"))
		return nil
	}

	counts := map[lint.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	fmt.Fprintln(w, text.Bold.Sprintf(
		"Policy lint — %d finding(s)  •  %d error(s), %d warning(s), %d info",
		len(findings), counts[lint.SevError], counts[lint.SevWarning], counts[lint.SevInfo]))
	fmt.Fprintln(w)

	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(table.StyleLight)
	t.AppendHeader(table.Row{
		text.Bold.Sprint("Sev"),
		text.Bold.Sprint("Code"),
		text.Bold.Sprint("Subject"),
		text.Bold.Sprint("Finding"),
	})
	for _, f := range findings {
		t.AppendRow(table.Row{severityLabel(f.Severity), f.Code, f.Subject, f.Message})
	}
	t.Render()

	fmt.Fprintln(w)
	fmt.Fprintln(w, text.Bold.Sprint("Hints:"))
	seen := map[string]bool{}
	for _, f := range findings {
		if f.Hint == "" {
			continue
		}
		key := f.Code + "|" + f.Hint
		if seen[key] {
			continue
		}
		seen[key] = true
		fmt.Fprintf(w, "  %s  %s\n", text.Faint.Sprint(f.Code), f.Hint)
	}
	return nil
}

// LintJSON emits findings as a JSON array — for piping into CI or dashboards.
func LintJSON(w io.Writer, findings []lint.Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}

func severityLabel(s lint.Severity) string {
	switch s {
	case lint.SevError:
		return color.RedString("ERROR")
	case lint.SevWarning:
		return color.YellowString("WARN")
	case lint.SevInfo:
		return color.CyanString("INFO")
	}
	return string(s)
}
