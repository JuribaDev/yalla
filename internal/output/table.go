package output

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Table renders a deterministic two-space-padded table to w. Empty input
// produces no output beyond the header row. Headers are required; passing
// none returns an error so callers cannot accidentally emit a column-less
// blob that downstream parsers will misread.
//
// Column widths are computed from the max rune count of the header and any
// row cell in that column, so rendering is stable across locales without
// pulling in a unicode width library.
func Table(w io.Writer, headers []string, rows [][]string) error {
	if len(headers) == 0 {
		return fmt.Errorf("output: table requires at least one header")
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = utf8.RuneCountInString(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i >= len(widths) {
				break
			}
			if n := utf8.RuneCountInString(cell); n > widths[i] {
				widths[i] = n
			}
		}
	}
	if err := writeRow(w, widths, headers); err != nil {
		return err
	}
	for _, row := range rows {
		if err := writeRow(w, widths, row); err != nil {
			return err
		}
	}
	return nil
}

func writeRow(w io.Writer, widths []int, cells []string) error {
	var sb strings.Builder
	for i, width := range widths {
		var cell string
		if i < len(cells) {
			cell = cells[i]
		}
		sb.WriteString(cell)
		if i < len(widths)-1 {
			pad := width - utf8.RuneCountInString(cell) + 2
			if pad < 1 {
				pad = 1
			}
			sb.WriteString(strings.Repeat(" ", pad))
		}
	}
	sb.WriteByte('\n')
	_, err := io.WriteString(w, sb.String())
	return err
}
