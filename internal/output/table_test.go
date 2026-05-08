package output

import (
	"bytes"
	"strings"
	"testing"
)

func TestTable_AlignsColumns(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	err := Table(&buf, []string{"NAME", "STATUS"}, [][]string{
		{"alpha", "running"},
		{"longer-name", "stopped"},
	})
	if err != nil {
		t.Fatalf("Table: %v", err)
	}
	out := buf.String()
	want := "NAME         STATUS\nalpha        running\nlonger-name  stopped\n"
	if out != want {
		t.Errorf("table mismatch\n got:\n%s\nwant:\n%s", out, want)
	}
}

func TestTable_HeaderOnly(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := Table(&buf, []string{"NAME", "STATUS"}, nil); err != nil {
		t.Fatalf("Table: %v", err)
	}
	if got, want := buf.String(), "NAME  STATUS\n"; got != want {
		t.Errorf("header-only table mismatch: got %q want %q", got, want)
	}
}

func TestTable_RejectsEmptyHeaders(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := Table(&buf, nil, [][]string{{"x"}}); err == nil {
		t.Fatal("expected error for empty headers")
	}
}

func TestTable_HandlesShorterRowsGracefully(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	err := Table(&buf, []string{"A", "B", "C"}, [][]string{{"1"}, {"2", "3"}})
	if err != nil {
		t.Fatalf("Table: %v", err)
	}
	if !strings.Contains(buf.String(), "A  B  C\n") {
		t.Errorf("header row missing or wrong padding: %q", buf.String())
	}
}

func TestTable_HandlesUnicodeWidthByRuneCount(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	err := Table(&buf, []string{"NAME", "EMOJI"}, [][]string{{"alpha", "🚀"}, {"beta", "ok"}})
	if err != nil {
		t.Fatalf("Table: %v", err)
	}
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line == "" {
			t.Error("blank line in table output")
		}
	}
}
