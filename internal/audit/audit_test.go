package audit

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestLogAppendRedactsAndTail(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dir)
	l := DefaultLogger()
	if err := l.Append(context.Background(), Record{OperationID: "project-create", Status: 200, Target: "token=secret-value"}); err != nil {
		t.Fatal(err)
	}
	lines, err := l.Tail(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "project-create") {
		t.Fatalf("lines = %#v", lines)
	}
	b, _ := os.ReadFile(l.Path())
	if strings.Contains(string(b), "secret-value") {
		t.Fatalf("audit log leaked secret: %s", string(b))
	}
}
