package output

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

func TestStreamingOutput_Section(t *testing.T) {
	buf := &bytes.Buffer{}
	out := NewStreamingOutput(buf)

	out.Section("🔍", "Test Section")

	got := buf.String()
	want := "\n🔍 Test Section\n"
	if got != want {
		t.Errorf("Section() = %q, want %q", got, want)
	}
}

func TestStreamingOutput_Info(t *testing.T) {
	buf := &bytes.Buffer{}
	out := NewStreamingOutput(buf)

	out.Info("test message")

	got := buf.String()
	want := "  test message\n"
	if got != want {
		t.Errorf("Info() = %q, want %q", got, want)
	}
}

func TestStreamingOutput_Success(t *testing.T) {
	buf := &bytes.Buffer{}
	out := NewStreamingOutput(buf)

	out.Success("operation succeeded")

	got := buf.String()
	if !strings.Contains(got, "✅") {
		t.Errorf("Success() should contain success emoji, got %q", got)
	}
	if !strings.Contains(got, "operation succeeded") {
		t.Errorf("Success() should contain message, got %q", got)
	}
}

func TestStreamingOutput_Warning(t *testing.T) {
	buf := &bytes.Buffer{}
	out := NewStreamingOutput(buf)

	out.Warning("potential issue")

	got := buf.String()
	if !strings.Contains(got, "⚠️") {
		t.Errorf("Warning() should contain warning emoji, got %q", got)
	}
}

func TestStreamingOutput_Error(t *testing.T) {
	buf := &bytes.Buffer{}
	out := NewStreamingOutput(buf)

	out.Error("failure occurred")

	got := buf.String()
	if !strings.Contains(got, "❌") {
		t.Errorf("Error() should contain error emoji, got %q", got)
	}
}

func TestStreamingOutput_ThreadSafety(t *testing.T) {
	buf := &bytes.Buffer{}
	out := NewStreamingOutput(buf)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			out.Info("message %d", n)
		}(i)
	}

	wg.Wait()

	lines := strings.Split(buf.String(), "\n")
	if len(lines) < 100 {
		t.Errorf("Expected at least 100 lines, got %d", len(lines))
	}
}

func TestBufferedOutput_Section(t *testing.T) {
	out := NewBufferedOutput()

	out.Section("🔍", "Test Section")

	lines := out.Lines()
	if len(lines) != 1 {
		t.Fatalf("Expected 1 line, got %d", len(lines))
	}
	if lines[0].Level != "section" {
		t.Errorf("Level = %q, want %q", lines[0].Level, "section")
	}
	if !strings.Contains(lines[0].Message, "Test Section") {
		t.Errorf("Message should contain 'Test Section', got %q", lines[0].Message)
	}
}

func TestBufferedOutput_MultipleCalls(t *testing.T) {
	out := NewBufferedOutput()

	out.Info("line 1")
	out.Success("line 2")
	out.Warning("line 3")

	lines := out.Lines()
	if len(lines) != 3 {
		t.Fatalf("Expected 3 lines, got %d", len(lines))
	}

	if lines[0].Level != "info" {
		t.Errorf("Line 0 level = %q, want 'info'", lines[0].Level)
	}
	if lines[1].Level != "success" {
		t.Errorf("Line 1 level = %q, want 'success'", lines[1].Level)
	}
	if lines[2].Level != "warning" {
		t.Errorf("Line 2 level = %q, want 'warning'", lines[2].Level)
	}
}

func TestBufferedOutput_Flush(t *testing.T) {
	out := NewBufferedOutput()
	out.Info("message 1")
	out.Success("message 2")

	buf := &bytes.Buffer{}
	out.Flush(buf)

	output := buf.String()
	if !strings.Contains(output, "message 1") {
		t.Errorf("Flush output should contain 'message 1', got %q", output)
	}
	if !strings.Contains(output, "message 2") {
		t.Errorf("Flush output should contain 'message 2', got %q", output)
	}
}

func TestBufferedOutput_ThreadSafety(t *testing.T) {
	out := NewBufferedOutput()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			out.Info("message %d", n)
		}(i)
	}

	wg.Wait()

	lines := out.Lines()
	if len(lines) != 100 {
		t.Errorf("Expected 100 lines, got %d", len(lines))
	}
}

func TestBufferedOutput_LinesReturnsDeepCopy(t *testing.T) {
	out := NewBufferedOutput()
	out.Info("original")

	lines1 := out.Lines()
	lines1[0].Message = "modified"

	lines2 := out.Lines()
	if lines2[0].Message != "  original" {
		t.Errorf("Lines() should return a copy, original was modified")
	}
}

func TestNewStreamingOutput_NilWriter(t *testing.T) {
	out := NewStreamingOutput(nil)
	if out.writer == nil {
		t.Error("NewStreamingOutput(nil) should default to os.Stdout")
	}
}

func TestStreamingOutput_Printf(t *testing.T) {
	buf := &bytes.Buffer{}
	out := NewStreamingOutput(buf)

	out.Printf("formatted: %d", 42)

	got := buf.String()
	want := "formatted: 42"
	if got != want {
		t.Errorf("Printf() = %q, want %q", got, want)
	}
}

func TestBufferedOutput_Header(t *testing.T) {
	out := NewBufferedOutput()
	out.Header("Test Header")

	lines := out.Lines()
	if len(lines) != 1 {
		t.Fatalf("Expected 1 line, got %d", len(lines))
	}
	if !strings.Contains(lines[0].Message, "Test Header") {
		t.Errorf("Header message should contain 'Test Header', got %q", lines[0].Message)
	}
	if !strings.Contains(lines[0].Message, "=") {
		t.Errorf("Header should contain underline, got %q", lines[0].Message)
	}
}
