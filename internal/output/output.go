package output

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/R167/netcheck/checkers/common"
)

type Output interface {
	Section(icon, title string)
	Header(title string)
	Info(format string, args ...interface{})
	Success(format string, args ...interface{})
	Warning(format string, args ...interface{})
	Error(format string, args ...interface{})
	Detail(format string, args ...interface{})
	Debug(format string, args ...interface{})
	Println(s string)
	Printf(format string, args ...interface{})
}

type StreamingOutput struct {
	writer io.Writer
	mu     sync.Mutex
}

func NewStreamingOutput(writer io.Writer) *StreamingOutput {
	if writer == nil {
		writer = os.Stdout
	}
	return &StreamingOutput{writer: writer}
}

func (o *StreamingOutput) Section(icon, title string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	fmt.Fprintf(o.writer, "\n%s %s\n", icon, title)
}

func (o *StreamingOutput) Header(title string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	fmt.Fprintf(o.writer, "\n%s\n%s\n", title, strings.Repeat("=", len(title)))
}

func (o *StreamingOutput) Info(format string, args ...interface{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	fmt.Fprintf(o.writer, "  "+format+"\n", args...)
}

func (o *StreamingOutput) Success(format string, args ...interface{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	fmt.Fprintf(o.writer, "  ✅ "+format+"\n", args...)
}

func (o *StreamingOutput) Warning(format string, args ...interface{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	fmt.Fprintf(o.writer, "  ⚠️  "+format+"\n", args...)
}

func (o *StreamingOutput) Error(format string, args ...interface{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	fmt.Fprintf(o.writer, "  ❌ "+format+"\n", args...)
}

func (o *StreamingOutput) Detail(format string, args ...interface{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	fmt.Fprintf(o.writer, "   "+format+"\n", args...)
}

func (o *StreamingOutput) Debug(format string, args ...interface{}) {
	if !common.IsDebugMode() {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	fmt.Fprintf(o.writer, "  🔍 [DEBUG] "+format+"\n", args...)
}

func (o *StreamingOutput) Println(s string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	fmt.Fprintln(o.writer, s)
}

func (o *StreamingOutput) Printf(format string, args ...interface{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	fmt.Fprintf(o.writer, format, args...)
}

type OutputLine struct {
	Level   string
	Message string
}

type BufferedOutput struct {
	lines []OutputLine
	mu    sync.Mutex
}

func NewBufferedOutput() *BufferedOutput {
	return &BufferedOutput{lines: make([]OutputLine, 0)}
}

func (o *BufferedOutput) Section(icon, title string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lines = append(o.lines, OutputLine{
		Level:   "section",
		Message: fmt.Sprintf("\n%s %s", icon, title),
	})
}

func (o *BufferedOutput) Header(title string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lines = append(o.lines, OutputLine{
		Level:   "header",
		Message: fmt.Sprintf("\n%s\n%s", title, strings.Repeat("=", len(title))),
	})
}

func (o *BufferedOutput) Info(format string, args ...interface{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lines = append(o.lines, OutputLine{
		Level:   "info",
		Message: fmt.Sprintf("  "+format, args...),
	})
}

func (o *BufferedOutput) Success(format string, args ...interface{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lines = append(o.lines, OutputLine{
		Level:   "success",
		Message: fmt.Sprintf("  ✅ "+format, args...),
	})
}

func (o *BufferedOutput) Warning(format string, args ...interface{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lines = append(o.lines, OutputLine{
		Level:   "warning",
		Message: fmt.Sprintf("  ⚠️  "+format, args...),
	})
}

func (o *BufferedOutput) Error(format string, args ...interface{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lines = append(o.lines, OutputLine{
		Level:   "error",
		Message: fmt.Sprintf("  ❌ "+format, args...),
	})
}

func (o *BufferedOutput) Detail(format string, args ...interface{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lines = append(o.lines, OutputLine{
		Level:   "detail",
		Message: fmt.Sprintf("   "+format, args...),
	})
}

func (o *BufferedOutput) Debug(format string, args ...interface{}) {
	if !common.IsDebugMode() {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lines = append(o.lines, OutputLine{
		Level:   "debug",
		Message: fmt.Sprintf("  🔍 [DEBUG] "+format, args...),
	})
}

func (o *BufferedOutput) Println(s string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lines = append(o.lines, OutputLine{
		Level:   "info",
		Message: s,
	})
}

func (o *BufferedOutput) Printf(format string, args ...interface{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lines = append(o.lines, OutputLine{
		Level:   "info",
		Message: fmt.Sprintf(format, args...),
	})
}

func (o *BufferedOutput) Flush(writer io.Writer) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, line := range o.lines {
		fmt.Fprintln(writer, line.Message)
	}
}

func (o *BufferedOutput) Lines() []OutputLine {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]OutputLine{}, o.lines...)
}

// NoOpOutput is a no-op implementation for tests
type NoOpOutput struct{}

func NewNoOpOutput() *NoOpOutput {
	return &NoOpOutput{}
}

func (o *NoOpOutput) Section(icon, title string)                 {}
func (o *NoOpOutput) Header(title string)                        {}
func (o *NoOpOutput) Info(format string, args ...interface{})    {}
func (o *NoOpOutput) Success(format string, args ...interface{}) {}
func (o *NoOpOutput) Warning(format string, args ...interface{}) {}
func (o *NoOpOutput) Error(format string, args ...interface{})   {}
func (o *NoOpOutput) Detail(format string, args ...interface{})  {}
func (o *NoOpOutput) Debug(format string, args ...interface{})   {}
func (o *NoOpOutput) Println(s string)                           {}
func (o *NoOpOutput) Printf(format string, args ...interface{})  {}
