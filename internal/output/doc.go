// Package output provides output interfaces for checkers, enabling both
// streaming and buffered output modes.
//
// The Output interface abstracts checker output, allowing the same checker
// code to work in both sequential and parallel execution modes:
//
//   - StreamingOutput: Writes directly to io.Writer for sequential execution
//   - BufferedOutput: Collects output in memory for parallel execution
//
// Usage Example (Sequential):
//
//	out := output.NewStreamingOutput(os.Stdout)
//	out.Section("🔍", "Checking web interface...")
//	out.Success("Port 80 is open")
//	out.Warning("Default credentials detected")
//
// Usage Example (Parallel):
//
//	out := output.NewBufferedOutput()
//	out.Info("Running checks...")
//	// ... checker runs ...
//	out.Flush(os.Stdout)  // Write all buffered output at once
//
// All implementations are thread-safe with mutex protection.
//
// Future Integration:
//
// This package is currently infrastructure for future use. The next phase
// will convert checkers from direct fmt.Print calls to use the Output interface,
// enabling true parallel execution without interleaved output.
package output
