# Phase 2 Integration Plan

This document describes the integration plan for the new infrastructure introduced in Phase 1 (PR #32).

## Current State (Phase 1)

✅ **Completed:**
- Dependency system added to all checkers
- Output interface created (StreamingOutput, BufferedOutput)
- RunContext created for shared resource management
- Type duplication eliminated (main.RouterInfo removed)
- Comprehensive documentation and tests added

⚠️ **Not Yet Integrated:**
The new infrastructure exists but is not yet used by the main execution path. Checkers still:
- Use `fmt.Print` directly instead of `Output` interface
- Don't receive `RunContext`
- Have no dependency validation at runtime

## Phase 2: Integration

### 1. Replace Direct Printing with Output Interface

**Goal:** Convert all checkers to use the `Output` interface instead of `fmt.Print*`.

**Changes Required:**
```go
// Before:
func checkWeb(router *common.RouterInfo) {
    fmt.Println("🔍 Checking web interface...")
    fmt.Printf("  ✅ Port %d open\n", port)
}

// After:
func checkWeb(out output.Output, router *common.RouterInfo) {
    out.Section("🔍", "Checking web interface...")
    out.Success("Port %d open", port)
}
```

**Impact:**
- ~179 `fmt.Print` calls to convert across 13 checkers
- Enables parallel execution without output interleaving
- Better testability (can capture output in tests)

### 2. Integrate RunContext

**Goal:** Pass `RunContext` to checkers instead of individual parameters.

**Changes Required:**
```go
// Update Checker interface:
type Checker interface {
    Run(ctx *runner.RunContext) error  // Changed signature
}

// Update main.go execution:
ctx := runner.NewRunContext(context.Background()).
    WithGateway(runner.DiscoverGateway()).
    WithGlobalTimeout(*timeoutFlag)

for _, checker := range checkers {
    if err := checker.Run(ctx); err != nil {
        // handle error
    }
}
```

**Benefits:**
- Single gateway discovery shared across checkers
- Centralized configuration management
- Easier to add new context fields in the future

### 3. Runtime Dependency Validation

**Goal:** Use `Dependencies()` to validate prerequisites before execution.

**Implementation:**
```go
func runChecker(checker Checker, ctx *runner.RunContext) error {
    deps := checker.Dependencies()

    for _, dep := range deps {
        switch dep {
        case checker.DependencyGateway:
            if ctx.Gateway == "" {
                return fmt.Errorf("checker %s requires gateway but none available", checker.Name())
            }
        case checker.DependencyNetwork:
            if !isNetworkAvailable() {
                return fmt.Errorf("checker %s requires network connectivity", checker.Name())
            }
        }
    }

    return checker.Run(ctx)
}
```

**Benefits:**
- Clear error messages when prerequisites not met
- Fail fast instead of during checker execution
- Foundation for resource pooling/optimization

### 4. Enable Parallel Execution

**Goal:** Run independent checkers in parallel using `BufferedOutput`.

**Implementation:**
```go
var wg sync.WaitGroup
results := make(chan *output.BufferedOutput, len(checkers))

for _, checker := range checkers {
    wg.Add(1)
    go func(c Checker) {
        defer wg.Done()
        out := output.NewBufferedOutput()
        c.Run(ctx, out)
        results <- out
    }(checker)
}

wg.Wait()
close(results)

// Flush results in deterministic order
for result := range results {
    result.Flush(os.Stdout)
}
```

**Benefits:**
- Faster execution (checkers run concurrently)
- Better resource utilization
- Clean, non-interleaved output

### 5. Auto-Generated Flag Registration

**Goal:** Eliminate hardcoded flag declarations in main.go.

**Implementation:**
```go
// In main.go init():
func init() {
    for _, checker := range checkers.AllCheckers() {
        name := checker.Name()
        desc := checker.Description()

        // Auto-register flag
        flags[name] = flag.Bool(name, checker.DefaultEnabled(), desc)

        // Register custom flags if checker provides them
        if cf, ok := checker.(CustomFlagsProvider); ok {
            for _, customFlag := range cf.CustomFlags() {
                // Register custom flags
            }
        }
    }
}
```

**Benefits:**
- Adding new checker = zero flag boilerplate
- Flags always match available checkers
- Less code in main.go

## Migration Strategy

**Recommended Order:**

1. **Phase 2a:** Output Interface (2-3 checkers as pilot)
   - Convert 2-3 simple checkers to use Output interface
   - Validate approach and update patterns
   - Roll out to remaining checkers

2. **Phase 2b:** RunContext Integration
   - Update Checker interface
   - Modify main.go execution loop
   - Update all checkers to accept RunContext

3. **Phase 2c:** Dependency Validation
   - Add validation logic to runner
   - Add network availability checks
   - Test error paths

4. **Phase 2d:** Parallel Execution
   - Implement parallel runner
   - Add ordering logic for deterministic output
   - Performance testing

5. **Phase 2e:** Auto-Generated Flags
   - Implement flag registration loop
   - Remove hardcoded flags
   - Add custom flag support

## Backward Compatibility

During Phase 2, maintain backward compatibility:
- Keep existing checker signatures working
- Provide adapter functions if needed
- Gradual migration, not big-bang

## Testing Strategy

Each phase should include:
- Unit tests for new functionality
- Integration tests for full flow
- Performance benchmarks for parallel execution
- Backward compatibility tests

## Timeline Estimate

- Phase 2a (Output Interface): 2-3 days
- Phase 2b (RunContext): 1-2 days
- Phase 2c (Validation): 1 day
- Phase 2d (Parallel): 2-3 days
- Phase 2e (Flags): 1 day

**Total: ~1.5-2 weeks** for complete integration

## Open Questions

1. Should we batch checkers by dependency groups for parallel execution?
2. How to handle checker failures in parallel mode?
3. Should output be sorted by severity or execution order?
4. Do we need a progress indicator for parallel execution?

## References

- PR #32: Initial infrastructure (Phase 1)
- `/root/src/netcheck/internal/output/` - Output interface
- `/root/src/netcheck/internal/runner/` - RunContext
- `/root/src/netcheck/internal/checker/` - Checker interface