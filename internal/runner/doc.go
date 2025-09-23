// Package runner provides the execution context and orchestration for security checkers.
//
// The runner package manages shared resources and execution context to optimize
// checker performance and avoid redundant operations like gateway discovery.
//
// Key Components:
//
//   - RunContext: Carries shared resources (gateway IP, RouterInfo, timeouts)
//   - DiscoverGateway: Centralized gateway IP discovery
//
// Usage Example:
//
//	ctx := runner.NewRunContext(context.Background())
//	ctx.WithGateway(runner.DiscoverGateway()).
//	    WithGlobalTimeout(60 * time.Second).
//	    WithPortTimeout(1 * time.Second)
//
//	// Pass context to checkers
//	checker.Run(ctx.GetCheckerConfig("web"), ctx.RouterInfo)
//
// Future Integration:
//
// This package is currently infrastructure for Phase 2 integration. The next
// phase will:
//  1. Replace getGatewayIP() in main.go with runner.DiscoverGateway()
//  2. Pass RunContext to checkers instead of individual parameters
//  3. Use Dependencies() to validate resource availability before execution
//  4. Enable resource-level optimizations (e.g., single gateway discovery)
package runner
