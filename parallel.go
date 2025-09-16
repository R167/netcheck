package main

import (
	"context"
	"sync"
)

// ParallelExecutor manages parallel execution of checks with cancellation support
type ParallelExecutor struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex
	errors []error
}

// NewParallelExecutor creates a new parallel executor with the given context
func NewParallelExecutor(ctx context.Context) *ParallelExecutor {
	execCtx, cancel := context.WithCancel(ctx)
	return &ParallelExecutor{
		ctx:    execCtx,
		cancel: cancel,
		errors: make([]error, 0),
	}
}

// Execute runs a function in a goroutine with proper waitgroup management
func (pe *ParallelExecutor) Execute(name string, fn func() error) {
	pe.wg.Add(1)
	go func() {
		defer pe.wg.Done()

		// Check if context is already cancelled
		select {
		case <-pe.ctx.Done():
			return
		default:
		}

		// Run the function
		if err := fn(); err != nil {
			pe.mu.Lock()
			pe.errors = append(pe.errors, err)
			pe.mu.Unlock()
		}
	}()
}

// Wait waits for all goroutines to complete
func (pe *ParallelExecutor) Wait() {
	pe.wg.Wait()
}

// Cancel cancels all running operations
func (pe *ParallelExecutor) Cancel() {
	pe.cancel()
}

// Errors returns any errors that occurred during execution
func (pe *ParallelExecutor) Errors() []error {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	return pe.errors
}

// Context returns the executor's context for child operations
func (pe *ParallelExecutor) Context() context.Context {
	return pe.ctx
}