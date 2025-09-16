package parallel

import (
	"context"
	"sync"
)

// Executor manages parallel execution of checks with cancellation support
type Executor struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex
	errors []error
}

// NewExecutor creates a new parallel executor with the given context
func NewExecutor(ctx context.Context) *Executor {
	execCtx, cancel := context.WithCancel(ctx)
	return &Executor{
		ctx:    execCtx,
		cancel: cancel,
		errors: make([]error, 0),
	}
}

// Execute runs a function in a goroutine with proper waitgroup management
func (pe *Executor) Execute(name string, fn func(context.Context) error) {
	pe.wg.Add(1)
	go func() {
		defer pe.wg.Done()

		// Check if context is already cancelled
		select {
		case <-pe.ctx.Done():
			return
		default:
		}

		// Run the function with context
		if err := fn(pe.ctx); err != nil {
			pe.mu.Lock()
			pe.errors = append(pe.errors, err)
			pe.mu.Unlock()
		}
	}()
}

// Wait waits for all goroutines to complete
func (pe *Executor) Wait() {
	pe.wg.Wait()
}

// Cancel cancels all running operations
func (pe *Executor) Cancel() {
	pe.cancel()
}

// Errors returns any errors that occurred during execution
func (pe *Executor) Errors() []error {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	return pe.errors
}

// Context returns the executor's context for child operations
func (pe *Executor) Context() context.Context {
	return pe.ctx
}