package runner

import (
	"context"
	"time"

	"github.com/R167/netcheck/checkers/common"
)

// RunContext carries shared resources and configuration for checker execution.
// It provides a centralized place for resources that multiple checkers need,
// avoiding redundant operations like gateway discovery.
//
// The context uses a builder pattern for easy construction:
//
//	ctx := NewRunContext(context.Background()).
//	    WithGateway("192.168.1.1").
//	    WithGlobalTimeout(60 * time.Second)
type RunContext struct {
	Ctx            context.Context
	Gateway        string
	RouterInfo     *common.RouterInfo
	ShowVirtual    bool
	GlobalTimeout  time.Duration
	PortTimeout    time.Duration
	CheckerConfigs map[string]interface{}
}

func NewRunContext(ctx context.Context) *RunContext {
	return &RunContext{
		Ctx:            ctx,
		CheckerConfigs: make(map[string]interface{}),
	}
}

func (rc *RunContext) WithGateway(gateway string) *RunContext {
	rc.Gateway = gateway
	return rc
}

func (rc *RunContext) WithRouterInfo(info *common.RouterInfo) *RunContext {
	rc.RouterInfo = info
	return rc
}

func (rc *RunContext) WithShowVirtual(show bool) *RunContext {
	rc.ShowVirtual = show
	return rc
}

func (rc *RunContext) WithGlobalTimeout(timeout time.Duration) *RunContext {
	rc.GlobalTimeout = timeout
	return rc
}

func (rc *RunContext) WithPortTimeout(timeout time.Duration) *RunContext {
	rc.PortTimeout = timeout
	return rc
}

func (rc *RunContext) SetCheckerConfig(checkerName string, config interface{}) {
	rc.CheckerConfigs[checkerName] = config
}

func (rc *RunContext) GetCheckerConfig(checkerName string) (interface{}, bool) {
	config, ok := rc.CheckerConfigs[checkerName]
	return config, ok
}
