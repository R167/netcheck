package runner

import (
	"context"
	"testing"
	"time"

	"github.com/R167/netcheck/checkers/common"
)

func TestNewRunContext(t *testing.T) {
	ctx := context.Background()
	rc := NewRunContext(ctx)

	if rc.Ctx != ctx {
		t.Error("NewRunContext should preserve context")
	}
	if rc.CheckerConfigs == nil {
		t.Error("CheckerConfigs should be initialized")
	}
}

func TestRunContext_WithGateway(t *testing.T) {
	rc := NewRunContext(context.Background())
	result := rc.WithGateway("192.168.1.1")

	if result.Gateway != "192.168.1.1" {
		t.Errorf("Gateway = %q, want '192.168.1.1'", result.Gateway)
	}
	if result != rc {
		t.Error("WithGateway should return same instance for chaining")
	}
}

func TestRunContext_WithRouterInfo(t *testing.T) {
	rc := NewRunContext(context.Background())
	routerInfo := &common.RouterInfo{IP: "192.168.1.1"}

	result := rc.WithRouterInfo(routerInfo)

	if result.RouterInfo != routerInfo {
		t.Error("WithRouterInfo should set RouterInfo")
	}
	if result != rc {
		t.Error("WithRouterInfo should return same instance for chaining")
	}
}

func TestRunContext_WithShowVirtual(t *testing.T) {
	rc := NewRunContext(context.Background())
	result := rc.WithShowVirtual(true)

	if !result.ShowVirtual {
		t.Error("WithShowVirtual(true) should set ShowVirtual to true")
	}
	if result != rc {
		t.Error("WithShowVirtual should return same instance for chaining")
	}
}

func TestRunContext_WithGlobalTimeout(t *testing.T) {
	rc := NewRunContext(context.Background())
	timeout := 60 * time.Second

	result := rc.WithGlobalTimeout(timeout)

	if result.GlobalTimeout != timeout {
		t.Errorf("GlobalTimeout = %v, want %v", result.GlobalTimeout, timeout)
	}
	if result != rc {
		t.Error("WithGlobalTimeout should return same instance for chaining")
	}
}

func TestRunContext_WithPortTimeout(t *testing.T) {
	rc := NewRunContext(context.Background())
	timeout := 2 * time.Second

	result := rc.WithPortTimeout(timeout)

	if result.PortTimeout != timeout {
		t.Errorf("PortTimeout = %v, want %v", result.PortTimeout, timeout)
	}
	if result != rc {
		t.Error("WithPortTimeout should return same instance for chaining")
	}
}

func TestRunContext_SetGetCheckerConfig(t *testing.T) {
	rc := NewRunContext(context.Background())

	config := "test-config"
	rc.SetCheckerConfig("web", config)

	got, ok := rc.GetCheckerConfig("web")
	if !ok {
		t.Fatal("GetCheckerConfig should return true for existing config")
	}
	if got != config {
		t.Error("GetCheckerConfig should return the same config that was set")
	}
}

func TestRunContext_GetCheckerConfig_NotFound(t *testing.T) {
	rc := NewRunContext(context.Background())

	_, ok := rc.GetCheckerConfig("nonexistent")
	if ok {
		t.Error("GetCheckerConfig should return false for non-existent config")
	}
}

func TestRunContext_BuilderPattern(t *testing.T) {
	ctx := context.Background()
	routerInfo := &common.RouterInfo{IP: "192.168.1.1"}

	rc := NewRunContext(ctx).
		WithGateway("192.168.1.1").
		WithRouterInfo(routerInfo).
		WithShowVirtual(true).
		WithGlobalTimeout(60 * time.Second).
		WithPortTimeout(1 * time.Second)

	if rc.Gateway != "192.168.1.1" {
		t.Error("Builder pattern should set Gateway")
	}
	if rc.RouterInfo != routerInfo {
		t.Error("Builder pattern should set RouterInfo")
	}
	if !rc.ShowVirtual {
		t.Error("Builder pattern should set ShowVirtual")
	}
	if rc.GlobalTimeout != 60*time.Second {
		t.Error("Builder pattern should set GlobalTimeout")
	}
	if rc.PortTimeout != 1*time.Second {
		t.Error("Builder pattern should set PortTimeout")
	}
}

func TestDiscoverGateway(t *testing.T) {
	gateway := DiscoverGateway()

	// Gateway discovery may fail in some environments (e.g., no network)
	// so we just test that it returns a string (empty or valid IP)
	if gateway != "" {
		// If we got a gateway, it should look like an IP
		parts := len(gateway)
		if parts < 7 { // Minimum valid IP: "0.0.0.0" = 7 chars
			t.Errorf("DiscoverGateway returned suspicious value: %q", gateway)
		}
	}
	// Empty string is valid (means discovery failed)
}

func TestDiscoverGateway_Format(t *testing.T) {
	gateway := DiscoverGateway()

	if gateway == "" {
		t.Skip("Gateway discovery failed (acceptable in test environments)")
	}

	// Should end with .1 if discovery succeeded
	if gateway[len(gateway)-2:] != ".1" {
		t.Errorf("DiscoverGateway() = %q, should end with '.1'", gateway)
	}

	// Should have exactly 4 octets
	parts := 0
	for _, ch := range gateway {
		if ch == '.' {
			parts++
		}
	}
	if parts != 3 {
		t.Errorf("DiscoverGateway() = %q, should have 3 dots (4 octets)", gateway)
	}
}
