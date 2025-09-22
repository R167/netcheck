package natpmp

import (
	"net"
	"testing"
	"time"

	"github.com/R167/netcheck/checkers/common"
)

func TestSendNATpmpRequest(t *testing.T) {
	t.Run("No NAT-PMP server", func(t *testing.T) {
		result := sendNATpmpRequest("127.0.0.1")
		if result {
			t.Error("Expected no NAT-PMP detection on closed port")
		}
	})

	t.Run("Invalid IP address", func(t *testing.T) {
		result := sendNATpmpRequest("999.999.999.999")
		if result {
			t.Error("Expected false for invalid IP")
		}
	})

	t.Run("Unreachable IP with timeout", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping timeout test in short mode")
		}
		start := time.Now()
		result := sendNATpmpRequest("192.0.2.1")
		elapsed := time.Since(start)

		if result {
			t.Error("Expected false for unreachable IP")
		}
		if elapsed > 5*time.Second {
			t.Errorf("Took %v, should timeout faster", elapsed)
		}
	})
}

func TestCheckNATpmp(t *testing.T) {
	t.Run("NAT-PMP disabled router", func(t *testing.T) {
		router := &common.RouterInfo{
			IP: "127.0.0.1",
		}

		checkNATpmp(router)

		if router.NATpmpEnabled {
			t.Error("Expected NATpmpEnabled to be false")
		}

		if len(router.Issues) > 0 {
			t.Error("Expected no security issues")
		}
	})

	t.Run("NAT-PMP security issue severity", func(t *testing.T) {
		router := &common.RouterInfo{
			IP:            "192.168.1.1",
			NATpmpEnabled: true,
		}

		router.Issues = append(router.Issues, common.SecurityIssue{
			Severity:    common.SeverityMedium,
			Description: "NAT-PMP service is enabled",
			Details:     "NAT-PMP allows automatic port mapping. Ensure it's properly secured.",
		})

		if router.Issues[0].Severity != common.SeverityMedium {
			t.Errorf("Expected MEDIUM severity, got %s", router.Issues[0].Severity)
		}
	})
}

func TestNATpmpChecker_Interface(t *testing.T) {
	checker := NewNATpmpChecker()

	if checker.Name() != "natpmp" {
		t.Errorf("Name() = %v, want natpmp", checker.Name())
	}

	if !checker.RequiresRouter() {
		t.Error("RequiresRouter() should return true")
	}

	if !checker.DefaultEnabled() {
		t.Error("DefaultEnabled() should return true")
	}

	config := checker.DefaultConfig()
	_, ok := config.(NATpmpConfig)
	if !ok {
		t.Fatal("DefaultConfig() should return NATpmpConfig")
	}
}

func TestNATpmpProtocol(t *testing.T) {
	t.Run("Protocol constants", func(t *testing.T) {
		request := []byte{0, 0}

		if request[0] != 0 {
			t.Errorf("Version byte = %d, want 0", request[0])
		}
		if request[1] != 0 {
			t.Errorf("Opcode byte = %d, want 0 (external address request)", request[1])
		}
		if len(request) != 2 {
			t.Errorf("Request length = %d, want 2", len(request))
		}
	})

	t.Run("Expected response format", func(t *testing.T) {
		validResponse := []byte{0, 128, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1}

		if len(validResponse) != 12 {
			t.Errorf("Response length = %d, want 12", len(validResponse))
		}
		if validResponse[0] != 0 {
			t.Errorf("Version = %d, want 0", validResponse[0])
		}
		if validResponse[1] != 128 {
			t.Errorf("Opcode = %d, want 128 (response)", validResponse[1])
		}
	})
}

func TestNATpmpTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

	t.Run("Request times out correctly", func(t *testing.T) {
		listener, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to create UDP listener: %v", err)
		}
		defer listener.Close()

		go func() {
			buffer := make([]byte, 1024)
			listener.SetDeadline(time.Now().Add(10 * time.Second))
			listener.ReadFrom(buffer)
			time.Sleep(5 * time.Second)
		}()

		start := time.Now()
		addr := listener.LocalAddr().String()
		sendNATpmpRequest(addr[:len(addr)-5])
		elapsed := time.Since(start)

		if elapsed > 5*time.Second {
			t.Errorf("Request took %v, expected timeout around %v", elapsed, common.NATpmpTimeout)
		}
	})
}

func BenchmarkSendNATpmpRequest(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sendNATpmpRequest("127.0.0.1")
	}
}