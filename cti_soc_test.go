package main

import (
	"testing"
)

func TestEstimateOS(t *testing.T) {
	tests := []struct {
		ttl        uint8
		windowSize uint16
		expectedOS string
		expectedHop int
	}{
		{ttl: 64, windowSize: 1024, expectedOS: "Linux / Android / macOS", expectedHop: 0},
		{ttl: 58, windowSize: 1024, expectedOS: "Linux / Android / macOS", expectedHop: 6},
		{ttl: 128, windowSize: 8192, expectedOS: "Windows (10/11/Server)", expectedHop: 0},
		{ttl: 120, windowSize: 8192, expectedOS: "Windows (10/11/Server)", expectedHop: 8},
		{ttl: 255, windowSize: 4128, expectedOS: "Network Appliance / Solaris / Cisco", expectedHop: 0},
	}

	for _, tc := range tests {
		osName, hops := EstimateOS(tc.ttl, tc.windowSize)
		if osName != tc.expectedOS {
			t.Errorf("TTL %d: expected OS %q, got %q", tc.ttl, tc.expectedOS, osName)
		}
		if hops != tc.expectedHop {
			t.Errorf("TTL %d: expected hops %d, got %d", tc.ttl, tc.expectedHop, hops)
		}
	}
}

func TestIdentifyScannerTool(t *testing.T) {
	tests := []struct {
		name       string
		windowSize uint16
		options    []string
		expected   string
	}{
		{
			name:       "Nmap SYN Scan",
			windowSize: 1024,
			options:    []string{"MSS", "SACKPerm", "TS", "NOP", "WScale"},
			expected:   "Nmap (Stealth SYN Scan)",
		},
		{
			name:       "Masscan",
			windowSize: 1024,
			options:    []string{},
			expected:   "Masscan",
		},
		{
			name:       "Standard OS Socket (PowerShell/Browser)",
			windowSize: 64240,
			options:    []string{"MSS", "WScale", "SACKPerm"},
			expected:   "Standard OS Socket (PowerShell/Browser/Socket)",
		},
		{
			name:       "ZMap",
			windowSize: 65535,
			options:    []string{},
			expected:   "ZMap",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := IdentifyScannerTool(tc.windowSize, tc.options)
			if res != tc.expected {
				t.Errorf("[%s] Expected %q, got %q", tc.name, tc.expected, res)
			}
		})
	}
}

func TestCalculateSYNFingerprint(t *testing.T) {
	fp, hash := CalculateSYNFingerprint(4, 64, 1024, []string{"SYN"}, []string{"MSS", "SACKPerm", "TS", "NOP", "WScale"})
	expectedFP := "4:64:1024:SYN:MSS,SACKPerm,TS,NOP,WScale"
	if fp != expectedFP {
		t.Errorf("Expected FP %q, got %q", expectedFP, fp)
	}
	if len(hash) != 32 {
		t.Errorf("Expected 32-character MD5 hash, got %d chars (%q)", len(hash), hash)
	}

	// Empty options fallback
	fpEmpty, hashEmpty := CalculateSYNFingerprint(4, 128, 65535, []string{"SYN"}, nil)
	expectedEmptyFP := "4:128:65535:SYN:none"
	if fpEmpty != expectedEmptyFP {
		t.Errorf("Expected FP %q, got %q", expectedEmptyFP, fpEmpty)
	}
	if len(hashEmpty) != 32 {
		t.Errorf("Expected 32-character MD5 hash, got %d chars (%q)", len(hashEmpty), hashEmpty)
	}
}

func TestCategorizeTargetService(t *testing.T) {
	tests := []struct {
		port           int
		expectedSvc    string
		expectedIntent string
	}{
		{22, "SSH", "REMOTE_ACCESS_PROBE"},
		{23, "Telnet", "INSECURE_REMOTE_ACCESS_PROBE"},
		{80, "HTTP", "WEB_RECONNAISSANCE"},
		{443, "HTTPS", "WEB_RECONNAISSANCE"},
		{445, "SMB/RPC", "LATERAL_MOVEMENT_PROBE"},
		{3389, "RDP", "REMOTE_DESKTOP_EXPLOITATION_PROBE"},
		{3306, "MySQL", "DATABASE_DISCOVERY"},
		{6379, "Redis", "DATABASE_DISCOVERY"},
		{9999, "Port-9999", "UNKNOWN_SERVICE_SCAN"},
	}

	for _, tc := range tests {
		svc, intent := CategorizeTargetService(tc.port)
		if svc != tc.expectedSvc {
			t.Errorf("Port %d: expected service %q, got %q", tc.port, tc.expectedSvc, svc)
		}
		if intent != tc.expectedIntent {
			t.Errorf("Port %d: expected intent %q, got %q", tc.port, tc.expectedIntent, intent)
		}
	}
}

func TestCalculateRiskScore(t *testing.T) {
	// Critical threat: Nmap scan + RDP + sweep scan + burst
	scoreCrit, sevCrit := CalculateRiskScore("Nmap (Stealth SYN Scan)", "REMOTE_DESKTOP_EXPLOITATION_PROBE", "PORT_SWEEP_SCAN", "BURST_AUTOMATED_SCAN", 15)
	if scoreCrit < 85 || sevCrit != "CRITICAL" {
		t.Errorf("Expected CRITICAL severity (>=85), got score %d severity %q", scoreCrit, sevCrit)
	}

	// Low threat: Standard OS socket single knock to unknown port
	scoreLow, sevLow := CalculateRiskScore("Standard OS Socket (PowerShell/Browser/Socket)", "UNKNOWN_SERVICE_SCAN", "SINGLE_PORT_KNOCK", "INITIAL_PROBE", 1)
	if scoreLow > 40 || (sevLow != "LOW" && sevLow != "INFO") {
		t.Errorf("Expected LOW or INFO severity, got score %d severity %q", scoreLow, sevLow)
	}
}
