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
