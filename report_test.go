package main

import (
	"fmt"
	"testing"
	"time"
)

func TestTableSortAndRender(t *testing.T) {
	// Reset data hitungan dan log
	hitunganMu.Lock()
	hitungan = make(map[string]int)
	hitunganMu.Unlock()

	lastStatusMu.Lock()
	lastStatus = make(map[string]string)
	lastStatusMu.Unlock()

	recentLogsMu.Lock()
	recentLogs = nil
	recentLogsMu.Unlock()

	// Simulasi hit dari beberapa IP berbeda dengan status port knock
	ips := []struct {
		ip     string
		status string
	}{
		{"192.168.1.100", "Knock Active (Port 80)"},
		{"10.0.0.5", "Knock Active (Port 443)"},
		{"192.168.1.100", "Knock Active (Port 8080)"},
		{"172.16.0.2", "Port 60606 (SFTP Ignored)"},
		{"192.168.1.100", "Knock Active (Port 22)"},
		{"10.0.0.5", "Knock Active (Port 8443)"},
	}
	for _, item := range ips {
		recordHitWithStatus(item.ip, item.status)
		addActivityLog(fmt.Sprintf("[SYN] %s -> %s", item.ip, item.status))
	}

	// Tunggu sebentar agar render worker mengeksekusi
	time.Sleep(100 * time.Millisecond)

	hitunganMu.Lock()
	c1 := hitungan["192.168.1.100"]
	c2 := hitungan["10.0.0.5"]
	c3 := hitungan["172.16.0.2"]
	hitunganMu.Unlock()

	if c1 != 3 {
		t.Errorf("Expected 3 hits for 192.168.1.100, got %d", c1)
	}
	if c2 != 2 {
		t.Errorf("Expected 2 hits for 10.0.0.5, got %d", c2)
	}
	if c3 != 1 {
		t.Errorf("Expected 1 hit for 172.16.0.2, got %d", c3)
	}

	recentLogsMu.Lock()
	logCount := len(recentLogs)
	recentLogsMu.Unlock()

	if logCount != 5 {
		t.Errorf("Expected recentLogs capped at 5 lines, got %d", logCount)
	}
}
