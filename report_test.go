package main

import (
	"testing"
	"time"
)

func TestTableSortAndRender(t *testing.T) {
	// Reset data hitungan
	hitunganMu.Lock()
	hitungan = make(map[string]int)
	hitunganMu.Unlock()

	// Simulasi hit dari beberapa IP berbeda
	ips := []string{"192.168.1.100", "10.0.0.5", "192.168.1.100", "172.16.0.2", "192.168.1.100", "10.0.0.5"}
	for _, ip := range ips {
		recordHitAndGetCount(ip)
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
}
