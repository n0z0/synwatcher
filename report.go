package main

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/olekukonko/tablewriter"
)

var (
	renderMu     sync.Mutex
	renderNotify = make(chan struct{}, 1)
)

type ipHitEntry struct {
	ip    string
	count int
}

func init() {
	// Worker background untuk me-render tabel secara stabil, terurut, dan throttled
	go tableRenderWorker()
}

func tableRenderWorker() {
	// Batasi frekuensi render tabel maksimal 1x per 500ms saat ada banjir port scan masif
	// agar layar tidak membludak, garis tabel tidak rusak, dan teks stabil terbaca
	const minInterval = 500 * time.Millisecond
	var lastRender time.Time

	for range renderNotify {
		elapsed := time.Since(lastRender)
		if elapsed < minInterval {
			time.Sleep(minInterval - elapsed)
		}

		// Kuras sinyal yang masuk selama masa sleep agar tidak rendering berulang tanpa jeda
		select {
		case <-renderNotify:
		default:
		}

		renderTableNow()
		lastRender = time.Now()
	}
}

// renderTableNow menyusun tabel secara deterministik dan mencetaknya secara atomic
func renderTableNow() {
	hitunganMu.Lock()
	if len(hitungan) == 0 {
		hitunganMu.Unlock()
		return
	}

	// Salin data dan urutkan secara konsisten:
	// 1. Jumlah scan terbanyak di atas (descending)
	// 2. Jika jumlah sama, urutkan berdasarkan IP secara alfabetis (ascending)
	// Mencegah baris tabel melompat-lompat posisi akibat urutan acak map di Go
	entries := make([]ipHitEntry, 0, len(hitungan))
	for ip, count := range hitungan {
		entries = append(entries, ipHitEntry{ip: ip, count: count})
	}
	hitunganMu.Unlock()

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count != entries[j].count {
			return entries[i].count > entries[j].count
		}
		return entries[i].ip < entries[j].ip
	})

	var buf bytes.Buffer
	buf.WriteString("--- Hasil Hitungan ---\n")

	table := tablewriter.NewWriter(&buf)
	table.Header([]string{"IP", "Jumlah"})
	for _, e := range entries {
		table.Append([]string{e.ip, fmt.Sprintf("%d", e.count)})
	}
	table.Render()

	// Cetak seluruh blok tabel sekaligus dengan mutex eksklusif
	// agar tidak terpotong di tengah baris oleh goroutine log lain
	renderMu.Lock()
	os.Stdout.Write(buf.Bytes())
	renderMu.Unlock()
}

func recordHitAndGetCount(srcIP string) int {
	hitunganMu.Lock()
	hitungan[srcIP]++
	count := hitungan[srcIP]
	hitunganMu.Unlock()

	// Picu render tabel secara non-blocking ke background worker
	select {
	case renderNotify <- struct{}{}:
	default:
	}

	return count
}

func recordAndPrintHitungan(srcIP string) {
	recordHitAndGetCount(srcIP)
}

func printHitungan(hitungan map[string]int) {
	renderTableNow()
}
