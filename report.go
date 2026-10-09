package main

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/olekukonko/tablewriter"
)

var (
	renderMu     sync.Mutex
	renderNotify = make(chan struct{}, 1)

	// Rolling buffer untuk aktivitas log writer dan paket terakhir (5 baris)
	recentLogsMu sync.Mutex
	recentLogs   []string

	// Status knock port terakhir per IP
	lastStatusMu sync.Mutex
	lastStatus   = make(map[string]string)

	stdoutWriter = colorable.NewColorableStdout()
	isTerminal   = isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
)

type ipHitEntry struct {
	ip     string
	count  int
	status string
}

func init() {
	// Background worker untuk rendering dashboard secara terkoordinasi (in-place & throttled)
	go dashboardRenderWorker()
}

// addActivityLog mencatat aktivitas terbaru ke rolling slot bawah (maksimal 5 baris)
// dan memicu pembaruan tampilan di tempat (in-place) tanpa memicu scroll.
func addActivityLog(msg string) {
	recentLogsMu.Lock()
	if len(recentLogs) >= 5 {
		recentLogs = recentLogs[1:]
	}
	recentLogs = append(recentLogs, msg)
	recentLogsMu.Unlock()

	triggerDashboardRender()
}

func triggerDashboardRender() {
	select {
	case renderNotify <- struct{}{}:
	default:
	}
}

func dashboardRenderWorker() {
	// Batasi frekuensi refresh maksimal 1x per 200ms saat banjir scan cepat
	// agar CPU hemat, render mulus, dan layar terminal tidak bergetar
	const minInterval = 200 * time.Millisecond
	var lastRender time.Time

	for range renderNotify {
		elapsed := time.Since(lastRender)
		if elapsed < minInterval {
			time.Sleep(minInterval - elapsed)
		}

		select {
		case <-renderNotify:
		default:
		}

		renderDashboardNow()
		lastRender = time.Now()
	}
}

// renderDashboardNow me-render split dashboard (Tabel di atas + Rolling Log di bawah)
// menggunakan ANSI Cursor Home (\033[H) agar selalu menimpa di tempat tanpa scroll.
func renderDashboardNow() {
	renderMu.Lock()
	defer renderMu.Unlock()

	hitunganMu.Lock()
	if len(hitungan) == 0 {
		hitunganMu.Unlock()
		return
	}

	lastStatusMu.Lock()
	entries := make([]ipHitEntry, 0, len(hitungan))
	for ip, count := range hitungan {
		st := lastStatus[ip]
		if st == "" {
			st = "Scanning..."
		}
		entries = append(entries, ipHitEntry{ip: ip, count: count, status: st})
	}
	lastStatusMu.Unlock()
	hitunganMu.Unlock()

	// Urutkan konsisten: jumlah scan terbanyak di atas (descending), lalu IP (ascending)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count != entries[j].count {
			return entries[i].count > entries[j].count
		}
		return entries[i].ip < entries[j].ip
	})

	recentLogsMu.Lock()
	logsCopy := make([]string, len(recentLogs))
	copy(logsCopy, recentLogs)
	recentLogsMu.Unlock()

	var buf bytes.Buffer

	// Jika terminal interaktif (PowerShell / Windows Terminal / Linux bash),
	// gunakan ANSI Cursor Home (\033[H) agar selalu menimpa di tempat tanpa scroll.
	if isTerminal {
		buf.WriteString("\033[H")
	}

	buf.WriteString("========================== SYNWATCHER LIVE DASHBOARD ==========================\n")
	buf.WriteString("--- Rekapitulasi Pemindaian Port (In-Place Update) ---\n")

	table := tablewriter.NewWriter(&buf)
	table.Header([]string{"IP Penyerang", "Jumlah Scan", "Status Terakhir (Port Knock)"})
	for _, e := range entries {
		table.Append([]string{e.ip, fmt.Sprintf("%d", e.count), e.status})
	}
	table.Render()

	buf.WriteString("\n--- Log Aktivitas Terakhir (Rolling Buffer 5 Baris) ---\n")
	if len(logsCopy) == 0 {
		buf.WriteString("  [Menunggu paket pemindaian masuk...]\n")
	} else {
		for _, l := range logsCopy {
			buf.WriteString("  " + l + "\n")
		}
	}
	// Pad slot jika belum 5 baris agar tinggi tampilan selalu konstan
	for i := len(logsCopy); i < 5; i++ {
		buf.WriteString("  ~\n")
	}
	buf.WriteString("==============================================================================\n")

	if isTerminal {
		// Bersihkan baris sisa di bawah jika frame sebelumnya lebih panjang
		buf.WriteString("\033[J")
	}

	stdoutWriter.Write(buf.Bytes())
}

func recordHitAndGetCount(srcIP string) int {
	return recordHitWithStatus(srcIP, "")
}

func recordHitWithStatus(srcIP string, status string) int {
	hitunganMu.Lock()
	hitungan[srcIP]++
	count := hitungan[srcIP]
	hitunganMu.Unlock()

	if status != "" {
		lastStatusMu.Lock()
		lastStatus[srcIP] = status
		lastStatusMu.Unlock()
	}

	triggerDashboardRender()
	return count
}

func recordAndPrintHitungan(srcIP string) {
	recordHitAndGetCount(srcIP)
}

func printHitungan(hitungan map[string]int) {
	renderDashboardNow()
}
