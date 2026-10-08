package main

import (
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
)

func recordHitAndGetCount(srcIP string) int {
	hitunganMu.Lock()
	hitungan[srcIP]++
	count := hitungan[srcIP]
	table := tablewriter.NewWriter(os.Stdout)
	table.Header([]string{"IP", "Jumlah"})
	for kata, jumlah := range hitungan {
		table.Append([]string{kata, fmt.Sprintf("%d", jumlah)})
	}
	hitunganMu.Unlock()

	fmt.Println("--- Hasil Hitungan ---")
	table.Render()
	return count
}

func recordAndPrintHitungan(srcIP string) {
	recordHitAndGetCount(srcIP)
}

func printHitungan(hitungan map[string]int) {
	hitunganMu.Lock()
	defer hitunganMu.Unlock()
	// Buat table writer
	table := tablewriter.NewWriter(os.Stdout)

	// Set header tabel
	table.Header([]string{"IP", "Jumlah"})

	// Iterasi map dan tambahkan data
	for kata, jumlah := range hitungan {
		table.Append([]string{kata, fmt.Sprintf("%d", jumlah)})
	}

	// Tampilkan judul dan render tabel
	fmt.Println("--- Hasil Hitungan ---")
	table.Render()
}
