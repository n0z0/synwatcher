package main

import (
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
)

func printHitungan(hitungan map[string]int) {
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
