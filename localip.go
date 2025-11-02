package main

import (
	"fmt"
	"net"
)

// privateNets akan menyimpan semua rentang jaringan IP privat
// yang akan kita periksa. Variabel ini diisi sekali saat package dimuat.
var privateNets []*net.IPNet

// init adalah fungsi khusus yang dijalankan secara otomatis
// sebelum fungsi main dijalankan. Kita gunakan untuk menyiapkan
// daftar rentang IP privat agar tidak perlu dibuat ulang setiap
// kali fungsi isLocalIP dipanggil.
func init() {
	// Daftar CIDR (Classless Inter-Domain Routing) untuk IP privat
	// dan lokal lainnya.
	cidrs := []string{
		"10.0.0.0/8",     // RFC 1918: Private network
		"172.16.0.0/12",  // RFC 1918: Private network
		"192.168.0.0/16", // RFC 1918: Private network
		"127.0.0.0/8",    // Loopback (localhost)
		"169.254.0.0/16", // Link-local
		"::1/128",        // IPv6 Loopback
		"fc00::/7",       // IPv6 Unique local address
		"fe80::/10",      // IPv6 Link-local
	}

	for _, cidr := range cidrs {
		// net.ParseCIDR memecah string CIDR menjadi IP dan netmask
		// Kita hanya butuh bagian netmask-nya (IPNet)
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			// Jika ada kesalahan parsing, program akan berhenti.
			// Ini seharusnya tidak terjadi karena stringnya sudah benar.
			panic(fmt.Sprintf("Error parsing CIDR %s: %v", cidr, err))
		}
		privateNets = append(privateNets, block)
	}
}

// isLocalIP memeriksa apakah string alamat IP yang diberikan
// merupakan IP lokal (privat, loopback, atau link-local).
func isLocalIP(ipaddress string) bool {
	// Pertama, kita parsing string IP menjadi tipe net.IP.
	// Jika formatnya salah, net.ParseIP akan mengembalikan nil.
	ip := net.ParseIP(ipaddress)
	if ip == nil {
		// Jika bukan IP yang valid, maka bukan IP lokal.
		return false
	}

	// Selanjutnya, kita iterasi melalui semua rentang jaringan privat
	// yang sudah kita siapkan di fungsi init().
	for _, block := range privateNets {
		// block.Contains(ip) akan mengembalikan true jika IP berada
		// di dalam rentang jaringan (block) tersebut.
		if block.Contains(ip) {
			return true // Ketemu! IP ini adalah lokal.
		}
	}

	// Jika setelah diperiksa di semua rentang tidak ada yang cocok,
	// berarti IP tersebut adalah IP publik.
	return false
}
