package main

import (
	"flag"
	"strconv"
	"strings"
	"sync"

	"github.com/google/gopacket/pcap"
)

var (
	iface   = flag.String("iface", "", "Npcap interface name (kosongkan untuk auto-pick)")
	snaplen = flag.Int("snaplen", 96, "SnapLen bytes per packet")
	promisc = flag.Bool("promisc", true, "Promiscuous mode")
	timeout = flag.Duration("timeout", pcap.BlockForever, "pcap timeout (BlockForever disarankan)")
	// Filter: TCP SYN (tanpa ACK) untuk ip & ip6
	// Catatan: tcp[13] & 0x02 != 0  => SYN bit set
	//          tcp[13] & 0x10 == 0  => ACK bit tidak set
	//-sS dan -sT nmap menghasilkan paket seperti ini
	bpfstring = "ip and ((tcp and (ip[6:2] & 0x1fff = 0) and (tcp[13] & 0x12 = 0x02)) or (udp and not (udp port 53 or 443 or 123 or 161 or 1900 or 5353)) or (icmp and icmp[0] = 3 and icmp[1] = 3))"

	bpf = flag.String("bpf", bpfstring, "BPF filter")
	// CTI Logging
	ctiLogFile = flag.String("logfile", "synwatcher_cti.jsonl", "Lokasi file log CTI (JSONL format, kosongkan untuk nonaktifkan)")
	sensorID   = flag.String("sensor", "", "Sensor / Host identifier untuk data CTI (default nama komputer)")

	// cache IP lokal dari device yang dipilih
	localIPs = map[string]struct{}{}
	//cachedb
	cacheDB = "127.0.0.1:50051"

	// Port services yang diabaikan agar tidak menimpa password port-knock
	sftpPort      = flag.Int("sftpport", 60606, "Port SFTP honeypot (scp) yang diabaikan agar tidak menimpa password knock")
	classrootPort = flag.Int("classrootport", 8443, "Port WebRTC decoy (ClassRoot) yang diabaikan")
	lemesPort     = flag.Int("lemesport", 50505, "Port Honeybeacon HTTP decoy (lemes) yang diabaikan")
	cachedbPort   = flag.Int("cachedbport", 50051, "Port gRPC bus (cacheDB) yang diabaikan")
	extraIgnore   = flag.String("ignoreports", "", "Daftar port tambahan yang diabaikan dipisahkan koma (contoh: 8080,9000)")

	hitungan   = make(map[string]int)
	hitunganMu sync.Mutex
)

// isIgnoredPort mengecek apakah port merupakan port decoy/honeypot internal yang harus diabaikan
// dari penulisan port-knock password di cacheDB.
func isIgnoredPort(p int) (bool, string) {
	if sftpPort != nil && p == *sftpPort {
		return true, "SFTP (scp)"
	}
	if classrootPort != nil && p == *classrootPort {
		return true, "WebRTC (ClassRoot)"
	}
	if lemesPort != nil && p == *lemesPort {
		return true, "Honeybeacon (lemes)"
	}
	if cachedbPort != nil && p == *cachedbPort {
		return true, "gRPC (cacheDB)"
	}
	if extraIgnore != nil && *extraIgnore != "" {
		for _, part := range strings.Split(*extraIgnore, ",") {
			part = strings.TrimSpace(part)
			if customP, err := strconv.Atoi(part); err == nil && customP == p {
				return true, "Custom Ignored"
			}
		}
	}
	return false, ""
}
