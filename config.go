package main

import (
	"flag"

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
	//bpfstring = "(ip or ip6) and tcp and (tcp[13] & 0x02 != 0) and (tcp[13] & 0x10 == 0)"
	// -sU untuk UDP bisa ditambahkan nanti
	bpfstring = "ip and ((tcp and (ip[6:2] & 0x1fff = 0) and (tcp[13] & 0x12 = 0x02)) or (udp and not (udp port 53 or 443 or 123 or 161 or 1900 or 5353)) or (icmp and icmp[0] = 3 and icmp[1] = 3))"

	//bpfstring = "ip and ((tcp and (ip[6:2] & 0x1fff = 0) and (tcp[13] & 0x12 = 0x02)) or udp or (icmp and icmp[0] = 3 and icmp[1] = 3))"
	bpf = flag.String("bpf", bpfstring, "BPF filter")
	// cache IP lokal dari device yang dipilih
	localIPs = map[string]struct{}{}
	//cachedb
	cacheDB = "127.0.0.1:50051"
	//ignore sftp port
	sftpPort = 2025
)
