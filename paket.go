package main

import (
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/n0z0/cachedb/cdc"
	"github.com/n0z0/cachedb/proto/cachepb"
)

func handlePacket(pkt gopacket.Packet, db cachepb.CacheClient) {
	net := pkt.NetworkLayer()
	//tr := pkt.TransportLayer()
	if net == nil {
		return
	}

	// ----- TCP: deteksi -sS/-sT (SYN tanpa ACK) -----
	if tcpL := pkt.Layer(layers.LayerTypeTCP); tcpL != nil {
		tcp := tcpL.(*layers.TCP)
		if tcp.SYN && !tcp.ACK {
			srcIP := net.NetworkFlow().Src().String()
			dstIP := net.NetworkFlow().Dst().String()

			if _, ok := localIPs[srcIP]; ok {
				return
			}
			if srcIP == "127.0.0.1" || srcIP == "::1" {
				return
			}

			flags := []string{}
			if tcp.SYN {
				flags = append(flags, "SYN")
			}
			if tcp.ACK {
				flags = append(flags, "ACK")
			}
			if tcp.RST {
				flags = append(flags, "RST")
			}
			if tcp.FIN {
				flags = append(flags, "FIN")
			}
			if tcp.PSH {
				flags = append(flags, "PSH")
			}
			if tcp.URG {
				flags = append(flags, "URG")
			}

			log.Printf("[SYN] %s:%d -> %s:%d flags=%s win=%d ts=%s",
				srcIP, tcp.SrcPort, dstIP, tcp.DstPort,
				strings.Join(flags, "|"), tcp.Window, time.Now().Format(time.RFC3339Nano))

			// Set a key-value pair to cacheDB
			if int(tcp.DstPort) == sftpPort {
				log.Println("Writer: Mengabaikan penulisan untuk port SFTP")
				return
			}
			log.Println("Writer: Menulis data...")
			passwd := strconv.Itoa(int(tcp.DstPort))
			err := cdc.Set(srcIP, passwd, db)
			if err != nil {
				log.Printf("Writer: Gagal menulis: %v", err)
			} else {
				log.Println("Writer: Berhasil menulis: " + srcIP + ":" + passwd)
			}

			return
		}
	}

	// ----- UDP: deteksi -sU (probe masuk) -----
	if udpL := pkt.Layer(layers.LayerTypeUDP); udpL != nil {
		udp := udpL.(*layers.UDP)

		srcIP := net.NetworkFlow().Src().String()
		dstIP := net.NetworkFlow().Dst().String()

		if _, ok := localIPs[srcIP]; ok {
			return
		}
		if _, ok := localIPs[dstIP]; !ok {
			return
		}
		if srcIP == "127.0.0.1" || srcIP == "::1" {
			return
		}
		if !isLocalIP(srcIP) {
			return
		}

		// Panjang payload (UDP.Length mencakup header 8 byte)
		payloadLen := int(udp.Length) - 8
		if payloadLen < 0 {
			payloadLen = 0
		}

		log.Printf("[UDP] %s:%d -> %s:%d len=%d ts=%s",
			srcIP, udp.SrcPort, dstIP, udp.DstPort, payloadLen, time.Now().Format(time.RFC3339Nano))

		// Set a key-value pair to cacheDB
		if int(udp.DstPort) == sftpPort {
			log.Println("Writer: Mengabaikan penulisan untuk port SFTP")
			return
		}
		log.Println("Writer: Menulis data...")
		passwd := strconv.Itoa(int(udp.DstPort))
		err := cdc.Set(srcIP, passwd, db)
		if err != nil {
			log.Printf("Writer: Gagal menulis: %v", err)
		} else {
			log.Println("Writer: Berhasil menulis: " + srcIP + ":" + passwd)
		}

		return
	}

	// ----- ICMPv4: indikasi -sU ke port closed (type 3 code 3) -----
	if icmpL := pkt.Layer(layers.LayerTypeICMPv4); icmpL != nil {
		icmp := icmpL.(*layers.ICMPv4)
		if icmp.TypeCode.Type() == layers.ICMPv4TypeDestinationUnreachable &&
			icmp.TypeCode.Code() == 3 {

			// Coba ekstrak 5-tuple asli dari payload ICMP (berisi IP header + 8 byte L4)
			// Ini memudahkan melihat port UDP yang dituju nmap.
			var ip4 layers.IPv4
			var udp layers.UDP
			parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &udp)
			decoded := []gopacket.LayerType{}
			if err := parser.DecodeLayers(icmp.Payload, &decoded); err == nil {
				if contains(decoded, layers.LayerTypeUDP) {
					log.Printf("[ICMP-UR] dst-unreach/port (%d) %s -> %s  origUDP %s:%d -> %s:%d ts=%s",
						icmp.TypeCode.Code(),
						net.NetworkFlow().Src().String(),
						net.NetworkFlow().Dst().String(),
						ip4.SrcIP, udp.SrcPort, ip4.DstIP, udp.DstPort,
						time.Now().Format(time.RFC3339Nano))
					return
				}
			}

			// Fallback kalau parsing payload gagal
			log.Printf("[ICMP-UR] dst-unreach/port (%d) %s -> %s ts=%s",
				icmp.TypeCode.Code(),
				net.NetworkFlow().Src().String(), net.NetworkFlow().Dst().String(),
				time.Now().Format(time.RFC3339Nano))
			return
		}
	}

	// (opsional) else: abaikan paket lain
}

func contains(ss []gopacket.LayerType, t gopacket.LayerType) bool {
	for _, x := range ss {
		if x == t {
			return true
		}
	}
	return false
}
