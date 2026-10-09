package main

import (
	"context"
	"fmt"
	netpkg "net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/n0z0/cachedb/cdc"
	"github.com/n0z0/cachedb/proto/cachepb"
)

var rdnsCache sync.Map

// getReverseDNS mengambil nama domain PTR dengan in-memory deduplication cache
func getReverseDNS(ip string) string {
	if val, ok := rdnsCache.Load(ip); ok {
		return val.(string)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()
	var r netpkg.Resolver
	var host string
	if names, err := r.LookupAddr(ctx, ip); err == nil && len(names) > 0 {
		host = strings.TrimSuffix(names[0], ".")
	}
	rdnsCache.Store(ip, host)
	return host
}

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
			// Hanya SYN yang ditujukan ke mesin ini (abaikan trafik host lain
			// yang ikut tertangkap karena mode promiscuous)
			if _, ok := localIPs[dstIP]; !ok {
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

			options := formatTCPOptions(tcp.Options)
			nowStr := time.Now().Format("15:04:05.000")

			// Set a key-value pair to cacheDB (Critical Path untuk port knock)
			if int(tcp.DstPort) == *sftpPort {
				recordHitWithStatus(srcIP, fmt.Sprintf("Port %d (SFTP Ignored)", tcp.DstPort))
				addActivityLog(fmt.Sprintf("[%s] [SYN] %s:%d -> :%d (%s) | Writer: Abaikan port SFTP (%d)",
					nowStr, srcIP, tcp.SrcPort, tcp.DstPort, strings.Join(flags, "|"), *sftpPort))
				return
			}

			passwd := strconv.Itoa(int(tcp.DstPort))
			err := cdc.Set(srcIP, passwd, db)
			var hitCount int
			if err != nil {
				hitCount = recordHitWithStatus(srcIP, fmt.Sprintf("Port %d (Knock Error)", tcp.DstPort))
				addActivityLog(fmt.Sprintf("[%s] [SYN] %s:%d -> :%d (%s) | Writer ERROR: %v",
					nowStr, srcIP, tcp.SrcPort, tcp.DstPort, strings.Join(flags, "|"), err))
			} else {
				hitCount = recordHitWithStatus(srcIP, fmt.Sprintf("Knock Active (Port %s)", passwd))
				addActivityLog(fmt.Sprintf("[%s] [SYN] %s:%d -> :%d (%s) | Writer: Set knock passwd=%s",
					nowStr, srcIP, tcp.SrcPort, tcp.DstPort, strings.Join(flags, "|"), passwd))
			}

			// Manfaatkan Goroutine untuk asynchronous enrichment CTI & push metadata ke CacheDB
			go func(srcIP, dstIP string, srcPort, dstPort int, win uint16, seq, ack uint32, tcpFlags, tcpOptions []string, packet gopacket.Packet, client cachepb.CacheClient, hits int) {
				if ctiLogger != nil {
					ctiEvent := newCTIBaseEvent("TCP_SYN_SCAN", srcIP, srcPort, dstIP, dstPort, packet, hits, win, tcpFlags, tcpOptions)
					ctiEvent.TCPLayer = &TCPLayerInfo{
						SeqNum:     seq,
						AckNum:     ack,
						WindowSize: win,
						Flags:      tcpFlags,
						Options:    tcpOptions,
					}

					// Async reverse DNS resolution non-blocking (dengan in-memory deduplication)
					if !ctiEvent.Source.IsPrivate && srcIP != "127.0.0.1" && srcIP != "::1" {
						ctiEvent.Source.ReverseDNS = getReverseDNS(srcIP)
					}

					ctiLogger.LogEvent(ctiEvent)

					// Inter-Service Threat Intelligence correlation ke CacheDB
					if client != nil {
						_ = cdc.Set("actor:syn_hash:"+srcIP, ctiEvent.SYNFingerprintHash, client)
						_ = cdc.Set("actor:risk:"+srcIP, strconv.Itoa(ctiEvent.RiskScore), client)
						_ = cdc.Set("actor:severity:"+srcIP, ctiEvent.Severity, client)
						_ = cdc.Set("actor:target_service:"+srcIP, ctiEvent.TargetService, client)
						_ = cdc.Set("actor:intent:"+srcIP, ctiEvent.IntentCategory, client)
						_ = cdc.Set("actor:velocity:"+srcIP, ctiEvent.ScanVelocity, client)
						_ = cdc.Set("actor:os:"+srcIP, ctiEvent.EstimatedOS, client)
						_ = cdc.Set("actor:scanner:"+srcIP, ctiEvent.ScannerTool, client)
						_ = cdc.Set("actor:scan_hits:"+srcIP, strconv.Itoa(hits), client)
						_ = cdc.Set("actor:last_scan:"+srcIP, ctiEvent.Timestamp, client)
						if ctiEvent.Source.ReverseDNS != "" {
							_ = cdc.Set("actor:rdns:"+srcIP, ctiEvent.Source.ReverseDNS, client)
						}
					}
				}
			}(srcIP, dstIP, int(tcp.SrcPort), int(tcp.DstPort), tcp.Window, tcp.Seq, tcp.Ack, flags, options, pkt, db, hitCount)

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

		nowStr := time.Now().Format("15:04:05.000")

		// Set a key-value pair to cacheDB
		if int(udp.DstPort) == *sftpPort {
			recordHitWithStatus(srcIP, fmt.Sprintf("Port %d (UDP SFTP Ignored)", udp.DstPort))
			addActivityLog(fmt.Sprintf("[%s] [UDP] %s:%d -> :%d | Writer: Abaikan port SFTP (%d)",
				nowStr, srcIP, udp.SrcPort, udp.DstPort, *sftpPort))
			return
		}

		passwd := strconv.Itoa(int(udp.DstPort))
		err := cdc.Set(srcIP, passwd, db)
		var hitCount int
		if err != nil {
			hitCount = recordHitWithStatus(srcIP, fmt.Sprintf("Port %d (UDP Knock Error)", udp.DstPort))
			addActivityLog(fmt.Sprintf("[%s] [UDP] %s:%d -> :%d | Writer ERROR: %v",
				nowStr, srcIP, udp.SrcPort, udp.DstPort, err))
		} else {
			hitCount = recordHitWithStatus(srcIP, fmt.Sprintf("Knock Active (UDP Port %s)", passwd))
			addActivityLog(fmt.Sprintf("[%s] [UDP] %s:%d -> :%d | Writer: Set knock passwd=%s",
				nowStr, srcIP, udp.SrcPort, udp.DstPort, passwd))
		}

		// Asynchronous CTI enrichment and metadata push using Goroutine
		go func(srcIP, dstIP string, srcPort, dstPort int, udpLen uint16, pLen int, packet gopacket.Packet, client cachepb.CacheClient, hits int) {
			if ctiLogger != nil {
				ctiEvent := newCTIBaseEvent("UDP_PROBE", srcIP, srcPort, dstIP, dstPort, packet, hits, 0, nil, nil)
				ctiEvent.UDPLayer = &UDPLayerInfo{
					Length:     udpLen,
					PayloadLen: pLen,
				}

				if !ctiEvent.Source.IsPrivate && srcIP != "127.0.0.1" && srcIP != "::1" {
					ctiEvent.Source.ReverseDNS = getReverseDNS(srcIP)
				}

				ctiLogger.LogEvent(ctiEvent)

				if client != nil {
					_ = cdc.Set("actor:risk:"+srcIP, strconv.Itoa(ctiEvent.RiskScore), client)
					_ = cdc.Set("actor:severity:"+srcIP, ctiEvent.Severity, client)
					_ = cdc.Set("actor:target_service:"+srcIP, ctiEvent.TargetService, client)
					_ = cdc.Set("actor:intent:"+srcIP, ctiEvent.IntentCategory, client)
					_ = cdc.Set("actor:velocity:"+srcIP, ctiEvent.ScanVelocity, client)
					_ = cdc.Set("actor:os:"+srcIP, ctiEvent.EstimatedOS, client)
					_ = cdc.Set("actor:scanner:"+srcIP, "UDP Probe", client)
					_ = cdc.Set("actor:scan_hits:"+srcIP, strconv.Itoa(hits), client)
					_ = cdc.Set("actor:last_scan:"+srcIP, ctiEvent.Timestamp, client)
					if ctiEvent.Source.ReverseDNS != "" {
						_ = cdc.Set("actor:rdns:"+srcIP, ctiEvent.Source.ReverseDNS, client)
					}
				}
			}
		}(srcIP, dstIP, int(udp.SrcPort), int(udp.DstPort), udp.Length, payloadLen, pkt, db, hitCount)

		return
	}

	// ----- ICMPv4: indikasi -sU ke port closed (type 3 code 3) -----
	if icmpL := pkt.Layer(layers.LayerTypeICMPv4); icmpL != nil {
		icmp := icmpL.(*layers.ICMPv4)
		if icmp.TypeCode.Type() == layers.ICMPv4TypeDestinationUnreachable &&
			icmp.TypeCode.Code() == 3 {

			srcIP := net.NetworkFlow().Src().String()
			dstIP := net.NetworkFlow().Dst().String()

			// Coba ekstrak 5-tuple asli dari payload ICMP (berisi IP header + 8 byte L4)
			var ip4 layers.IPv4
			var udp layers.UDP
			parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &udp)
			decoded := []gopacket.LayerType{}
			if err := parser.DecodeLayers(icmp.Payload, &decoded); err == nil {
				if contains(decoded, layers.LayerTypeUDP) {
					addActivityLog(fmt.Sprintf("[%s] [ICMP-UR] port unreach %s -> %s (Orig UDP :%d)",
						time.Now().Format("15:04:05.000"), srcIP, dstIP, udp.DstPort))

					if ctiLogger != nil {
						go func(srcIP, dstIP string, packet gopacket.Packet, typeCode layers.ICMPv4TypeCode, oSrc, oDst EndpointInfo) {
							event := newCTIBaseEvent("ICMP_PORT_UNREACHABLE", srcIP, 0, dstIP, 0, packet, 1, 0, nil, nil)
							event.ICMPLayer = &ICMPLayerInfo{
								Type:     uint8(typeCode.Type()),
								Code:     typeCode.Code(),
								OrigSrc:  &oSrc,
								OrigDest: &oDst,
							}
							ctiLogger.LogEvent(event)
						}(srcIP, dstIP, pkt, icmp.TypeCode, EndpointInfo{
							IP:        ip4.SrcIP.String(),
							Port:      int(udp.SrcPort),
							IsPrivate: isLocalIP(ip4.SrcIP.String()),
						}, EndpointInfo{
							IP:        ip4.DstIP.String(),
							Port:      int(udp.DstPort),
							IsPrivate: isLocalIP(ip4.DstIP.String()),
						})
					}
					return
				}
			}

			// Fallback kalau parsing payload gagal
			addActivityLog(fmt.Sprintf("[%s] [ICMP-UR] port unreach %s -> %s (Code %d)",
				time.Now().Format("15:04:05.000"), srcIP, dstIP, icmp.TypeCode.Code()))

			if ctiLogger != nil {
				go func(srcIP, dstIP string, packet gopacket.Packet, typeCode layers.ICMPv4TypeCode) {
					event := newCTIBaseEvent("ICMP_PORT_UNREACHABLE", srcIP, 0, dstIP, 0, packet, 1, 0, nil, nil)
					event.ICMPLayer = &ICMPLayerInfo{
						Type: uint8(typeCode.Type()),
						Code: typeCode.Code(),
					}
					ctiLogger.LogEvent(event)
				}(srcIP, dstIP, pkt, icmp.TypeCode)
			}
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
