package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// CTIEvent merepresentasikan skema data event untuk Threat Intelligence tingkat lanjut (SOC-Grade)
type CTIEvent struct {
	Timestamp     string          `json:"timestamp"` // ISO 8601 UTC
	SensorID      string          `json:"sensor_id"`
	EventType     string          `json:"event_type"` // TCP_SYN_SCAN, UDP_PROBE, ICMP_PORT_UNREACHABLE
	ScanBehavior  string          `json:"scan_behavior,omitempty"` // SINGLE_PORT_KNOCK, PORT_SWEEP_SCAN
	ScanHitCount  int             `json:"scan_hit_count,omitempty"`
	EstimatedOS   string          `json:"estimated_os,omitempty"` // Linux/Android/macOS, Windows, Network Device, dll.
	EstimatedHops int             `json:"estimated_hops,omitempty"`
	ScannerTool   string          `json:"scanner_tool,omitempty"` // Nmap, Masscan, Standard OS Socket, dll.
	Source        EndpointInfo    `json:"source"`
	Target        EndpointInfo    `json:"target"`
	IPLayer       *IPLayerInfo    `json:"ip_layer,omitempty"`
	TCPLayer      *TCPLayerInfo   `json:"tcp_layer,omitempty"`
	UDPLayer      *UDPLayerInfo   `json:"udp_layer,omitempty"`
	ICMPLayer     *ICMPLayerInfo  `json:"icmp_layer,omitempty"`
	Mitre         MitreAttackInfo `json:"mitre_attack"`
}

type EndpointInfo struct {
	IP        string `json:"ip"`
	Port      int    `json:"port,omitempty"`
	IsPrivate bool   `json:"is_private"`
}

type IPLayerInfo struct {
	Version  uint8  `json:"version"`
	TTL      uint8  `json:"ttl"`
	ID       uint16 `json:"id"`
	Protocol string `json:"protocol"`
	Length   uint16 `json:"length"`
}

type TCPLayerInfo struct {
	SeqNum     uint32   `json:"seq"`
	AckNum     uint32   `json:"ack"`
	WindowSize uint16   `json:"window_size"`
	Flags      []string `json:"flags"`
	Options    []string `json:"options,omitempty"`
}

type UDPLayerInfo struct {
	Length     uint16 `json:"length"`
	PayloadLen int    `json:"payload_length"`
}

type ICMPLayerInfo struct {
	Type     uint8         `json:"type"`
	Code     uint8         `json:"code"`
	OrigSrc  *EndpointInfo `json:"orig_src,omitempty"`
	OrigDest *EndpointInfo `json:"orig_dst,omitempty"`
}

type MitreAttackInfo struct {
	Tactic    string `json:"tactic"`
	Technique string `json:"technique"`
	ID        string `json:"technique_id"`
}

type CTILogger struct {
	file      *os.File
	eventChan chan *CTIEvent
	quit      chan struct{}
	wg        sync.WaitGroup
	mu        sync.Mutex
}

var ctiLogger *CTILogger

func initCTILogger(path string) (*CTILogger, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("gagal membuka log CTI %s: %w", path, err)
	}

	logger := &CTILogger{
		file:      f,
		eventChan: make(chan *CTIEvent, 4096),
		quit:      make(chan struct{}),
	}

	logger.wg.Add(1)
	go func() {
		defer logger.wg.Done()
		for {
			select {
			case event, ok := <-logger.eventChan:
				if !ok {
					return
				}
				data, err := json.Marshal(event)
				if err != nil {
					log.Printf("[CTI] Gagal serialize JSON event: %v", err)
					continue
				}
				logger.mu.Lock()
				logger.file.Write(append(data, '\n'))
				logger.mu.Unlock()
			case <-logger.quit:
				for {
					select {
					case event := <-logger.eventChan:
						data, err := json.Marshal(event)
						if err == nil {
							logger.mu.Lock()
							logger.file.Write(append(data, '\n'))
							logger.mu.Unlock()
						}
					default:
						return
					}
				}
			}
		}
	}()

	ctiLogger = logger
	return ctiLogger, nil
}

func (l *CTILogger) Close() {
	if l != nil {
		close(l.quit)
		l.wg.Wait()
		if l.file != nil {
			l.file.Close()
		}
	}
}

func (l *CTILogger) LogEvent(event *CTIEvent) {
	if l == nil {
		return
	}
	select {
	case l.eventChan <- event:
	default:
		go func() {
			data, err := json.Marshal(event)
			if err == nil && l.file != nil {
				l.mu.Lock()
				defer l.mu.Unlock()
				l.file.Write(append(data, '\n'))
			}
		}()
	}
}

// Helper untuk mengekstrak layer IP (IPv4 / IPv6)
func extractIPInfo(pkt gopacket.Packet) *IPLayerInfo {
	if ip4L := pkt.Layer(layers.LayerTypeIPv4); ip4L != nil {
		ip4 := ip4L.(*layers.IPv4)
		return &IPLayerInfo{
			Version:  4,
			TTL:      ip4.TTL,
			ID:       ip4.Id,
			Protocol: ip4.Protocol.String(),
			Length:   ip4.Length,
		}
	}
	if ip6L := pkt.Layer(layers.LayerTypeIPv6); ip6L != nil {
		ip6 := ip6L.(*layers.IPv6)
		return &IPLayerInfo{
			Version:  6,
			TTL:      ip6.HopLimit,
			Protocol: ip6.NextHeader.String(),
			Length:   ip6.Length,
		}
	}
	return nil
}

// Helper untuk mengidentifikasi nama-nama opsi TCP (penting untuk fingerprinting/p0f)
func formatTCPOptions(opts []layers.TCPOption) []string {
	var res []string
	for _, opt := range opts {
		switch opt.OptionType {
		case layers.TCPOptionKindMSS:
			res = append(res, "MSS")
		case layers.TCPOptionKindWindowScale:
			res = append(res, "WScale")
		case layers.TCPOptionKindSACKPermitted:
			res = append(res, "SACKPerm")
		case layers.TCPOptionKindSACK:
			res = append(res, "SACK")
		case layers.TCPOptionKindTimestamps:
			res = append(res, "TS")
		case layers.TCPOptionKindNop:
			res = append(res, "NOP")
		case layers.TCPOptionKindEndList:
			res = append(res, "EOL")
		default:
			res = append(res, fmt.Sprintf("Opt(%d)", opt.OptionType))
		}
	}
	return res
}

// EstimateOS mengestimasi sistem operasi pelaku berdasarkan TTL dan Window Size (Passive OS Fingerprinting)
func EstimateOS(ttl uint8, windowSize uint16) (string, int) {
	if ttl == 0 {
		return "Unknown", 0
	}

	var baseTTL uint8
	var osName string

	if ttl <= 64 {
		baseTTL = 64
		osName = "Linux / Android / macOS"
	} else if ttl <= 128 {
		baseTTL = 128
		osName = "Windows (10/11/Server)"
	} else {
		baseTTL = 255
		osName = "Network Appliance / Solaris / Cisco"
	}

	hops := int(baseTTL - ttl)
	if hops < 0 {
		hops = 0
	}

	return osName, hops
}

// IdentifyScannerTool menganalisis urutan opsi TCP dan ukuran window untuk mengidentifikasi alat scanner
func IdentifyScannerTool(windowSize uint16, options []string) string {
	hasMSS := false
	hasSACK := false
	hasTS := false
	hasWScale := false

	for _, opt := range options {
		switch opt {
		case "MSS":
			hasMSS = true
		case "SACKPerm":
			hasSACK = true
		case "TS":
			hasTS = true
		case "WScale":
			hasWScale = true
		}
	}

	// Masscan signature: Window Size 1024, tanpa opsi TCP
	if windowSize == 1024 && len(options) == 0 {
		return "Masscan"
	}

	// Nmap Stealth SYN Scan signature: Window Size kelipatan 1024 (1024, 2048, 3072, 4096), urutan khas MSS, SACKPerm, TS, NOP, WScale
	if (windowSize == 1024 || windowSize == 2048 || windowSize == 3072 || windowSize == 4096) && hasMSS && hasSACK {
		return "Nmap (Stealth SYN Scan)"
	}

	// ZMap signature: Window size 65535, tanpa opsi
	if windowSize == 65535 && len(options) == 0 {
		return "ZMap"
	}

	// Standard OS Socket (PowerShell / Test-NetConnection / Browser / Python):
	if windowSize >= 8192 && hasMSS {
		if hasWScale || hasSACK || hasTS {
			return "Standard OS Socket (PowerShell/Browser/Socket)"
		}
		return "Standard TCP Client"
	}

	if len(options) > 0 {
		return "Custom TCP Scanner"
	}

	return "Raw SYN Probe"
}

func newCTIBaseEvent(eventType, srcIP string, srcPort int, dstIP string, dstPort int, pkt gopacket.Packet, hitCount int, windowSize uint16, options []string) *CTIEvent {
	hostname := *sensorID
	if hostname == "" {
		hostname, _ = os.Hostname()
		if hostname == "" {
			hostname = "synwatcher"
		}
	}

	ipLayer := extractIPInfo(pkt)
	var estimatedOS string
	var estimatedHops int
	if ipLayer != nil {
		estimatedOS, estimatedHops = EstimateOS(ipLayer.TTL, windowSize)
	}

	var scannerTool string
	if len(options) > 0 || windowSize > 0 {
		scannerTool = IdentifyScannerTool(windowSize, options)
	}

	scanBehavior := "SINGLE_PORT_KNOCK"
	mitreTechnique := "Network Service Discovery"
	mitreID := "T1046"

	if hitCount > 1 {
		scanBehavior = "PORT_SWEEP_SCAN"
		mitreTechnique = "Active Scanning: Scanning IP Blocks / Ports"
		mitreID = "T1595.002"
	}

	return &CTIEvent{
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		SensorID:      hostname,
		EventType:     eventType,
		ScanBehavior:  scanBehavior,
		ScanHitCount:  hitCount,
		EstimatedOS:   estimatedOS,
		EstimatedHops: estimatedHops,
		ScannerTool:   scannerTool,
		Source: EndpointInfo{
			IP:        srcIP,
			Port:      srcPort,
			IsPrivate: isLocalIP(srcIP),
		},
		Target: EndpointInfo{
			IP:        dstIP,
			Port:      dstPort,
			IsPrivate: isLocalIP(dstIP),
		},
		IPLayer: ipLayer,
		Mitre: MitreAttackInfo{
			Tactic:    "Reconnaissance",
			Technique: mitreTechnique,
			ID:        mitreID,
		},
	}
}
