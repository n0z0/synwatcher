package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// CTIEvent merepresentasikan skema data event untuk Threat Intelligence tingkat lanjut (SOC-Grade)
type CTIEvent struct {
	Timestamp          string          `json:"timestamp"` // ISO 8601 UTC
	SensorID           string          `json:"sensor_id"`
	EventType          string          `json:"event_type"` // TCP_SYN_SCAN, UDP_PROBE, ICMP_PORT_UNREACHABLE
	ScanBehavior       string          `json:"scan_behavior,omitempty"` // SINGLE_PORT_KNOCK, PORT_SWEEP_SCAN
	ScanHitCount       int             `json:"scan_hit_count,omitempty"`
	ScanVelocity       string          `json:"scan_velocity,omitempty"` // BURST_AUTOMATED_SCAN, STEADY_PACE_SCAN, SLOW_AND_LOW_STEALTH
	EstimatedOS        string          `json:"estimated_os,omitempty"` // Linux/Android/macOS, Windows, Network Device, dll.
	EstimatedHops      int             `json:"estimated_hops,omitempty"`
	ScannerTool        string          `json:"scanner_tool,omitempty"` // Nmap, Masscan, Standard OS Socket, dll.
	SYNFingerprint     string          `json:"syn_fingerprint,omitempty"` // Signature TCP (Ver:TTL:WS:Flags:Options)
	SYNFingerprintHash string          `json:"syn_hash,omitempty"`        // MD5 Hash IOC permanen
	TargetService      string          `json:"target_service,omitempty"` // SSH, SMB, RDP, Web, DB, dll.
	IntentCategory     string          `json:"intent_category,omitempty"` // LATERAL_MOVEMENT_PROBE, REMOTE_ACCESS_PROBE, dll.
	RiskScore          int             `json:"risk_score"`               // 0 - 100
	Severity           string          `json:"severity"`                 // INFO, LOW, MEDIUM, HIGH, CRITICAL
	Source             EndpointInfo    `json:"source"`
	Target             EndpointInfo    `json:"target"`
	IPLayer            *IPLayerInfo    `json:"ip_layer,omitempty"`
	TCPLayer           *TCPLayerInfo   `json:"tcp_layer,omitempty"`
	UDPLayer           *UDPLayerInfo   `json:"udp_layer,omitempty"`
	ICMPLayer          *ICMPLayerInfo  `json:"icmp_layer,omitempty"`
	Mitre              MitreAttackInfo `json:"mitre_attack"`
}

type EndpointInfo struct {
	IP         string `json:"ip"`
	Port       int    `json:"port,omitempty"`
	IsPrivate  bool   `json:"is_private"`
	ReverseDNS string `json:"reverse_dns,omitempty"`
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

// CalculateSYNFingerprint menghitung signature unik TCP SYN dan MD5 hash-nya
func CalculateSYNFingerprint(ipVer uint8, ttl uint8, windowSize uint16, flags []string, options []string) (string, string) {
	optsStr := "none"
	if len(options) > 0 {
		optsStr = strings.Join(options, ",")
	}
	flagsStr := "none"
	if len(flags) > 0 {
		flagsStr = strings.Join(flags, ",")
	}
	fp := fmt.Sprintf("%d:%d:%d:%s:%s", ipVer, ttl, windowSize, flagsStr, optsStr)
	h := md5.Sum([]byte(fp))
	return fp, hex.EncodeToString(h[:])
}

// CategorizeTargetService mengklasifikasikan port tujuan dan niat ancaman (threat intent)
func CategorizeTargetService(port int) (string, string) {
	switch port {
	case 22:
		return "SSH", "REMOTE_ACCESS_PROBE"
	case 23:
		return "Telnet", "INSECURE_REMOTE_ACCESS_PROBE"
	case 80, 8080, 8000, 8888:
		return "HTTP", "WEB_RECONNAISSANCE"
	case 443, 8443:
		return "HTTPS", "WEB_RECONNAISSANCE"
	case 445, 139, 135:
		return "SMB/RPC", "LATERAL_MOVEMENT_PROBE"
	case 3389:
		return "RDP", "REMOTE_DESKTOP_EXPLOITATION_PROBE"
	case 21:
		return "FTP", "FILE_TRANSFER_PROBE"
	case 3306:
		return "MySQL", "DATABASE_DISCOVERY"
	case 5432:
		return "PostgreSQL", "DATABASE_DISCOVERY"
	case 1433:
		return "MSSQL", "DATABASE_DISCOVERY"
	case 6379:
		return "Redis", "DATABASE_DISCOVERY"
	case 27017:
		return "MongoDB", "DATABASE_DISCOVERY"
	case 2222, 2022:
		return "SFTP/Alt-SSH", "REMOTE_ACCESS_PROBE"
	default:
		return fmt.Sprintf("Port-%d", port), "UNKNOWN_SERVICE_SCAN"
	}
}

var (
	velocityMu    sync.Mutex
	lastProbeTime = make(map[string]time.Time)
)

// TrackVelocity menganalisis kecepatan dan timing probe dari source IP
func TrackVelocity(srcIP string) string {
	velocityMu.Lock()
	defer velocityMu.Unlock()

	now := time.Now()
	lastTime, exists := lastProbeTime[srcIP]
	lastProbeTime[srcIP] = now

	if !exists {
		return "INITIAL_PROBE"
	}

	delta := now.Sub(lastTime)
	if delta < 200*time.Millisecond {
		return "BURST_AUTOMATED_SCAN"
	} else if delta <= 2*time.Second {
		return "STEADY_PACE_SCAN"
	}
	return "SLOW_AND_LOW_STEALTH"
}

// CalculateRiskScore menghitung dynamic risk score 0 - 100 dan severity level
func CalculateRiskScore(scannerTool, intentCategory, scanBehavior, scanVelocity string, hitCount int) (int, string) {
	score := 20 // baseline score untuk probe/scan

	if strings.Contains(scannerTool, "Nmap") || strings.Contains(scannerTool, "Masscan") || strings.Contains(scannerTool, "ZMap") {
		score += 25
	} else if strings.Contains(scannerTool, "Custom") || strings.Contains(scannerTool, "Raw") {
		score += 15
	}

	if scanBehavior == "PORT_SWEEP_SCAN" {
		score += 20
	}
	if hitCount > 10 {
		score += 15
	} else if hitCount > 3 {
		score += 10
	}

	switch intentCategory {
	case "LATERAL_MOVEMENT_PROBE", "REMOTE_DESKTOP_EXPLOITATION_PROBE":
		score += 25
	case "DATABASE_DISCOVERY":
		score += 20
	case "REMOTE_ACCESS_PROBE", "INSECURE_REMOTE_ACCESS_PROBE":
		score += 15
	case "WEB_RECONNAISSANCE":
		score += 10
	}

	switch scanVelocity {
	case "BURST_AUTOMATED_SCAN":
		score += 10
	case "SLOW_AND_LOW_STEALTH":
		score += 15
	}

	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	severity := "INFO"
	if score >= 85 {
		severity = "CRITICAL"
	} else if score >= 70 {
		severity = "HIGH"
	} else if score >= 45 {
		severity = "MEDIUM"
	} else if score >= 25 {
		severity = "LOW"
	}

	return score, severity
}

func newCTIBaseEvent(eventType, srcIP string, srcPort int, dstIP string, dstPort int, pkt gopacket.Packet, hitCount int, windowSize uint16, flags []string, options []string) *CTIEvent {
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
	var ipVer uint8 = 4
	var ipTTL uint8 = 64
	if ipLayer != nil {
		ipVer = ipLayer.Version
		ipTTL = ipLayer.TTL
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

	// Hitung SYN Fingerprint & Hash
	synFp, synHash := CalculateSYNFingerprint(ipVer, ipTTL, windowSize, flags, options)

	// Kategorisasi Service & Threat Intent
	targetService, intentCategory := CategorizeTargetService(dstPort)

	// Hitung Scan Velocity
	scanVelocity := TrackVelocity(srcIP)

	// Hitung Risk Score & Severity
	riskScore, severity := CalculateRiskScore(scannerTool, intentCategory, scanBehavior, scanVelocity, hitCount)

	return &CTIEvent{
		Timestamp:          time.Now().UTC().Format(time.RFC3339Nano),
		SensorID:           hostname,
		EventType:          eventType,
		ScanBehavior:       scanBehavior,
		ScanHitCount:       hitCount,
		ScanVelocity:       scanVelocity,
		EstimatedOS:        estimatedOS,
		EstimatedHops:      estimatedHops,
		ScannerTool:        scannerTool,
		SYNFingerprint:     synFp,
		SYNFingerprintHash: synHash,
		TargetService:      targetService,
		IntentCategory:     intentCategory,
		RiskScore:          riskScore,
		Severity:           severity,
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
