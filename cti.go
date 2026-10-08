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

// CTIEvent merepresentasikan skema data event untuk Threat Intelligence
type CTIEvent struct {
	Timestamp  string          `json:"timestamp"` // ISO 8601 UTC
	SensorID   string          `json:"sensor_id"`
	EventType  string          `json:"event_type"` // TCP_SYN_SCAN, UDP_PROBE, ICMP_UNREACHABLE
	Source     EndpointInfo    `json:"source"`
	Target     EndpointInfo    `json:"target"`
	IPLayer    *IPLayerInfo    `json:"ip_layer,omitempty"`
	TCPLayer   *TCPLayerInfo   `json:"tcp_layer,omitempty"`
	UDPLayer   *UDPLayerInfo   `json:"udp_layer,omitempty"`
	ICMPLayer  *ICMPLayerInfo  `json:"icmp_layer,omitempty"`
	Mitre      MitreAttackInfo `json:"mitre_attack"`
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

func newCTIBaseEvent(eventType, srcIP string, srcPort int, dstIP string, dstPort int, pkt gopacket.Packet) *CTIEvent {
	hostname := *sensorID
	if hostname == "" {
		hostname, _ = os.Hostname()
		if hostname == "" {
			hostname = "synwatcher"
		}
	}

	return &CTIEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		SensorID:  hostname,
		EventType: eventType,
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
		IPLayer: extractIPInfo(pkt),
		Mitre: MitreAttackInfo{
			Tactic:    "Reconnaissance",
			Technique: "Network Service Discovery",
			ID:        "T1046",
		},
	}
}
