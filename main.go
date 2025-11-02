package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"
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
	//boltdb
	dbPath      = "data.db"
	usersBucket = "users"             // username -> bcrypt(password)
	bktName     = []byte(usersBucket) // nama bucket
)

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	dev := *iface
	if dev == "" {
		// Auto-pick interface pertama yang up & punya alamat
		devs, err := pcap.FindAllDevs()
		println(devs)
		if err != nil || len(devs) == 0 {
			log.Fatalf("Tidak menemukan interface Npcap: %v", err)
		}
		for _, d := range devs {
			println(d.Name, ": ", d.Description, " addrs=", len(d.Addresses))
			if len(d.Addresses) > 0 {
				for _, addr := range d.Addresses {
					println(" - ", addr.IP.String())
				}
				dev = d.Name
				break
			}
		}
		if dev == "" {
			log.Fatalf("Tidak ada interface yang valid, gunakan -iface untuk memilih.")
		}
	}
	fmt.Printf("dev: %v\n", dev)

	// Kumpulkan IP lokal untuk device NPF yang dipilih
	loadLocalIPsFor(*iface)
	log.Printf("[*] Local IPs on %s: %v", *iface, keys(localIPs))

	handle, err := pcap.OpenLive(dev, int32(*snaplen), *promisc, *timeout)
	if err != nil {
		log.Fatalf("OpenLive gagal di %s: %v", dev, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(*bpf); err != nil {
		log.Fatalf("SetBPFFilter gagal: %v", err)
	}
	log.Printf("[*] Sniffing on: %s", dev)
	log.Printf("[*] BPF: %s", *bpf)

	// Buka DB (akan membuat file jika belum ada)
	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{
		Timeout:         2 * time.Second,       // tunggu lock file jika dipakai proses lain
		FreelistType:    bbolt.FreelistMapType, // freelist lebih efisien (disarankan)
		InitialMmapSize: 32 * 1024 * 1024,      // opsional: kurangi remap awal
	})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Buat bucket jika belum ada (WRITE TX)
	err = db.Update(func(tx *bbolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists(bktName)
		return e
	})
	if err != nil {
		log.Fatal(err)
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for pkt := range src.Packets() {
		handlePacket(pkt, db)
	}
}

func handlePacket(pkt gopacket.Packet, db *bbolt.DB) {
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

			// contoh aksi: simpan hash berdasarkan dstPort (seperti kode kamu)
			hash, err := bcrypt.GenerateFromPassword([]byte(tcp.DstPort.String()), bcrypt.DefaultCost)
			if err == nil {
				_ = db.Update(func(tx *bbolt.Tx) error {
					b := tx.Bucket(bktName)
					return b.Put([]byte(srcIP), []byte(hash))
				})
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
