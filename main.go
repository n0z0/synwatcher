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
	bpf = flag.String("bpf", "(ip or ip6) and tcp and (tcp[13] & 0x02 != 0) and (tcp[13] & 0x10 == 0)", "BPF filter")
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
		printSYN(pkt, db)
	}
}

func printSYN(pkt gopacket.Packet, db *bbolt.DB) {
	net := pkt.NetworkLayer()
	tr := pkt.TransportLayer()

	if net == nil || tr == nil {
		return
	}
	tcp, _ := tr.(*layers.TCP)
	if tcp == nil {
		return
	}

	// Extra guard (selain BPF) kalau-kalau filter diubah
	if !(tcp.SYN && !tcp.ACK) {
		return
	}

	srcIP := net.NetworkFlow().Src().String()
	dstIP := net.NetworkFlow().Dst().String()

	// SKIP paket yang bersumber dari IP kita sendiri
	if _, ok := localIPs[srcIP]; ok {
		return
	}
	// skip loopback just in case
	if srcIP == "127.0.0.1" || srcIP == "::1" {
		return
	}

	// ringkas info flags
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
		srcIP, tcp.SrcPort, dstIP, tcp.DstPort, strings.Join(flags, "|"),
		tcp.Window, time.Now().Format(time.RFC3339Nano))

	// SET / PUT
	hash, err := bcrypt.GenerateFromPassword([]byte(tcp.DstPort.String()), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}

	err = db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bktName)
		return b.Put([]byte(srcIP), []byte(hash))
	})
	if err != nil {
		log.Fatal(err)
	}
}
