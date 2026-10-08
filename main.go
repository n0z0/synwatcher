package main

import (
	"flag"
	"fmt"
	"log"
	"runtime"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/n0z0/cachedb/cdc"
)

// version diisi saat build release: -ldflags "-X main.version=v1.2.3"
var version = "dev"

var showVersion = flag.Bool("version", false, "Tampilkan versi lalu keluar")

func main() {
	flag.Parse()
	if *showVersion {
		fmt.Println("synwatcher", version)
		return
	}
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("[*] synwatcher %s", version)

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
	loadLocalIPsFor(dev)
	log.Printf("[*] Local IPs on %s: %v", dev, keys(localIPs))

	handle, err := pcap.OpenLive(dev, int32(*snaplen), *promisc, *timeout)
	if err != nil {
		log.Fatalf("OpenLive gagal di %s: %v", dev, err)
	}
	defer handle.Close()

	// Inisialisasi CTI Logger
	if *ctiLogFile != "" {
		cti, err := initCTILogger(*ctiLogFile)
		if err != nil {
			log.Printf("[WARN] Gagal membuat file log CTI: %v", err)
		} else {
			defer cti.Close()
			log.Printf("[*] CTI Logging aktif -> %s", *ctiLogFile)
		}
	}

	if err := handle.SetBPFFilter(*bpf); err != nil {
		log.Fatalf("SetBPFFilter gagal: %v", err)
	}
	log.Printf("[*] Sniffing on: %s", dev)
	log.Printf("[*] BPF: %s", *bpf)

	// Buka DB
	// Connect to cache server
	db, conn, err := cdc.Connect(cacheDB)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	workerCount := runtime.NumCPU() * 2
	if workerCount < 4 {
		workerCount = 4
	}
	packetChan := make(chan gopacket.Packet, 4096)
	var wg sync.WaitGroup

	log.Printf("[*] Worker pool aktif: %d goroutines (Buffer: 4096 paket)", workerCount)
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for pkt := range packetChan {
				handlePacket(pkt, db)
			}
		}(i)
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for pkt := range src.Packets() {
		select {
		case packetChan <- pkt:
		default:
			// Buffer penuh pada lalu lintas ekstrem, drop untuk mencegah stalling loop pcap
		}
	}

	close(packetChan)
	wg.Wait()
}
