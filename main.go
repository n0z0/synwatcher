package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/n0z0/cachedb/cdc"
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

	// Buka DB
	// Connect to cache server
	db, conn, err := cdc.Connect(cacheDB)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for pkt := range src.Packets() {
		handlePacket(pkt, db)
	}
}
