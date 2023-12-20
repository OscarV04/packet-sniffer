package main

import (
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var totalUDP int64 = 0
var totalTCP int64 = 0
var timeValue int64 = 30

func main() {

	devicesOnNetwork, err := pcap.FindAllDevs()
	checkError(err)

	fmt.Print("LOOKING AT WHAT DEVICES ARE AVAILABLE ON THE NETWORK")
	for _, device := range devicesOnNetwork {
		fmt.Printf("Device Name: %s\n", device.Name)
		fmt.Printf("Device Description: %s\n", device.Description)
		fmt.Printf("Device Flags: %d\n", device.Flags)
		for _, iaddress := range device.Addresses {
			fmt.Printf("\tInterfact IP: %s\n", iaddress.IP)
			fmt.Printf("\tInterface NetMask: %s\n", iaddress.Netmask)
		}
	}

	//properties for the pcap.OpenLive
	const (
		iface string = "enp0s3"

		snaplen int32 = 65536

		promisc bool = false

		timeoutT = 30
	)

	fmt.Print("START")
	defer fmt.Print("END")

	//Opening Device
	handle, err := pcap.OpenLive(iface, snaplen, promisc, timeoutT)
	checkError(err)

	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	//starting timer
	go funkytown()

	//printing the size of each packet and summing them up
	for packet := range packetSource.Packets() {
		fmt.Printf("Bytes : %d\n", getTotalLength(packet))
	}
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error %s", err.Error())
		os.Exit(1)
	}
}

// timer subroutine
func funkytown() {
	timer := time.NewTimer(time.Duration(timeValue) * time.Second)

	<-timer.C
	fmt.Println("END OF CAPTURE")

	//printing out the results of the capture
	var udpsec float64 = float64(totalUDP / timeValue)
	var tcpsec float64 = float64(totalTCP / timeValue)
	fmt.Printf("%f UDP Bytes/Second\n", udpsec)
	fmt.Printf("%f TCP Bytes/Second\n", tcpsec)
	os.Exit(0)
}

func getTotalLength(packet gopacket.Packet) uint16 {

	//summing and printing if UDP packet
	var total_len uint16
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		total_len = udp.Length
		fmt.Print("UDP PACKET: ")
		totalUDP += int64(udp.Length)
	}

	//summing and printing if TCP packet
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		total_len = uint16(len(tcp.Payload))
		fmt.Print("TCP PACKET: ")
		totalTCP += int64(len(tcp.Payload))
	}

	return total_len
}
