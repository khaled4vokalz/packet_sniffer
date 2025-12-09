package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type EthernetFrame struct {
	DestinationMAC string
	SourceMAC      string
	EtherType      uint16
}

func printDevices(devices []pcap.Interface) {
	fmt.Println("Available network interfaces:")
	fmt.Println("==============================")
	for i, device := range devices {
		fmt.Printf("%d. %s\n", i+1, device.Name)
		if device.Description != "" {
			fmt.Printf("   Description: %s\n", device.Description)
		}
		for _, address := range device.Addresses {
			fmt.Printf("   IP: %s\n", address.IP)
		}
		fmt.Println()
	}
}


func main() {
	// Step-1:: List all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal("Error finding devices: ", err)
	}
	printDevices(devices)

	// Step-2:: Capture packets on the first device (if available)
	var deviceName string
	for _, device := range devices {
		if len(device.Addresses) > 0 {
			deviceName = device.Name
			break
		}
	}
	if deviceName == "" {
		log.Fatal("No suitable device found for capturing packets.")
	}
	fmt.Printf("Capturing packets on device: %s\n", deviceName)
	fmt.Println("==============================")

	// Open the device for packet capture
	// Parameters:
	// - device: the name of the device
	// - snapshot length: (max bytes to capture per packet)
	// - promiscuous mode: true to capture all packets
	// - timeout: pcap.BlockForever to wait indefinitely
	handle, err := pcap.OpenLive(deviceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("Error opening device: ", err)
	}
	defer handle.Close()

	// Step-3:: Create a packet source to read packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Println("Listening for packets... (Press Ctrl+C to stop)")
	fmt.Println()

	packetCount := 0
	for packet := range packetSource.Packets() {
		packetCount++
		// fmt.Printf("Packet #%d:\n", packetCount)
		// fmt.Printf("Length: %d bytes\n", len(packet.Data()))
		// fmt.Printf("Raw bytes (first 64): %x\n", truncateBytes(packet.Data(), 0, 64))
		// fmt.Println()
		if len(packet.Data()) >= 14 {
			ethernetFrame, err := parseEthernet(truncateBytes(packet.Data(), 0, 14))
			if err != nil {
				fmt.Println("Error parsing Ethernet frame:", err)
				continue
			}
			fmt.Printf("Packet #%d:\n", packetCount)
		  fmt.Printf("Raw bytes (first 64): %x\n", truncateBytes(packet.Data(), 0, 64))
			fmt.Printf("Destination MAC: %s\n", ethernetFrame.DestinationMAC)
			fmt.Printf("Source MAC: %s\n", ethernetFrame.SourceMAC)
			fmt.Printf("EtherType: 0x%04x\n", ethernetFrame.EtherType)
			fmt.Println()
		}

		// Stop after capturing 10 packets for demonstration purposes
		if packetCount >= 10 {
			fmt.Println("Captured 10 packets, stopping.")
			break
		}
	}
}

func parseEthernet(data []byte) (*EthernetFrame, error) {
	if len(data) < 14 {
		return nil, fmt.Errorf("data too short to be an Ethernet frame")
	}
	frame := &EthernetFrame{
		DestinationMAC: fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", data[0], data[1], data[2], data[3], data[4], data[5]),
		SourceMAC:      fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", data[6], data[7], data[8], data[9], data[10], data[11]),
		EtherType:      uint16(data[12])<<8 | uint16(data[13]),  // Big-endian conversion
		// EtherType:      binary.BigEndian.Uint16(data[12:14]), // Alternative using encoding/binary
	}
	// frame := &EthernetFrame{
	// 	DestinationMAC: fmt.Printf("%02x:%02x:%02x:%02x:%02x:%02x", data[:6]),
	// 	SourceMAC:      data[6:12],
	// 	EtherType:      data[12:14],
	// 	Payload:        data[14:],
	// }
	return frame, nil
}

func truncateBytes(data []byte, start int, end int) []byte {
	if len(data) > end {
		return data[start:end]
	}
	return data
}
