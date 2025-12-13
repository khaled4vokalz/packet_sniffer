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

type IPPacket struct {
	Version        uint8
	IHL            uint8 // Internet Header Length
	TTL            uint8 // Time To Live
	Protocol       IPProtocol
	SourceIP       string
	DestinationIP  string
}

type UDPSegment struct {
	SourcePort      uint16
	DestinationPort uint16
	Length          uint16
	Checksum        uint16
}

type TCPSegment struct {
	SourcePort      uint16
	DestinationPort uint16
	SequenceNumber  uint32
	AckNumber       uint32
	Flags           uint16 // e.g., SYN, ACK, SYN-ACK, FIN
}

type IPProtocol uint8 
const (
	IPProtocolICMP IPProtocol = 1
	IPProtocolTCP  IPProtocol = 6
	IPProtocolUDP  IPProtocol = 17
)

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

		if len(packet.Data()) < 14 {
			continue
		}

		ethernetFrame, err := parseEthernet(getEthernetHeaderSlice(packet.Data()))
		if err != nil {
			fmt.Println("Error parsing Ethernet frame:", err)
			continue
		}

		fmt.Printf("Packet #%d:\n", packetCount)
		fmt.Printf("Destination MAC: %s\n", ethernetFrame.DestinationMAC)
		fmt.Printf("Source MAC: %s\n", ethernetFrame.SourceMAC)
		fmt.Printf("EtherType: 0x%04x\n", ethernetFrame.EtherType)
		fmt.Println()

		if !isIPV4(ethernetFrame.EtherType) {
			continue
		}

		ipPacket, err := parseIP(getIPHeaderSlice(packet.Data()))
		if err != nil {
			fmt.Println("Error parsing IP packet:", err)
			continue
		}

		fmt.Printf("  IP Version: %d\n", ipPacket.Version)
		fmt.Printf("  IHL: %d\n", ipPacket.IHL)
		fmt.Printf("  TTL: %d\n", ipPacket.TTL)
		fmt.Printf("  Protocol: %s (%d)\n", getIPProtocolName(ipPacket.Protocol), ipPacket.Protocol)
		fmt.Printf("  Source IP: %s\n", ipPacket.SourceIP)
		fmt.Printf("  Destination IP: %s\n", ipPacket.DestinationIP)
		fmt.Println()

		tcp_udp_slice := getProtocolHeaderSlice(packet.Data(), int(ipPacket.IHL))
		if ipPacket.Protocol == IPProtocolTCP {
			tcpSegment, err := parseTCP(tcp_udp_slice)
			if err != nil {
				fmt.Println("Error parsing TCP segment:", err)
				continue
			}
			fmt.Printf("    TCP Source Port: %d\n", tcpSegment.SourcePort)
			fmt.Printf("    TCP Destination Port: %d\n", tcpSegment.DestinationPort)
			fmt.Printf("    TCP Sequence Number: %d\n", tcpSegment.SequenceNumber)
			fmt.Printf("    TCP Acknowledgment Number: %d\n", tcpSegment.AckNumber)
			fmt.Printf("    TCP Flags: %s\n", getTCPFlagNames(tcpSegment.Flags))
			fmt.Println()
		} else if ipPacket.Protocol == IPProtocolUDP {
			udpSegment, err := parseUDP(tcp_udp_slice)
			if err != nil {
				fmt.Println("Error parsing UDP segment:", err)
				continue
			}
			fmt.Printf("    UDP Source Port: %d\n", udpSegment.SourcePort)
			fmt.Printf("    UDP Destination Port: %d\n", udpSegment.DestinationPort)
			fmt.Printf("    UDP Length: %d\n", udpSegment.Length)
			fmt.Println()
		} else {
			fmt.Println("    Unsupported IP protocol, skipping TCP/UDP parsing.")
			fmt.Println()
		}

		// Stop after capturing 10 packets for demonstration purposes
		if packetCount >= 10 {
			fmt.Println("Captured 10 packets, stopping.")
			break
		}
	}
}

func isIPV4(etherType uint16) bool {
	return etherType == 0x0800
}

// first 14 bytes are Ethernet header
func getEthernetHeaderSlice(data []byte) []byte {
	return sliceBytes(data, 0, 14)
}

// bytes after first 14 bytes are IP header and payload
func getIPHeaderSlice(data []byte) []byte {
	return sliceBytes(data, 14, len(data))
}

// bytes after first 14 + ipHeaderLength*4 bytes are TCP/UDP header and payload
func getProtocolHeaderSlice(data []byte, ipHeaderLength int) []byte {
	return sliceBytes(data, 14+ipHeaderLength*4, len(data))
}

func parseTCP(data []byte) (*TCPSegment, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("data too short to be a TCP segment")
	}
	// ports -> 2 bytes (each, thus bit shifted by 8,0)
	// sequence/ack number -> 4 bytes (thus bit sfhifted by 24,16,8,0)
	// flags -> 2 bytes (data offset + reserved + flags)
	segment := &TCPSegment{
		SourcePort:      uint16(data[0])<<8 | uint16(data[1]),
		DestinationPort: uint16(data[2])<<8 | uint16(data[3]),
		SequenceNumber:  uint32(data[4])<<24 | uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7]),
		AckNumber:       uint32(data[8])<<24 | uint32(data[9])<<16 | uint32(data[10])<<8 | uint32(data[11]),
		Flags:           uint16(data[13]), // skipping the NS (nonce sum) flag for now
	}
	return segment, nil
}

func parseUDP(data []byte) (*UDPSegment, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("data too short to be a UDP segment")
	}

	// we need to shift the bits here as the resulting data should be 16 bits
	// without shifting, we would get incorrect 8 bit values
	segment := &UDPSegment{
		SourcePort:      uint16(data[0])<<8 | uint16(data[1]),
		DestinationPort: uint16(data[2])<<8 | uint16(data[3]),
		Length:          uint16(data[4])<<8 | uint16(data[5]),
		Checksum:        uint16(data[6])<<8 | uint16(data[7]),
	}
	return segment, nil
}

func parseIP(data []byte) (*IPPacket, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("data too short to be an IP packet")
	}
	packet := &IPPacket{
		Version:       data[0] >> 4,
		IHL:           data[0] & 0x0F,
		TTL:           data[8],
		Protocol:      parseIPProtocol(data[9]),
		SourceIP:      fmt.Sprintf("%d.%d.%d.%d", data[12], data[13], data[14], data[15]),
		DestinationIP: fmt.Sprintf("%d.%d.%d.%d", data[16], data[17], data[18], data[19]),
	}
	return packet, nil
}

func parseIPProtocol(proto byte) IPProtocol {
	return IPProtocol(proto)
}

func getIPProtocolName(proto IPProtocol) string {
	switch proto {
	case IPProtocolICMP:
		return "ICMP"
	case IPProtocolTCP:
		return "TCP"
	case IPProtocolUDP:
		return "UDP"
	default:
		return "Unknown"
	}
}

func getTCPFlagNames(flags uint16) []string {
	var names []string
	if flags&0x02 != 0 {
		names = append(names, "SYN")
	}
	if flags&0x10 != 0 {
		names = append(names, "ACK")
	}
	if flags&0x01 != 0 {
		names = append(names, "FIN")
	}
	if flags&0x04 != 0 {
		names = append(names, "RST")
	}
	if flags&0x08 != 0 {
		names = append(names, "PSH")
	}
	if flags&0x20 != 0 {
		names = append(names, "URG")
	}
	return names
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

func sliceBytes(data []byte, start int, end int) []byte {
	return data[start:end]
}
