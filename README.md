# Packet Sniffer

A learning project to understand networking from the ground up by building a packet sniffer in Go.

## Learning Goals

- Understand how network packets are structured at each layer
- Learn to parse raw bytes into meaningful protocol data
- Build knowledge foundation for eventually creating a web server from scratch

## Progress

- [x] Set up Go project with gopacket/pcap
- [x] Capture raw packets from network interface
- [x] Parse Ethernet frames (MAC addresses, EtherType)
- [ ] Parse IP packets (version, TTL, protocol, IP addresses)
- [ ] Parse TCP segments (ports, flags, sequence numbers)
- [ ] Parse UDP datagrams
- [ ] Pretty print packet information

## Packet Layers

```
┌─────────────────────────────────────┐
│ Ethernet Frame                      │
│  - Destination MAC (6 bytes)        │
│  - Source MAC (6 bytes)             │
│  - EtherType (2 bytes)              │
├─────────────────────────────────────┤
│ IP Packet                           │
│  - Version, Header Length           │
│  - TTL, Protocol                    │
│  - Source/Destination IP            │
├─────────────────────────────────────┤
│ TCP/UDP                             │
│  - Source/Destination Port          │
│  - Sequence/Ack numbers (TCP)       │
│  - Flags (TCP)                      │
├─────────────────────────────────────┤
│ Application Data (HTTP, etc.)       │
└─────────────────────────────────────┘
```

## Running

```bash
go mod tidy
sudo go run main.go
```

Note: `sudo` is required for raw packet capture permissions.
