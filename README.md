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
- [x] Parse IP packets (version, TTL, protocol, IP addresses)
- [ ] Parse TCP segments (ports, flags, sequence numbers)
- [ ] Parse UDP datagrams
- [ ] Pretty print packet information

## Packet Layers

```
┌──────────────────────────────────────────────────┐
│ Ethernet Frame (First 14 bytes) [0-13]           │
│  - Destination MAC (6 bytes)                     │
│  - Source MAC (6 bytes)                          │
│  - EtherType (2 bytes)                           │
├──────────────────────────────────────────────────┤
│ IP Packet [next (Header Length * 4) bytes]       │────┐
│  - Version, Header Length                        │    │
│  - TTL, Protocol                                 │    │
│  - Source/Destination IP                         │    │
├──────────────────────────────────────────────────┤    │
│ TCP/UDP                                          │    │
│  - Source/Destination Port                       │    │
│  - Sequence/Ack numbers (TCP)                    │    │
│  - Flags (TCP)                                   │    │
├──────────────────────────────────────────────────┤    │
│ Application Data (HTTP, etc.)                    │    │
└──────────────────────────────────────────────────┘    │
                                                        │
                                                        ▼
IPv4 Header Structure (IP Packet):

  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┤
│Version│  IHL  │    TOS    │          Total Length             │  Bytes 0-3
├───────┴───────┴───────────┼───────────────────────────────────┤
│         Identification    │Flags│      Fragment Offset        │  Bytes 4-7
├───────────────────────────┼─────┴─────────────────────────────┤
│    TTL        │  Protocol │         Header Checksum           │  Bytes 8-11
├───────────────┴───────────┴───────────────────────────────────┤
│                       Source IP Address                       │  Bytes 12-15
├───────────────────────────────────────────────────────────────┤
│                    Destination IP Address                     │  Bytes 16-19
└───────────────────────────────────────────────────────────────┘
```

## Running

```bash
go mod tidy
sudo go run main.go
```

Note: `sudo` is required for raw packet capture permissions.
