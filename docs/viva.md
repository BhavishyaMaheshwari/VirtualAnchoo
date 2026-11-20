# Computer Networks viva notes

## What does a packet sniffer observe?

A sniffer asks the operating system for packets visible at an interface. It does not automatically see every packet on a switched network. A switch normally forwards unicast Ethernet traffic only to the relevant port. A mirror/SPAN port, a network tap, or capture inside an endpoint can provide other viewpoints. Promiscuous mode changes what a NIC accepts; it does not make a switch copy unrelated traffic onto that NIC.

VirtualAnchoo uses Scapy to capture and dissect packets. Capture and analysis are separate operations: live capture obtains bytes from an interface; offline analysis reads bytes already stored in a PCAP. Imported traffic has its original capture timestamps and must not be labelled as traffic currently crossing the operator's network.

## Ethernet frames and encapsulation

An Ethernet frame has destination and source MAC addresses and an EtherType identifying the next protocol. Typical EtherTypes are `0x0800` for IPv4, `0x86dd` for IPv6, and `0x0806` for ARP. A frame carries a network-layer packet, which may carry a transport segment or datagram, which may carry application data.

The protocol hierarchy is not guaranteed. ARP is carried directly in Ethernet and has no TCP/UDP port. Loopback and other link types may not use Ethernet at all. Truncated captures may omit bytes needed to decode a layer. Robust parsers check for a layer before reading its fields.

## IPv4 and IPv6

IP addresses identify network-layer endpoints. Routers forward packets between networks using routing tables. IPv4 TTL is decremented at each router; IPv6 uses Hop Limit for the same purpose. IPv4 can be fragmented, so a fragment may not contain transport headers. IPv6 extension headers also complicate dissection. IP alone does not guarantee reliable delivery, ordering, or application success.

A subnet prefix identifies the on-link address range. For example, `192.168.10.0/24` has a 24-bit network prefix. A host sends an off-subnet destination to its default gateway instead of resolving the destination's MAC locally.

## TCP

TCP provides a reliable ordered byte stream using sequence numbers, acknowledgements, retransmissions, flow control, and congestion control. A common connection begins with SYN, SYN-ACK, ACK. FIN supports graceful shutdown; RST aborts a connection. The advertised receive window is a flow-control signal, not a direct measurement of network bandwidth.

A retransmission inference based on repeated sequence ranges is heuristic. Duplicate captures, packet reordering, overlapping segments, sequence wraparound, offload, and missing packets can complicate it. VirtualAnchoo's flow counters are packet observations, not a full reconstruction of application sessions.

## UDP

UDP adds source and destination ports and a length/checksum to a datagram. It does not establish a connection or provide retransmission and ordering. Applications can implement these features themselves. DNS, DHCP, voice traffic, and QUIC are common UDP uses. UDP does not always mean unreliable application behavior; reliability depends on the application protocol.

## ICMP

ICMP communicates control and diagnostic information. Echo request/reply supports `ping`; destination-unreachable and time-exceeded messages explain some delivery failures. An ICMP echo success demonstrates reachability for ICMP at that moment, not that TCP or a particular application is allowed. Conversely, a failed ping can reflect filtering, a missing route, a stopped host, or another fault.

## DNS

DNS maps names to resource records such as A and AAAA addresses. A request carries a query name/type and transaction ID; a response carries flags, an outcome code, and potentially answers. Traditional DNS often uses UDP port 53, with TCP used in several cases. DNS over TLS/HTTPS encrypts the query exchange and cannot be decoded from ordinary plaintext DNS fields.

## ARP and neighbor discovery

ARP resolves an IPv4 address to a MAC address within a local broadcast domain. A request asks who owns an IP; a reply advertises the mapping. It does not cross routers as a broadcast. A captured ARP association is an observation, not authenticated ownership: ARP can be spoofed. IPv6 uses ICMPv6 Neighbor Discovery rather than ARP.

## VLANs and 802.1Q

A VLAN separates a switch into logical Layer 2 broadcast domains. Hosts in different VLANs do not share ordinary broadcasts, even when connected to the same physical switch.

An 802.1Q tag includes a 12-bit VLAN identifier, a 3-bit Priority Code Point (PCP), and a Drop Eligible Indicator (DEI). VLAN IDs 1–4094 are usable in the project; 0 represents priority-tagged traffic and 4095 is reserved. A trunk carries multiple VLANs using tags. An access port assigns ordinary untagged host traffic to one VLAN and usually removes the tag on egress to that host.

A capture on an access host may show no VLAN header even though VLAN separation is working. Capture on the trunk is the appropriate experiment for observing 802.1Q. Hardware offload can hide tags from some capture points on physical NICs.

## Broadcast domains, routing, and segmentation

VLAN membership is Layer 2 separation. IP subnetting is Layer 3 addressing. They are often aligned one-to-one, as in the example lab, but they are different concepts.

Communication between VLANs requires a Layer 3 path, such as a router with one tagged subinterface per VLAN. Hosts use their respective gateway addresses. Routing is disabled initially in the example lab so cross-VLAN traffic has no forwarding path. Enabling routing does not erase the Layer 2 VLAN boundaries: broadcasts remain separated.

Segmentation combines topology and policy to constrain communication. A VLAN alone does not express which applications a routed peer may use. An ACL or firewall applies criteria such as source/destination subnet, protocol, port, action, and ordering.

## Stateful firewall rules

A stateful firewall tracks connections. Allowing an Engineering-initiated connection to Administration normally requires its return traffic to be accepted too. An established/related rule can provide this without broadly allowing new Administration-initiated connections in the opposite direction. Policy changes may not terminate already tracked connections; use new connections when validating new policy.

Rule order and default policy matter. A broad earlier rule may make a later specific rule ineffective. “Finance cannot initiate a connection to Engineering” differs from “no packet may ever travel from Finance to Engineering”: response packets for a separately allowed connection are a different policy case.

## Flows and statistics

A conventional unidirectional flow key is source IP, destination IP, source port, destination port, and transport protocol. A bidirectional tracker canonicalizes the two endpoints so request and response share an aggregate, while keeping directional counts when available. VLAN context is relevant where overlapping address spaces exist.

Packets per second counts observed packets in a time interval. Bytes per second sums observed captured sizes in that interval. Average packet size is total bytes divided by packet count. Session-average rate is not the same as a one-second instantaneous rate. Capture loss and truncated packet snapshots can cause observation-based totals to differ from wire traffic.

Packet bytes, IP total length, and application payload length are different quantities. Link overhead, preamble, inter-frame gap, and NIC offloads may be absent from a capture. A bandwidth chart should be read according to the exact capture-length and time-bin definition documented by the application.

## Encryption and limitations

HTTPS is HTTP over TLS. TLS encrypts application content and authenticates peers according to its configuration. A passive capture may reveal endpoints, ports, lengths, timing, and parts of a handshake; it does not reveal decrypted HTTP bodies without suitable keys and a supported decryption workflow. Port 443 is only a heuristic indicator of TLS/HTTPS, and traffic on another port may also be encrypted.

VirtualAnchoo is a teaching and diagnostic tool. It does not guarantee security, identify every application, authenticate MAC/IP ownership, or replace a production network monitoring platform.
