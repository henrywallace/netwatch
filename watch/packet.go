package watch

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
)

// Host is a tracked entity.
type Host struct {
	Active           bool
	FirstSeen        time.Time
	FirstSeenEpisode time.Time
	LastSeen         time.Time

	MAC  MAC
	IPv4 net.IP
	IPv6 net.IP

	expire *time.Timer
}

func (h Host) String() string {
	return fmt.Sprintf(
		"Host(%s, %s)",
		h.MAC,
		h.IPv4,
		// TODO: hostname
	)
}

// NewHost returns a new Host whose first and last seen timestamps are set
// to now.
func NewHost(
	mac MAC,
	expire func(h *Host),
) *Host {
	now := time.Now()
	h := Host{
		MAC:              mac,
		FirstSeen:        now,
		FirstSeenEpisode: now,
		LastSeen:         now,
	}
	h.expire = time.AfterFunc(defaultTTL, func() {
		h.Active = false
		expire(&h)
	})
	return &h
}

// Touch updates the last seen time of this Host.
func (h *Host) Touch() {
	now := time.Now()
	if !h.Active {
		h.FirstSeenEpisode = now
	}
	h.Active = true
	h.LastSeen = now
	h.expire.Reset(defaultTTL)
}

// MAC is a string form of a net.HardwareAddr, so as to be used as keys in
// maps.
type MAC string

// $ rg 'layers\.(LayerType[A-Z]\w+)\b' -I -or '$1' | sort | uniq -c | sort -nr
// 19 LayerTypeEthernet
// 13 LayerTypeTCP
// 12 LayerTypeLCM
//  9 LayerTypeIPv4
//  5 LayerTypeIPv6
//  2 LayerTypeUDP
//  2 LayerTypeDNS
//  2 LayerTypeARP
//  1 LayerTypePFLog
//  1 LayerTypeLoopback
//  1 LayerTypeDot11InformationElement
//
// But hmm, there seem to be layers that don't satify the decoding
// interface as necessary below.
type availLayers struct {
	eth     layers.Ethernet
	tcp     layers.TCP
	lcm     layers.LCM
	ip4     layers.IPv4
	ip6     layers.IPv6
	udp     layers.UDP
	dns     layers.DNS
	arp     layers.ARP
	pf      layers.PFLog
	lo      layers.Loopback
	dot     layers.Dot11InformationElement
	llc     layers.LLC
	tls     layers.TLS
	dhcp4   layers.DHCPv4
	payload gopacket.Payload
}

// View represents a subset of information depicted about a Host, from a single
// packet. This can be used to be associate with a host, and update it's
// information.
type View struct {
	MAC  *MAC
	IPv4 net.IP
	IPv6 net.IP
	Port int
}

// ViewPair represents a pair of views that are communicating withing one
// packet, all determined from a single packet.
type ViewPair struct {
	Src View
	Dst View
}

// ScanPackets updates hosts with a given a stream of packets, and sends
// events to a channel based on their updated activity, when applicable.
//
// A map of hosts known will be updated with the diffs.
func (w *Watcher) ScanPackets(
	hosts map[MAC]*Host,
	packets <-chan gopacket.Packet,
) {
	defer close(w.events)

	var avail availLayers
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&avail.eth,
		&avail.tcp,
		&avail.lcm,
		&avail.ip4,
		&avail.ip6,
		&avail.udp,
		&avail.dns,
		&avail.arp,
		&avail.pf,
		&avail.lo,
		&avail.dot,
		&avail.llc,
		&avail.tls,
		&avail.dhcp4,
		&avail.payload,
	)
	decodedLayers := make([]gopacket.LayerType, 0, 10)
	for p := range packets {
		if err := parser.DecodeLayers(
			p.Data(),
			&decodedLayers,
		); err != nil {
			w.log.WithError(err).Debug("failed to decode packet")
			continue
		}
		var v View
		for _, ty := range decodedLayers {
			switch ty {
			case layers.LayerTypeEthernet:
				handleEthernet(&v, avail.eth)
			case layers.LayerTypeTCP:
				handleTCP(&v, avail.tcp)
			case layers.LayerTypeLCM:
			case layers.LayerTypeIPv4:
				handleIP(&v, avail.ip4)
			case layers.LayerTypeIPv6:
			case layers.LayerTypeUDP:
			case layers.LayerTypeDNS:
				handleDNS(&v, avail.dns)
			case layers.LayerTypeARP:
				handleARP(w.log, &v, avail.arp)
			case layers.LayerTypePFLog:
			case layers.LayerTypeLoopback:
			case layers.LayerTypeDot11InformationElement:
			case layers.LayerTypeLLC:
			case layers.LayerTypeTLS:
			case layers.LayerTypeDHCPv4:
			default:
				w.log.Debugf("unhanded layer type: %#v", ty)
			}
		}
		updateHosts(w.events, &v, hosts)
	}
}

// // Consider using a graph database for storing all directed interactions
// // between the hosts.

// InvalidHost can be used to represent a newly found Host, where there is only
// a non-empty Curr.
var InvalidHost = Host{}

func updateHosts(
	events chan<- Event,
	v *View,
	hosts map[MAC]*Host,
) bool {
	// TODO: Relieve this handicap, which is an artifact of the hosts
	// map[MAC]*Host datastructure, which should be made more
	// relational.
	if v.MAC == nil {
		return false
	}

	prev := findHost(v, hosts)
	var curr *Host
	if prev == nil {
		curr = NewHost(*v.MAC, func(h *Host) {
			up := time.Since(h.FirstSeenEpisode)
			events <- Event{
				Kind: HostDrop,
				Body: EventHostDrop{up, h},
			}
		})
		hosts[*v.MAC] = curr
		events <- Event{
			Kind: HostNew,
			Body: EventHostNew{curr},
		}
	} else {
		if time.Since(prev.LastSeen) > defaultTTL {
			down := time.Since(prev.LastSeen)
			events <- Event{
				Kind: HostReturn,
				Body: EventHostReturn{down, prev},
			}
		}
		curr = prev
		curr.Touch()
	}

	// TODO: Display differences, which may be a job for
	// findHost.
	if v.IPv4 != nil {
		curr.IPv4 = v.IPv4
	}
	if v.IPv6 != nil {
		curr.IPv6 = v.IPv6
	}

	return true
}

// findHost tries to find a host associated with the given view.
//
// TODO: Use more sophisticated host association techniques, such as using
// previously seen ip address.
func findHost(
	v *View,
	hosts map[MAC]*Host,
) *Host {
	if v.MAC == nil {
		return nil
	}
	return hosts[*v.MAC]
}

func handleEthernet(
	v *View,
	eth layers.Ethernet,
) {
	mac := MAC(eth.SrcMAC.String())
	v.MAC = &mac
	// spew.Dump(dns)
}

func handleTCP(
	v *View,
	tcp layers.TCP,
) {
	v.Port = int(tcp.SrcPort)
}

func handleIP(
	v *View,
	ipv4 layers.IPv4,
) {
	v.IPv4 = ipv4.SrcIP
}

func handleDNS(
	v *View,
	dns layers.DNS,
) {
	// spew.Dump(dns)
}

func handleARP(
	log *logrus.Logger,
	v *View,
	arp layers.ARP,
) {
	// TODO: Check for change.
	mac := MAC(net.HardwareAddr(arp.SourceHwAddress).String())
	v.MAC = &mac
	ip := net.IP(arp.SourceProtAddress)
	if len(ip) == net.IPv4len {
		v.IPv4 = ip
	} else if len(ip) == net.IPv6len {
		v.IPv6 = ip
	} else {
		log.Warnf("invalid ip len=%d: %#v", len(ip), ip)
	}
}
