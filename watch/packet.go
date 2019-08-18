package watch

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

func init() {
	customFormatter := new(logrus.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	customFormatter.FullTimestamp = true
	logrus.SetFormatter(customFormatter)
}

// Host is a tracked entity.
type Host struct {
	FirstSeen time.Time
	LastSeen  time.Time

	MAC  MAC
	IPv4 net.IP
	IPv6 net.IP

	expire *time.Timer
}

func (h Host) String() string {
	return fmt.Sprintf(
		"%s/%s",
		h.MAC,
		h.IPv4,
		// TODO: hostname
	)
}

// NewHost returns a new Host whose first and last seen timestamps are set
// to now.
func NewHost(
	mac MAC,
	expire func(),
) Host {
	return Host{
		MAC:       mac,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		expire:    time.AfterFunc(defaultTTL, expire),
	}
}

// Touch updates the last seen time of this Host.
func (h *Host) Touch() {
	h.LastSeen = time.Now()
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

type View struct {
	MAC  *MAC
	IPv4 net.IP
	IPv6 net.IP
	Port int
}

// DiffPackets sends new diffs for hosts given a stream of packets.
//
// A map of hosts known will be updated with the diffs.
func DiffPackets(
	events chan<- Event,
	diffs chan<- Diff,
	hosts map[MAC]Host,
	packets <-chan gopacket.Packet,
) {
	defer close(diffs)

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
			log.WithError(err).Error("failed to decode packet")
			continue
		}
		var v View
		for _, ty := range decodedLayers {
			switch ty {
			case layers.LayerTypeEthernet:
				handleEthernet(&v, hosts, avail.eth)
			case layers.LayerTypeTCP:
				handleTCP(&v, hosts, avail.tcp)
			case layers.LayerTypeLCM:
			case layers.LayerTypeIPv4:
				handleIP(&v, hosts, avail.ip4)
			case layers.LayerTypeIPv6:
			case layers.LayerTypeUDP:
			case layers.LayerTypeDNS:
				handleDNS(&v, hosts, avail.dns)
			case layers.LayerTypeARP:
				handleARP(&v, hosts, avail.arp)
			case layers.LayerTypePFLog:
			case layers.LayerTypeLoopback:
			case layers.LayerTypeDot11InformationElement:
			case layers.LayerTypeLLC:
			case layers.LayerTypeTLS:
			case layers.LayerTypeDHCPv4:
			default:
				log.Debugf("unhanded layer type: %#v", ty)
			}
		}
		d, ok := diffView(events, &v, hosts)
		if ok {
			diffs <- d
		}
	}
}

// Consider using a graph database for storing all directed interactions
// between the hosts.

// Diff represents a different between the previous and current host.
type Diff struct {
	New bool
	A   Host
	B   Host
}

var EmptyDiff = Diff{}

// InvalidHost can be used to represent a newly found Host, where there is only
// a non-empty Curr.
var InvalidHost = Host{}

func diffView(
	events chan<- Event,
	v *View,
	hosts map[MAC]Host,
) (Diff, bool) {
	if v.MAC == nil {
		// TODO: Try harder
		return EmptyDiff, false
	}

	prev, ok := hosts[*v.MAC]
	var curr Host
	if ok {
		curr = prev
		curr.Touch()
		if v.IPv4 != nil {
			curr.IPv4 = v.IPv4
		}
		if v.IPv6 != nil {
			curr.IPv6 = v.IPv6
		}
	} else {
		curr = NewHost(*v.MAC, func() {
			events <- Event{
				Kind: HostDrop,
				// TODO: Actually reference whatever this new
				// host is.
				Body: EventHostDrop{prev},
			}
		})
		if v.IPv4 != nil {
			curr.IPv4 = v.IPv4
		}
		if v.IPv6 != nil {
			curr.IPv6 = v.IPv6
		}
		hosts[*v.MAC] = curr
	}
	d := Diff{
		A: prev,
		B: curr,
	}
	if !ok {
		d.New = true
	}
	return d, true
}

func handleEthernet(
	v *View,
	hosts map[MAC]Host,
	eth layers.Ethernet,
) {
	mac := MAC(eth.SrcMAC.String())
	v.MAC = &mac
	// spew.Dump(dns)
}

func handleTCP(
	v *View,
	hosts map[MAC]Host,
	tcp layers.TCP,
) {
	v.Port = int(tcp.SrcPort)
}

func handleIP(
	v *View,
	hosts map[MAC]Host,
	ipv4 layers.IPv4,
) {
	v.IPv4 = ipv4.SrcIP
}

func handleDNS(
	v *View,
	hosts map[MAC]Host,
	dns layers.DNS,
) {
	// spew.Dump(dns)
}

func handleARP(
	v *View,
	hosts map[MAC]Host,
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
