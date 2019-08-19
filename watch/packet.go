package watch

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/henrywallace/homelab/go/netwatch/util"
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

	TCP map[int]*Port
	UDP map[int]*Port
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
		TCP:              make(map[int]*Port),
		UDP:              make(map[int]*Port),
	}
	h.expire = time.AfterFunc(ttlHost, func() {
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
	h.expire.Reset(ttlHost)
}

func (h Host) ActiveTCP() []*Port {
	var active []*Port
	for _, p := range h.TCP {
		if p.Active {
			active = append(active, p)
		}
	}
	return active
}

func (h Host) ActiveUDP() []*Port {
	var active []*Port
	for _, p := range h.UDP {
		if p.Active {
			active = append(active, p)
		}
	}
	return active
}

type Port struct {
	Active           bool
	FirstSeen        time.Time
	FirstSeenEpisode time.Time
	LastSeen         time.Time

	expire *time.Timer

	Num   int
	isTCP bool
}

// Touch updates the last seen time of this Host.
func (p *Port) Touch() {
	now := time.Now()
	if !p.Active {
		p.FirstSeenEpisode = now
	}
	p.Active = true
	p.LastSeen = now
	p.expire.Reset(ttlHost)
}

func NewPortTCP(
	num int,
	expire func(p *Port),
) *Port {
	now := time.Now()
	p := Port{
		FirstSeen:        now,
		FirstSeenEpisode: now,
		LastSeen:         now,
		Num:              num,
		isTCP:            true,
	}
	p.expire = time.AfterFunc(ttlPort, func() {
		p.Active = false
		expire(&p)
	})
	return &p
}

func NewPortUDP(
	num int,
	expire func(p *Port),
) *Port {
	now := time.Now()
	p := Port{
		FirstSeen:        now,
		FirstSeenEpisode: now,
		LastSeen:         now,
		Num:              num,
		isTCP:            false,
	}
	p.expire = time.AfterFunc(ttlHost, func() {
		p.Active = false
		expire(&p)
	})
	return &p
}

func (p Port) String() string {
	var suffix string
	if p.isTCP {
		suffix = "tcp"
	} else {
		suffix = "udp"
	}

	return fmt.Sprintf("%d/%s", p.Num, suffix)

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
	TCP  map[int]bool
	UDP  map[int]bool
}

func NewView() View {
	return View{
		TCP: make(map[int]bool),
		UDP: make(map[int]bool),
	}
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
	decodedLayers := make([]gopacket.LayerType, 0, 32)
	for p := range packets {
		if err := parser.DecodeLayers(
			p.Data(),
			&decodedLayers,
		); err != nil {
			w.log.WithError(err).Debug("failed to decode packet")
			continue
		}
		v := ViewPair{Src: NewView(), Dst: NewView()}
		for _, ty := range decodedLayers {
			switch ty {
			case layers.LayerTypeEthernet:
				handleEthernet(&v, avail.eth)
			case layers.LayerTypeTCP:
				handleTCP(&v, avail.tcp)
			case layers.LayerTypeLCM:
				handleLCM(&v, avail.lcm)
			case layers.LayerTypeIPv4:
				handleIPv4(&v, avail.ip4)
			case layers.LayerTypeIPv6:
				handleIPv6(&v, avail.ip6)
			case layers.LayerTypeUDP:
				handleUDP(&v, avail.udp)
			case layers.LayerTypeDNS:
				handleDNS(&v, avail.dns)
			case layers.LayerTypeARP:
				handleARP(&v, avail.arp)
			default:
				w.log.Debugf("unhandled layer type: %v", ty)
			}
		}
		w.updateHosts(v, hosts)
	}
}

// // Consider using a graph database for storing all directed interactions
// // between the hosts.

// InvalidHost can be used to represent a newly found Host, where there is only
// a non-empty Curr.
var InvalidHost = Host{}

func (w *Watcher) updateHosts(
	v ViewPair,
	hosts map[MAC]*Host,
) {
	w.updateHostWithView(hosts, v.Src)
	// TODO: There are some bugs here with the double updating, with
	// duplicate new hosts being detected.
	//
	// w.updateHostWithView(v.Dst, hosts)
}

func (w *Watcher) updateHostWithView(
	hosts map[MAC]*Host,
	v View,
) {
	// TODO: Relieve this handicap, which is an artifact of the hosts
	// map[MAC]*Host datastructure, which should be made more
	// relational.
	if v.MAC == nil {
		return
	}

	prev := findHost(v, hosts)
	var curr *Host
	if prev == nil {
		curr = NewHost(*v.MAC, func(h *Host) {
			up := time.Since(h.FirstSeenEpisode)
			w.events <- Event{
				Kind: HostDrop,
				Body: EventHostDrop{h, up},
			}
		})
		hosts[*v.MAC] = curr
		w.events <- Event{
			Kind: HostNew,
			Body: EventHostNew{curr},
		}
	} else {
		if time.Since(prev.LastSeen) > ttlHost {
			down := time.Since(prev.LastSeen)
			w.events <- Event{
				Kind: HostReturn,
				Body: EventHostReturn{prev, down},
			}
		}
		curr = prev
		curr.Touch()
		w.log.Debugf("touch host %s", curr)
	}

	// TODO: Display differences, which may be a job for
	// findHost.
	if v.IPv4 != nil && !v.IPv4.Equal(net.IPv4zero) {
		if !curr.IPv4.Equal(v.IPv4) {
			w.log.Debugf("host %s changed ips %s -> %s", curr, curr.IPv4, v.IPv4)
		}
		curr.IPv4 = v.IPv4
	}
	if v.IPv6 != nil && !v.IPv6.Equal(net.IPv6zero) {
		if !curr.IPv6.Equal(v.IPv6) {
			w.log.Debugf("host %s changed ips %s -> %s", curr, curr.IPv6, v.IPv6)
		}
		curr.IPv6 = v.IPv6
	}

	w.updatePortsWithView(curr, v)
}

// TODO: Only update dst ports whenever the dst host is active.
func (w *Watcher) updatePortsWithView(h *Host, v View) {
	for num := range v.TCP {
		prev, ok := h.TCP[num]
		var curr *Port
		if !ok {
			curr = NewPortTCP(num, func(p *Port) {
				up := time.Since(p.FirstSeenEpisode)
				w.events <- Event{
					Kind: PortDrop,
					Body: EventPortDrop{p, up, h},
				}
			})
			h.TCP[num] = curr
			w.events <- Event{
				Kind: PortNew,
				Body: EventPortNew{curr, h},
			}
		} else {
			if time.Since(prev.LastSeen) > ttlHost {
				down := time.Since(prev.LastSeen)
				w.events <- Event{
					Kind: HostReturn,
					Body: EventPortReturn{prev, down, h},
				}
			}
			curr = prev
			curr.Touch()
			w.log.Debugf("touch host %s", curr)
		}

	}
	for num := range v.UDP {
		prev, ok := h.UDP[num]
		var curr *Port
		if !ok {
			curr = NewPortUDP(num, func(p *Port) {
				up := time.Since(p.FirstSeenEpisode)
				w.events <- Event{
					Kind: PortDrop,
					Body: EventPortDrop{p, up, h},
				}
			})
			h.UDP[num] = curr
			w.events <- Event{
				Kind: PortNew,
				Body: EventPortNew{curr, h},
			}
		} else {
			if time.Since(prev.LastSeen) > ttlHost {
				down := time.Since(prev.LastSeen)
				w.events <- Event{
					Kind: PortReturn,
					Body: EventPortReturn{prev, down, h},
				}
			}
			curr = prev
			curr.Touch()
			w.log.Debugf("touch host %s", curr)
		}

	}
}

// findHost tries to find a host associated with the given view.
//
// TODO: Use more sophisticated host association techniques, such as using
// previously seen ip address.
func findHost(v View, hosts map[MAC]*Host) *Host {
	if v.MAC == nil {
		return nil
	}
	return hosts[*v.MAC]
}

func handleEthernet(v *ViewPair, eth layers.Ethernet) {
	mac := MAC(eth.SrcMAC.String())
	v.Src.MAC = &mac
}

func handleTCP(v *ViewPair, tcp layers.TCP) {
	v.Src.TCP[int(tcp.SrcPort)] = true
	v.Dst.TCP[int(tcp.DstPort)] = true
}

func handleLCM(v *ViewPair, lcm layers.LCM) {
}

func handleIPv4(v *ViewPair, ip4 layers.IPv4) {
	v.Src.IPv4 = ip4.SrcIP
	v.Dst.IPv4 = ip4.DstIP
}

func handleIPv6(v *ViewPair, ip6 layers.IPv6) {
	v.Src.IPv6 = ip6.SrcIP
	v.Dst.IPv6 = ip6.DstIP
}

func handleUDP(v *ViewPair, udp layers.UDP) {
	v.Src.UDP[int(udp.SrcPort)] = true
	v.Dst.UDP[int(udp.DstPort)] = true
}

func handleDNS(v *ViewPair, dns layers.DNS) {
	// spew.Dump(dns)
}

func handleARP(v *ViewPair, arp layers.ARP) {
	// TODO: Check for change.
	srcMAC := MAC(net.HardwareAddr(arp.SourceHwAddress).String())
	dstMAC := MAC(net.HardwareAddr(arp.DstHwAddress).String())
	v.Src.MAC = &srcMAC
	v.Dst.MAC = &dstMAC

	addIP(&v.Src, net.IP(arp.SourceProtAddress))
	addIP(&v.Dst, net.IP(arp.DstProtAddress))
}

func addIP(v *View, ip net.IP) {
	if len(ip) == net.IPv4len {
		v.IPv4 = ip
	} else if len(ip) == net.IPv6len {
		v.IPv6 = ip
	} else {
		util.NewLogger().Warnf("invalid ip len=%d: %#v", len(ip), ip)
	}
}