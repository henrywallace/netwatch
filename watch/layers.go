package watch

import (
	"net"
	"regexp"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
)

// TODO: Support returning more than just a view pair. Perhaps more generally a
// collection of views, and a set of relationships between them.
func handlePacket(
	log *logrus.Logger,
	packet gopacket.Packet,
) ViewPair {
	vp := ViewPair{
		Src:    NewView(),
		Dst:    NewView(),
		Layers: make(map[gopacket.LayerType]int),
	}
	for _, l := range packet.Layers() {
		vp.Layers[l.LayerType()]++
		switch l.LayerType() {
		case layers.LayerTypeARP:
			handleARP(&vp, l.(*layers.ARP))
		case layers.LayerTypeEthernet:
			handleEthernet(&vp, l.(*layers.Ethernet))
		case layers.LayerTypeTCP:
			handleTCP(&vp, l.(*layers.TCP))
		case layers.LayerTypeLCM:
			handleLCM(&vp, l.(*layers.LCM))
		case layers.LayerTypeIPv4:
			handleIPv4(&vp, l.(*layers.IPv4))
		case layers.LayerTypeIPv6:
			handleIPv6(&vp, l.(*layers.IPv6))
		case layers.LayerTypeUDP:
			handleUDP(&vp, l.(*layers.UDP))
		case layers.LayerTypeDNS:
			handleDNS(&vp, l.(*layers.DNS))
		case layers.LayerTypeDHCPv4:
			handleDHCPv4(&vp, l.(*layers.DHCPv4))
		case layers.LayerTypeDHCPv6:
			handleDHCPv6(&vp, l.(*layers.DHCPv6))
		default:
			log.Debugf("unhandled layer type: %v", l.LayerType())
		}
	}
	return vp
}

func handleEthernet(v *ViewPair, eth *layers.Ethernet) {
	mac := MAC(eth.SrcMAC.String())
	v.Src.MAC = &mac
}

func handleTCP(v *ViewPair, tcp *layers.TCP) {
	v.Src.TCP[int(tcp.SrcPort)] = true
	v.Dst.TCP[int(tcp.DstPort)] = true
}

func handleLCM(v *ViewPair, lcm *layers.LCM) {
}

func handleIPv4(v *ViewPair, ip4 *layers.IPv4) {
	v.Src.IPv4 = ip4.SrcIP
	v.Dst.IPv4 = ip4.DstIP
}

func handleIPv6(v *ViewPair, ip6 *layers.IPv6) {
	v.Src.IPv6 = ip6.SrcIP
	v.Dst.IPv6 = ip6.DstIP
}

func handleUDP(v *ViewPair, udp *layers.UDP) {
	v.Src.UDP[int(udp.SrcPort)] = true
	v.Dst.UDP[int(udp.DstPort)] = true
}

func handleDNS(v *ViewPair, dns *layers.DNS) {
}

func handleDHCPv4(v *ViewPair, dhcp *layers.DHCPv4) {
	if dhcp.Operation == layers.DHCPOpRequest {
		for _, opt := range dhcp.Options {
			switch opt.Type {
			case layers.DHCPOptHostname:
				v.Src.Hostname = string(opt.Data)
			case layers.DHCPOptClassID:
				// TODO
			case layers.DHCPOptClientID:
				// TODO
			}
		}
	}
}

var reControl = regexp.MustCompile(`^\p{Cc}+`)

func stripOptDHCPv6(s string) string {
	s = reControl.ReplaceAllString(s, "")
	s = strings.TrimSpace(s)
	return s
}

func handleDHCPv6(v *ViewPair, dhcp *layers.DHCPv6) {
	if dhcp.MsgType == layers.DHCPv6MsgTypeSolicit {
		for _, opt := range dhcp.Options {
			switch opt.Code {
			case layers.DHCPv6OptClientFQDN:
				v.Src.Hostname = stripOptDHCPv6(string(opt.Data))
			case layers.DHCPv6OptClientID:
				// TODO
			case layers.DHCPv6OptVendorClass:
				// TODO
			}
		}
	}
}

func handleARP(v *ViewPair, arp *layers.ARP) {
	// TODO: Check for change.
	srcMAC := MAC(net.HardwareAddr(arp.SourceHwAddress).String())
	dstMAC := MAC(net.HardwareAddr(arp.DstHwAddress).String())
	v.Src.MAC = &srcMAC
	v.Dst.MAC = &dstMAC

	addIP(&v.Src, net.IP(arp.SourceProtAddress))
	addIP(&v.Dst, net.IP(arp.DstProtAddress))
}
