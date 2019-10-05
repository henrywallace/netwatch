package watch

import (
	"net"

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

func handleARP(v *ViewPair, arp *layers.ARP) {
	// TODO: Check for change.
	srcMAC := MAC(net.HardwareAddr(arp.SourceHwAddress).String())
	dstMAC := MAC(net.HardwareAddr(arp.DstHwAddress).String())
	v.Src.MAC = &srcMAC
	v.Dst.MAC = &dstMAC

	addIP(&v.Src, net.IP(arp.SourceProtAddress))
	addIP(&v.Dst, net.IP(arp.DstProtAddress))
}
