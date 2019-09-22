package watch

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
)

// Hmm, it seems that there exist layers which don't satify the decoding
// interface as necessary in gopacket.NewDecodingLayerParser below.
type availLayers struct {
	arp     layers.ARP
	eth     layers.Ethernet
	tcp     layers.TCP
	lcm     layers.LCM
	ip4     layers.IPv4
	ip6     layers.IPv6
	udp     layers.UDP
	dns     layers.DNS
	pf      layers.PFLog
	lo      layers.Loopback
	dot     layers.Dot11InformationElement
	llc     layers.LLC
	tls     layers.TLS
	dhcp4   layers.DHCPv4
	payload gopacket.Payload
}

// TODO: Support returning more than just a view pair. Perhaps more generally a
// collection of views, and a set of relationships between them.
func handleDecoded(
	log *logrus.Logger,
	avail availLayers,
	decodedLayers []gopacket.LayerType,
) ViewPair {
	vp := ViewPair{Src: NewView(), Dst: NewView()}
	for _, ty := range decodedLayers {
		switch ty {
		case layers.LayerTypeARP:
			handleARP(&vp, avail.arp)
		case layers.LayerTypeEthernet:
			handleEthernet(&vp, avail.eth)
		case layers.LayerTypeTCP:
			handleTCP(&vp, avail.tcp)
		case layers.LayerTypeLCM:
			handleLCM(&vp, avail.lcm)
		case layers.LayerTypeIPv4:
			handleIPv4(&vp, avail.ip4)
		case layers.LayerTypeIPv6:
			handleIPv6(&vp, avail.ip6)
		case layers.LayerTypeUDP:
			handleUDP(&vp, avail.udp)
		case layers.LayerTypeDNS:
			handleDNS(&vp, avail.dns)
		default:
			log.Debugf("unhandled layer type: %v", ty)
		}
	}
	return vp
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
