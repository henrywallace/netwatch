# netwatch

netwatch both a library and tool for aggregating information about hosts in a
network, by passively sniffing packets. And to fashion high-level events based
on changes to those hosts. For example, a new host has entered the local
network, or a new port is being used by an known host.

As a disclaimer, there do indeed exist many other tools adjacent to this
functionaltiy such as bettercap [1] skydive [2], wirshark [3], or otherwise a
vast universe of pcap analysis. I'm naive, curious, and selfishly motivated to
build this tool for personal learning. As such, please forgive what may seem
like reinventing the wheel: it's really fun.

There are a few concepts that aim to make this a flexible framework:
- An Agent is the abstract notion of a entity in a network. An Agent may use
  MAC spoofing or be controlling several real computers in concert.
- A Host is a aggregate of information about a single computer in a network
  defined by a MAC address. It can hold all information that has been extracted
  about this computer over the lifetime of passive sniffing.
- A View is a collection of extracted data from a single packet about one Host,
  such as MAC address, IP address, ports, and adjacent Hosts that it's
  communicating with.
- Events are high level descriptions of changes to Agents, which are
  timestamped in case you'd like to analyze a offline pcap file [4].
- Subscribers are hooks to a stream of new Events.
- Top is a collection of information that summarizes the entire local network,
  such as the total number of Hosts.


## Wishlist

The following is a wishlist of new information to glean from packets, and
aggregate into corresponding host state. Or otherwise, just things to do.

- SSI signal strength, and possible location trianguation.
- Any OS or manufacturer information gleaned from packets, and possibly MAC OUI
  lookup [5].
- Detect ARP scan being triggered.
- Keep track of touched, and most used domain and host requests from Hosts.
- JA3 TLS/SSL client/server fingerprinting [6].
- HASSH SSH client/server fingerprinting [7].
- IP geo location lookup [8].
- Record rolling window stream of packets, and save relevant windows around
  events of interest.
- File extraction fingerprinting [9].


## References

- [1] https://github.com/bettercap/bettercap
- [2] https://github.com/skydive-project/skydive
- [3] https://github.com/wireshark/wireshark
- [4] https://www.netresec.com/?page=PcapFiles
- [5] https://www.wireshark.org/tools/oui-lookup.html
- [6] https://github.com/salesforce/ja3
- [7] https://github.com/salesforce/hassh
- [8] https://en.wikipedia.org/wiki/Geolocation_software
- [9] https://packages.bro.org/packages/view/435bb7a9-8ed4-11e9-88be-0a645a3f3086
