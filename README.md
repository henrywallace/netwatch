# netwatch

netwatch is a library and command line tool for aggregating and inferring
information about hosts in a network by passively sniffing packets. It fashions
events based on changes to those hosts, e.g. a new host with new MAC address
has entered the local network, a known host is using never before used port
22/tcp, or a host is performing an ARP scan.

Example:
```
% sudo -E go run main.go --only log
INFO[2019-09-24 20:28:38] using first up interface: eth0
INFO[2019-09-24 20:28:44] new Host(xx:xx:xx:xx:xx:xx, 192.168.86.50)
INFO[2019-09-24 20:28:44] new 1900/udp on Host(xx:xx:xx:xx:xx:xx, 192.168.86.50)
INFO[2019-09-24 20:28:46] new Host(yy:yy:yy:yy:yy:yy, 192.168.86.20)
INFO[2019-09-24 20:28:46] new 44054/tcp on Host(yy:yy:yy:yy:yy:yy, 192.168.86.20)
INFO[2019-09-24 20:28:46] new Host(zz:zz:zz:zz:zz:zz, 0.0.0.0)
INFO[2019-09-24 20:28:46] new 443/tcp on Host(zz:zz:zz:zz:zz:zz, 0.0.0.0)
```

Using the config, you can also configure your own hook events, with builtin
event names, and templated variables for use in commands:
```sh
% cat > config.toml <<END
[triggers]
  [triggers.new-host]
    onEvents = ["host.new"]
    doShell = "echo 'New host {{.Host.MAC}} on {{.Host.IPv4}}'"
END
% sudo netwatch --only new-host
```

You can also filter events by a shell command that exits 0 on success, instead
of builtin `onEvents` like in the example above. For example we could send an
email to ourselves with github.com/henrywallace/notify whenever SSH port is
used on some IP address of interest:
```sh
% cat > config.toml <<END
[triggers]
  [triggers.gmail-ssh]
    onShell = '[ "{{.Host.IPv4}}:{{.PortString}}" = "192.168.86.4:22" ]'
    doShell = "NOTIFY_TO=alerts@mydomain.io notify --subject '{{.Description}}'"
END
% sudo netwatch --only gmail-ssh
```

As a disclaimer, there do indeed exist many other tools adjacent to this
functionality such as bettercap [1] skydive [2], wireshark [3], ad nauseum. I'm
naive, curious, and selfishly motivated by personal learning. Please forgive
what may seem like reinventing the wheel; it's really fun.

There are a few concepts that aim to make this a flexible framework:

- A Host is identified by a MAC address. It also holds aggregated port usage,
  and connections to other hosts over time. If no activity is seen originating
  from a Host it becomes inactive.

- A View is a collection of extracted data from a single frame/packet about one
  Host, such as MAC address, IP address, ports, and adjacent Hosts that it's
  communicating with.

- Events are high level descriptions of changes to Hosts. For example, a port
  that was being used hasn't seen any activity for say 30 seconds, and is
  deemed inactive. Or a Host appears to be performing an ARP scan. Or a Host is
  sending a packet whose TLS signature matches that of a known metasploit
  exploit [6]. Events should be timestamped in case you'd like to analyze a
  offline pcap file [4].

- Subscribers are hooks to a stream of new Events. As a CLI, Subscribers can be
  configured in a config.toml, each of which can be either hardcoded named
  builtins such as "log" events, or custom shell scripts. As a library,
  Subscribers are just functions that take in a single Event as an argument.


## Wishlist

The following is a wishlist of what I want to do next, which should eventually
get converted to issues:

- Use persistent storage, such as PostgreSQL/Redis.
- SSI signal strength, for use in location triangulation. I shit you not. [10]
- Hardware vendor OUI names [5].
- Detect ARP scan being triggered from Host.
- Keep track of touched, and most used domain/paths requests from Hosts, e.g.
  Bob's laptop visits example.com/foobar most frequently.
- Create events whenever unencrypted traffic is detected.
- JA3 TLS/SSL client/server fingerprinting [6].
- HASSH SSH client/server fingerprinting [7].
- IP geo location lookup [8].
- Record surrounding window of packets, for events of interest.
- File extraction fingerprinting [9].
- Stenography detection [11].


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
- [10] https://youtu.be/2IeU7Cck0hI
- [11] https://github.com/google/stenographer
