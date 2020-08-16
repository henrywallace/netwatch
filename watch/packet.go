package watch

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/henrywallace/netwatch/util"
)

var (
	ttlHost     = 120 * time.Second
	ttlPort     = 30 * time.Second
	ttlArpScan  = 5 * time.Second
	arpScanFreq = 20.0
	arpWindow   = 10 * time.Second
)

// Activity holds episodic state for something.
type Activity struct {
	IsActive         bool
	FirstSeen        time.Time
	FirstSeenEpisode time.Time
	LastSeen         time.Time

	expireFunc func(a *Activity)
	expire     *time.Timer
	ttl        time.Duration
}

// NewActivity creates a new Activity with the given time-to-live, and callback
// once it hasn't been touched after the given ttl.
func NewActivity(ttl time.Duration, expireFunc func(a *Activity)) *Activity {
	a := &Activity{
		ttl:        ttl,
		expireFunc: expireFunc,
	}
	return a
}

// Touch resets the time to live for this Activity, and returns if already was
// active.
func (a *Activity) Touch(now time.Time) bool {
	if a.expire == nil {
		a.expire = time.AfterFunc(a.ttl, func() {
			a.IsActive = false
			a.expireFunc(a)
		})
	} else {
		a.expire.Reset(a.ttl)
	}
	if a.FirstSeen.IsZero() {
		a.FirstSeen = now
	}
	var wasActive bool
	if a.IsActive {
		wasActive = true
	} else {
		a.FirstSeenEpisode = now
	}
	a.IsActive = true
	a.LastSeen = now
	return wasActive
}

// Age returns the time since this was first seen, regardless if it is
// currently active or not.
func (a Activity) Age() time.Duration {
	return time.Since(a.FirstSeen)
}

// Up returns the time since this was recently first seen.
func (a Activity) Up() time.Duration {
	return time.Since(a.FirstSeenEpisode)
}

// Host is a tracked entity.
type Host struct {
	Activity        *Activity
	ActivityARPScan *Activity

	MAC      MAC
	IPv4     net.IP
	IPv6     net.IP
	TCP      map[int]*Port
	UDP      map[int]*Port
	Hostname string

	arps *windowed
}

func (h Host) String() string {
	var parts []string
	if h.Hostname != "" {
		parts = append(parts, h.Hostname)
	}
	parts = append(parts, string(h.MAC), h.IPv4.String())
	s := fmt.Sprintf("Host(%s)", strings.Join(parts, ", "))
	return s
}

// NewHost returns a new Host whose activity is touched on creation. The given
// expire function is called whenever the Host hasn't been touched after some
// default amount of time, indicating that it is non-active.
func NewHost(
	mac MAC,
	events chan<- Event,
	now time.Time,
	expire func(h *Host),
) *Host {
	h := Host{
		MAC:  mac,
		TCP:  make(map[int]*Port),
		UDP:  make(map[int]*Port),
		arps: newWindowed(arpWindow),
	}
	h.Activity = NewActivity(ttlHost, func(a *Activity) {
		expire(&h)
	})
	h.Activity.Touch(now)
	h.ActivityARPScan = NewActivity(ttlArpScan, func(a *Activity) {
		events <- Event{
			Type: HostARPScanStop,
			Body: EventHostARPScanStop{
				Host: &h,
				Up:   time.Since(a.FirstSeenEpisode),
			},
		}
	})
	return &h
}

// ActiveTCP returns all TCP ports for the given Host that are currently
// active.
//
// NOTE: Due to the expiring nature of Ports, it may be that returned pointers
// to Ports are inactive when received or used.
func (h Host) ActiveTCP() []*Port {
	var active []*Port
	for _, p := range h.TCP {
		if p.Activity.IsActive {
			active = append(active, p)
		}
	}
	return active
}

// ActiveUDP returns all UDP ports for the given Host that are currently
// active.
//
// NOTE: Due to the expiring nature of Ports, it may be that returned pointers
// to Ports are inactive when received or used.
func (h Host) ActiveUDP() []*Port {
	var active []*Port
	for _, p := range h.UDP {
		if p.Activity.IsActive {
			active = append(active, p)
		}
	}
	return active
}

// Port represents a TCP or UDP connection. A Port could both appear on either
// a sending or receiving host. Each Port has a TTL, before being considered
// inactive. But it can be "touched" to be kept alive.
type Port struct {
	Activity *Activity
	Num      int

	isTCP bool
}

// NewPortTCP returns a new TCP port of the given port number. And a function
// one what to do when the port expires, given a pointer to the created Port.
func NewPortTCP(
	num int,
	now time.Time,
	expire func(p *Port),
) *Port {
	p := Port{
		Num:   num,
		isTCP: true,
	}
	p.Activity = NewActivity(ttlHost, func(a *Activity) {
		expire(&p)
	})
	p.Activity.Touch(now)
	return &p
}

// NewPortUDP returns a new UDP port of the given port number. And a function
// one what to do when the port expires, given a pointer to the created Port.
func NewPortUDP(
	num int,
	now time.Time,
	expire func(p *Port),
) *Port {
	p := Port{
		Num:   num,
		isTCP: false,
	}
	p.Activity = NewActivity(ttlHost, func(a *Activity) {
		expire(&p)
	})
	p.Activity.Touch(now)
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

// View represents a subset of information depicted about a Host, from a single
// packet. This can be used to be associate with a host, and update it's
// information. A View's properties are intended to be updated as different
// layers of the packet are decoded. Some packet layers may not yet influence a
// View, but it aims to capture as much information from each packet as
// possible before updating the hosts.
type View struct {
	MAC      *MAC
	IPv4     net.IP
	IPv6     net.IP
	TCP      map[int]bool
	UDP      map[int]bool
	Hostname string
}

// NewView returns a new
func NewView() View {
	return View{
		TCP: make(map[int]bool),
		UDP: make(map[int]bool),
	}
}

// ViewPair represents a pair of views that are communicating withing one
// packet, all determined from a single packet.
type ViewPair struct {
	Src    View
	Dst    View
	Layers map[gopacket.LayerType]int
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
	for p := range packets {
		vp := handlePacket(w.log, p)
		w.updateHosts(vp, hosts)
	}
}

// Consider using a graph database for storing all directed interactions
// between the hosts.

// InvalidHost can be used to represent a newly found Host, where there is only
// a non-empty Curr.
var InvalidHost = Host{}

func (w *Watcher) updateHosts(
	vp ViewPair,
	hosts map[MAC]*Host,
) {
	w.updateHostWithView(hosts, vp, vp.Src)
	// TODO: There are some bugs here with the double updating, with
	// duplicate new hosts being detected.
	//
	// w.updateHostWithView(v.Dst, hosts)
}

func (w *Watcher) updateHostWithView(
	hosts map[MAC]*Host,
	vp ViewPair,
	v View,
) {
	now := time.Now()

	// TODO: Relieve this handicap, which is an artifact of the hosts
	// map[MAC]*Host datastructure, which should be made more
	// flexible.
	if v.MAC == nil {
		return
	}

	prev := findHost(v, hosts)
	var curr *Host
	if prev == nil {
		curr = NewHost(*v.MAC, w.events, now, func(h *Host) {
			up := time.Since(h.Activity.FirstSeenEpisode)
			w.events <- Event{
				Type: HostLost,
				Body: EventHostLost{h, up},
			}
		})
		hosts[*v.MAC] = curr
		w.events <- Event{
			Type: HostNew,
			Body: EventHostNew{curr},
		}
	} else {
		if time.Since(prev.Activity.LastSeen) > ttlHost {
			down := time.Since(prev.Activity.LastSeen)
			w.events <- Event{
				Type: HostFound,
				Body: EventHostFound{prev, down},
			}
		}
		curr = prev
		// TODO: Add timestamp arg to Touch method.
		curr.Activity.Touch(now)
		w.log.Debugf("touch host %s", curr)
		w.events <- Event{
			Type: HostTouch,
			Body: EventHostTouch{curr},
		}
	}

	if v.Hostname != "" {
		if curr.Hostname != v.Hostname {
			w.log.Warnf("hostname has changed %s -> %s", curr.Hostname, v.Hostname)
		}
		curr.Hostname = v.Hostname
	}

	// Update ARP scan.
	if vp.Layers[layers.LayerTypeARP] > 0 {
		// TODO: Use a View timestamp.
		curr.arps.Add(now)
	}
	freq := curr.arps.Freq()
	if freq >= arpScanFreq {
		if !curr.ActivityARPScan.Touch(now) {
			w.events <- Event{
				Type: HostARPScanStart,
				Body: EventHostARPScanStart{curr},
			}
		}
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
	now := time.Now()

	for num := range v.TCP {
		prev, ok := h.TCP[num]
		var curr *Port
		if !ok {
			curr = NewPortTCP(num, now, func(p *Port) {
				w.events <- Event{
					Type: PortLost,
					Body: EventPortLost{p, p.Activity.Up(), h},
				}
			})
			h.TCP[num] = curr
			w.events <- Event{
				Type: PortNew,
				Body: EventPortNew{curr, h},
			}
		} else {
			if time.Since(prev.Activity.LastSeen) > ttlPort {
				// We consider the host to have been alive for
				// ttlPort nanoseconds after it was last seen.
				down := time.Since(prev.Activity.LastSeen) - ttlPort
				w.events <- Event{
					Type: PortFound,
					Body: EventPortFound{prev, down, h},
				}
			}
			curr = prev
			curr.Activity.Touch(now)
			w.log.Debugf("touch host %s on %s", curr, h.IPv4)
		}

	}
	for num := range v.UDP {
		prev, ok := h.UDP[num]
		var curr *Port
		if !ok {
			curr = NewPortUDP(num, now, func(p *Port) {
				w.events <- Event{
					Type: PortLost,
					Body: EventPortLost{p, p.Activity.Up(), h},
				}
			})
			h.UDP[num] = curr
			w.events <- Event{
				Type: PortNew,
				Body: EventPortNew{curr, h},
			}
		} else {
			if time.Since(prev.Activity.LastSeen) > ttlPort {
				// We consider the host to have been alive for
				// ttlPort nanoseconds after it was last seen.
				down := time.Since(prev.Activity.LastSeen) - ttlPort
				w.events <- Event{
					Type: PortFound,
					Body: EventPortFound{prev, down, h},
				}
			}
			curr = prev
			curr.Activity.Touch(now)
			w.log.Debugf("touch host %s on %s", curr, h.IPv4)
			w.events <- Event{
				Type: PortTouch,
				Body: EventPortTouch{curr, h},
			}
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

func addIP(v *View, ip net.IP) {
	if len(ip) == net.IPv4len {
		v.IPv4 = ip
	} else if len(ip) == net.IPv6len {
		v.IPv6 = ip
	} else {
		util.NewLogger().Warnf("invalid ip len=%d: %#v", len(ip), ip)
	}
}

type windowed struct {
	size    time.Duration
	mu      sync.Mutex
	entries []time.Time
}

func newWindowed(size time.Duration) *windowed {
	return &windowed{size: size}
}

// Add adds an entry with the given timestamp.
func (w *windowed) Add(ts time.Time) {
	w.mu.Lock()
	w.entries = append(w.entries, ts)
	if len(w.entries)%50 == 0 {
		w.flush()
	}
	w.mu.Unlock()
}

func (w *windowed) flush() {
	now := time.Now()
	cut := now.Add(-w.size)
	i := sort.Search(len(w.entries), func(i int) bool {
		return w.entries[i].After(cut)
	})
	w.entries = w.entries[i:]
}

// Count returns the nubmer of entries in the window size.
func (w *windowed) Count() int {
	w.flush()
	return len(w.entries)
}

// Freq returns the current Count per second.
func (w *windowed) Freq() float64 {
	return float64(w.Count()) / w.size.Seconds()
}
