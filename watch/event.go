package watch

import (
	"fmt"
	"time"
)

// Event represents network activity. Events are intended to provide
// higher-level descriptions of network changes, possibly encapsulating packets
// seen over an extended period of time.
//
// A body of information peritent to the event type is attached to each event.
// For example, the relevant introcution of a new host's MAC address.
type Event struct {
	Type      EventType
	Timestamp time.Time
	Body      interface{}
}

// EventType describes the type of Event that has occurred.
type EventType int

// A complete list of types of Events.
const (
	Invalid EventType = iota
	HostTouch
	HostNew
	HostLost
	HostFound
	PortTouch
	PortNew
	PortLost
	PortFound
)

// MarshalText satisfies the encoding.TextMarshaler interface.
func (ty EventType) MarshalText() ([]byte, error) {
	var s string
	switch ty {
	case Invalid:
		s = "invalid"
	case HostTouch:
		s = "host.touch"
	case HostNew:
		s = "host.new"
	case HostLost:
		s = "host.lost"
	case HostFound:
		s = "host.found"
	case PortTouch:
		s = "port.touch"
	case PortNew:
		s = "port.new"
	case PortLost:
		s = "port.lost"
	case PortFound:
		s = "port.found"
	default:
		panic(fmt.Sprintf("unknown event type: %v", ty))
	}
	return []byte(s), nil
}

// UnmarshalText satisfies the encoding.TextUnmarshaler interface.
func (ty *EventType) UnmarshalText(text []byte) error {
	s := string(text)
	switch s {
	case "", "invalid":
		*ty = Invalid
	case "host.touch":
		*ty = HostTouch
	case "host.new":
		*ty = HostNew
	case "host.lost":
		*ty = HostLost
	case "host.found":
		*ty = HostFound
	case "port.touch":
		*ty = PortTouch
	case "port.new":
		*ty = PortNew
	case "port.lost":
		*ty = PortLost
	case "port.found":
		*ty = PortFound
	default:
		panic(fmt.Sprintf("unknown event type: %v", ty))
	}
	return nil
}

//
// host
//

// TODO: All of these events should be copies of events. If these events are
// fed into many different subscribers, then some of the attributes about the
// Host or Port, may not be correct.

// EventHostTouch happens when any activity updates the state of a host.
type EventHostTouch struct {
	Host *Host
	// TODO: Add an id or number indicating which number this is, or some
	// other stats. Might be useful for other event bodies as well.
}

// EventHostNew happens upon the introduction of a new host not yet seen.
// Becoming inactive does not make it unseen.
type EventHostNew struct {
	Host *Host
}

// EventHostLost happens when a host becomes inactive, after having no activity
// for some amount of time.
type EventHostLost struct {
	Host *Host
	Up   time.Duration
}

// EventHostFound happens whenever a host becomes active again after being
// contiguously inactive for some period of time.
type EventHostFound struct {
	Host *Host
	Down time.Duration
}

//
// port
//

// EventPortTouch happens when any activity updates the state of a Port.
type EventPortTouch struct {
	Port *Port
	Host *Host
}

// EventPortNew happens upon the introduction of a new port not yet seen.
// Becoming inactive does not make it unseen.
type EventPortNew struct {
	Port *Port
	Host *Host
}

// EventPortLost happens when a port becomes inactive, after having no activity
// for some amount of time.
type EventPortLost struct {
	Port *Port
	Up   time.Duration
	Host *Host
}

// EventPortFound happens whenever a port becomes active again after being
// contiguously inactive for some period of time.
type EventPortFound struct {
	Port *Port
	Down time.Duration
	Host *Host
}
