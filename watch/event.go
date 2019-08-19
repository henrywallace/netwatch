package watch

import (
	"fmt"
	"time"
)

type EventType int

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

type Event struct {
	Type EventType
	Body interface{}
}

//
// host
//

type EventHostTouch struct {
	Host *Host
	// TODO: Add an id or number indicating which number this is, or some
	// other stats. Might be useful for other event bodies as well.
}

type EventHostNew struct {
	Host *Host
}

type EventHostFound struct {
	Host *Host
	Down time.Duration
}

type EventHostLost struct {
	Host *Host
	Up   time.Duration
}

//
// port
//

type EventPortTouch struct {
	Port *Port
	Host *Host
}

type EventPortNew struct {
	Port *Port
	Host *Host
}

type EventPortDrop struct {
	Port *Port
	Up   time.Duration
	Host *Host
}

type EventPortReturn struct {
	Port *Port
	Down time.Duration
	Host *Host
}
