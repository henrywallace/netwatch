package watch

import (
	"fmt"
	"time"
)

type EventType int

const (
	Invalid EventType = iota
	HostNew
	HostLost
	HostFound
	PortNew
	PortLost
	PortFound
	// TODO: Add simple touch events.
)

func (ty EventType) MarshalText() ([]byte, error) {
	var s string
	switch ty {
	case Invalid:
		s = "invalid"
	case HostNew:
		s = "host.new"
	case HostLost:
		s = "host.lost"
	case HostFound:
		s = "host.found"
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
	case "host.new":
		*ty = HostNew
	case "host.lost":
		*ty = HostLost
	case "host.found":
		*ty = HostFound
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
