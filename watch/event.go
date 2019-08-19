package watch

import (
	"fmt"
	"time"
)

type EventType int

const (
	Invalid EventType = iota
	HostNew
	HostDrop
	HostReturn
	PortNew
	PortDrop
	PortReturn
	// TODO: Add simple touch events.
)

func (ty EventType) MarshalText() ([]byte, error) {
	var s string
	switch ty {
	case Invalid:
		s = "invalid"
	case HostNew:
		s = "host.new"
	case HostDrop:
		s = "host.drop"
	case HostReturn:
		s = "host.return"
	case PortNew:
		s = "port.new"
	case PortDrop:
		s = "port.drop"
	case PortReturn:
		s = "port.return"
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
	case "host.drop":
		*ty = HostDrop
	case "host.return":
		*ty = HostReturn
	case "port.new":
		*ty = PortNew
	case "port.drop":
		*ty = PortDrop
	case "port.return":
		*ty = PortReturn
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

type EventHostReturn struct {
	Host *Host
	Down time.Duration
}

type EventHostDrop struct {
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
