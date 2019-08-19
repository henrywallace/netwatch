package watch

import "time"

type EventKind int

const (
	HostNew EventKind = iota
	HostDrop
	HostReturn
	PortNew
	PortDrop
	PortReturn
)

type Event struct {
	Kind EventKind
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
