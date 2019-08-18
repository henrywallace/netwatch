package watch

import "time"

type EventKind int

const (
	HostNew EventKind = iota
	HostDrop
	HostReturn
	PortNew
	PortDrop
)

type Event struct {
	Kind EventKind
	Body interface{}
}

type EventHostNew struct {
	Host *Host
}

type EventHostReturn struct {
	Down time.Duration
	Host *Host
}

type EventHostDrop struct {
	Up   time.Duration
	Host *Host
}
