package watch

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
	Host Host
}

type EventHostReturn struct {
	Diff Diff
}

type EventHostDrop struct {
	Host Host
}
