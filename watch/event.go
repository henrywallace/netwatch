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
	TrackedEndpoint
}

type EventHostReturn struct {
	TrackedEndpoint
}

type EventHostDrop struct {
	TrackedEndpoint
}
