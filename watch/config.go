package watch

type Config struct {
	Subscribers map[string]SubSpec `toml:"subs"`
}

type SubSpec struct {
	Disabled       bool
	OnEvents       []EventType
	OnEventsExcept []EventType
	OnAny          bool
	DoBuiltin      string
	DoShell        string
}
