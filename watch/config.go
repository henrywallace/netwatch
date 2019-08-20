package watch

type Config struct {
	Subscribers map[string]SubSpec `toml:"subs"`
}

type SubSpec struct {
	OnEvent        EventType
	OnEvents       []EventType
	OnEventsExcept []EventType
	OnAny          bool
	DoBuiltin      string
}
