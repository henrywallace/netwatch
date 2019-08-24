package watch

// Config holds configuration for Triggers.
type Config struct {
	Triggers map[string]TriggerSpec `toml:"triggers"`
}

// TriggerSpec describes specification for one trigger.
type TriggerSpec struct {
	Disabled       bool
	OnEvents       []EventType
	OnEventsExcept []EventType
	OnAny          bool
	OnShell        string
	DoBuiltin      string
	DoShell        string
}
