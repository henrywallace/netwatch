package watch

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	ttlHost = 120 * time.Second
	ttlPort = 30 * time.Second
)

// Watcher watches network activity and sends resultant Events to all of it's
// Subscribers.
type Watcher struct {
	log    *logrus.Logger
	events chan Event
	subs   []Subscriber
}

// NewWatcher creates a new watcher initialized with the given subscribers.
func NewWatcher(log *logrus.Logger, subs ...Subscriber) *Watcher {
	if len(subs) == 0 {
		subs = []Subscriber{NewSubLogger(log)}
	}
	return &Watcher{
		log:    log,
		events: make(chan Event, 32),
		subs:   subs,
	}
}

// Watch scans the given src for packets, and publish resultant Events to all
// of it's registered Subscribers.
func (w *Watcher) Watch(ctx context.Context, src *gopacket.PacketSource) error {
	hosts := make(map[MAC]*Host)
	go w.ScanPackets(hosts, src.Packets())
	return w.Publish()
}

// blocks forever
func (w *Watcher) WatchLive(ctx context.Context, iface string) error {
	h, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	src := gopacket.NewPacketSource(h, h.LinkType())
	return w.Watch(ctx, src)

}

func (w *Watcher) WatchPCAP(ctx context.Context, pcapPath string) error {
	h, err := pcap.OpenOffline(pcapPath)
	if err != nil {
		return err
	}
	src := gopacket.NewPacketSource(h, h.LinkType())
	return w.Watch(ctx, src)
}

// Publish endlessly reads incomming events, and sends a shallow copy of that
// event to each of this Watcher's Subscribers.
func (w *Watcher) Publish() error {
	for e := range w.events {
		for _, sub := range w.subs {
			if err := sub(e); err != nil {
				w.log.WithError(err).Errorf("failed to respond to event")
			}
		}
	}
	return nil
}

// NewSubConfig returns a new Subscriber
func NewSubConfig(
	log *logrus.Logger,
	path string,
	only []string,
) (Subscriber, error) {
	var conf Config
	if _, err := toml.DecodeFile(path, &conf); err != nil {
		return nil, err
	}
	// TODO: validate config, e.g. not on event and on events, etc.

	triggers := make(map[string]FilteredSubscriber)
	onlySet := stringSet(only)
	for name, spec := range conf.Triggers {
		if len(onlySet) > 0 && !onlySet[name] {
			continue
		}
		log.Debugf("loading subscriber %s", name)
		trig := newTriggerFromConfig(log, name, spec)
		if spec.Disabled && !onlySet[name] {
			continue
		}
		triggers[name] = trig
	}
	if len(triggers) == 0 {
		log.Fatal("no subscribers loaded")
	}

	return func(e Event) error {
		for name, trig := range triggers {
			if !trig.ShouldDo(e) {
				continue
			}
			if err := trig.Sub(e); err != nil {
				log.WithError(err).Errorf("failed to execute sub: %s", name)
			}
		}
		return nil
	}, nil
}

func newTriggerFromConfig(
	log *logrus.Logger,
	name string,
	spec TriggerSpec,
) FilteredSubscriber {
	var sub Subscriber
	if spec.DoBuiltin != "" {
		sub = newSubFromBuiltin(log, spec.DoBuiltin)
	}
	if spec.DoShell != "" {
		sub = newSubFromShell(context.TODO(), log, spec.DoShell)
	}
	if sub == nil {
		log.Fatalf(
			"failed to construct a trigger, "+
				"did you fill out doBuiltin or doShell?: %#v",
			spec,
		)
	}
	var shouldDo func(e Event) bool
	if spec.OnShell != "" {
		shouldDo = newShouldDoFromShell(context.TODO(), log, spec.OnShell)
	}
	return FilteredSubscriber{
		Sub: sub,
		ShouldDo: func(e Event) bool {
			if spec.OnAny {
				return true
			}
			if shouldDo != nil {
				return shouldDo(e)
			}
			if len(spec.OnEventsExcept) > 0 {
				for _, ty := range spec.OnEventsExcept {
					if ty == e.Type {
						return false
					}
				}
				return true
			}
			for _, ty := range spec.OnEvents {
				if ty == e.Type {
					return true
				}
			}
			return false
		},
	}
}

func newSubFromBuiltin(log *logrus.Logger, builtin string) Subscriber {
	var sub Subscriber
	switch strings.ToLower(builtin) {
	case "null":
		sub = NewSubNull(log)
	case "log":
		sub = NewSubLogger(log)
	default:
		panic(fmt.Sprintf("unsupported sub name: '%s'", builtin))
	}
	return sub
}

func newSubFromShell(
	ctx context.Context,
	log *logrus.Logger,
	shell string,
) Subscriber {
	return func(e Event) error {
		shell = os.ExpandEnv(shell)
		tmpl, err := template.New("").Parse(shell)
		if err != nil {
			return err
		}
		info := newEventInfo(e)
		var buf bytes.Buffer
		err = tmpl.Execute(&buf, info)
		if err != nil {
			return err
		}
		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", buf.String())
		b, err := cmd.CombinedOutput()
		if err != nil {
			return errors.Wrapf(err, "failed to run command: %v", string(b))
		}
		out := strings.TrimSpace(string(b))
		fmt.Println(out)
		return nil
	}
}

func newShouldDoFromShell(
	ctx context.Context,
	log *logrus.Logger,
	shell string,
) func(e Event) bool {
	shell = os.ExpandEnv(shell)
	tmpl, err := template.New("").Parse(shell)
	if err != nil {
		log.WithError(err).Fatalf("failed to template parse shell: %s", shell)
	}
	return func(e Event) bool {
		info := newEventInfo(e)
		var buf bytes.Buffer
		err = tmpl.Execute(&buf, info)
		if err != nil {
			log.WithError(err).Fatalf("failed to execute template")
			return false
		}
		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", buf.String())
		b, err := cmd.CombinedOutput()
		if err != nil {
			// The point of this shell command is to return a
			// non-zero exit code when an event should be skipped.
			// However, we also log so as to not preclude
			// debugging.
			log.Debugf("failed to run output: %v: %s", err, string(b))
			return false
		}
		return true
	}
}

type printableEvent struct {
	Description string
	Host        Host
	Port        Port
	PortString  string
	Up          time.Duration
	Down        time.Duration
	Age         time.Duration
}

func newEventInfo(e Event) printableEvent {
	var pe printableEvent
	switch e.Type {
	case HostTouch:
		e := e.Body.(EventHostTouch)
		pe.Host = *e.Host
		pe.Description = fmt.Sprintf(
			"touched host %s at %s (up %s) (age %s)",
			e.Host.MAC,
			e.Host.IPv4,
			time.Since(e.Host.FirstSeenEpisode),
			e.Host.Age(),
		)
	case HostNew:
		e := e.Body.(EventHostNew)
		pe.Host = *e.Host
		pe.Age = e.Host.Age()
		pe.Description = fmt.Sprintf(
			"new host %s at %s",
			e.Host.MAC,
			e.Host.IPv4,
		)
	case HostLost:
		e := e.Body.(EventHostLost)
		pe.Host = *e.Host
		pe.Up = e.Up
		pe.Description = fmt.Sprintf(
			"new host %s at %s (up %s) (age %s)",
			e.Host.MAC,
			e.Host.IPv4,
			e.Up,
			e.Host.Age(),
		)
	case HostFound:
		e := e.Body.(EventHostFound)
		pe.Host = *e.Host
		pe.Down = e.Down
		pe.Description = fmt.Sprintf(
			"found host %s at %s (down %s) (age %s)",
			e.Host.MAC,
			e.Host.IPv4,
			e.Down,
			e.Host.Age(),
		)
	case PortTouch:
		e := e.Body.(EventPortTouch)
		pe.Port = *e.Port
		pe.Host = *e.Host
		pe.PortString = e.Port.String()
		pe.Description = fmt.Sprintf(
			"touched port %s at %s (up %s)",
			pe.Port,
			pe.Host.IPv4,
			time.Since(pe.Host.FirstSeenEpisode),
		)
	case PortNew:
		e := e.Body.(EventPortNew)
		pe.Port = *e.Port
		pe.Host = *e.Host
		pe.PortString = e.Port.String()
		pe.Description = fmt.Sprintf(
			"new port %s at %s (age %s)",
			e.Port,
			e.Host.IPv4,
			e.Port.Age(),
		)
	case PortLost:
		e := e.Body.(EventPortLost)
		pe.Port = *e.Port
		pe.Up = e.Up
		pe.Host = *e.Host
		pe.PortString = e.Port.String()
		pe.Description = fmt.Sprintf(
			"new port %s at %s (up %s) (age %s)",
			e.Port,
			e.Host.IPv4,
			e.Up,
			e.Port.Age(),
		)
	case PortFound:
		e := e.Body.(EventPortFound)
		pe.Port = *e.Port
		pe.Down = e.Down
		pe.Host = *e.Host
		pe.PortString = e.Port.String()
		pe.Description = fmt.Sprintf(
			"found port %s at %s (down %s) (age %s)",
			e.Port,
			e.Host.IPv4,
			e.Down,
			e.Port.Age(),
		)
	default:
		panic(fmt.Sprintf("unhandled event type: %#v", e))
	}
	return pe
}

func stringSet(slice []string) map[string]bool {
	m := make(map[string]bool)
	for _, s := range slice {
		m[s] = true
	}
	return m
}
