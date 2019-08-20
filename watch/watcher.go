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
	"github.com/sirupsen/logrus"
)

var (
	ttlHost = 120 * time.Second
	ttlPort = 30 * time.Second
)

type Watcher struct {
	log    *logrus.Logger
	events chan Event
	subs   []Subscriber
}

type Subscriber func(e Event) error

func NewWatcher(log *logrus.Logger, subs ...Subscriber) *Watcher {
	if len(subs) == 0 {
		subs = []Subscriber{SubLogger(log)}
	}
	return &Watcher{
		log:    log,
		events: make(chan Event, 32),
		subs:   subs,
	}
}

func (w *Watcher) Watch(ctx context.Context) error {
	iface := os.Getenv("IFACE")
	if iface == "" {
		w.log.Fatal("must provide env IFACE")
	}
	h, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	src := gopacket.NewPacketSource(h, h.LinkType())
	hosts := make(map[MAC]*Host)
	go w.ScanPackets(hosts, src.Packets())
	return w.Publish()
}

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

func SubLogger(log *logrus.Logger) Subscriber {
	return func(e Event) error {
		switch e.Type {
		case HostTouch:
			e := e.Body.(EventHostTouch)
			log.Infof("touch %s", e.Host)
		case HostNew:
			e := e.Body.(EventHostNew)
			log.Infof("new %s", e.Host)
		case HostLost:
			e := e.Body.(EventHostLost)
			log.Infof("drop %s (up %s)", e.Host, e.Up)
		case HostFound:
			e := e.Body.(EventHostFound)
			log.Infof("return %s (down %s)", e.Host, e.Down)
		case PortTouch:
			e := e.Body.(EventPortTouch)
			log.Infof("touch %s on %s", e.Port, e.Host)
		case PortNew:
			e := e.Body.(EventPortNew)
			log.Infof("new %s on %s", e.Port, e.Host)
		case PortLost:
			e := e.Body.(EventPortDrop)
			log.Infof("drop %s (up %s) on %s", e.Port, e.Up, e.Host)
		case PortFound:
			e := e.Body.(EventPortReturn)
			log.Infof("return %s (down %s) on %s", e.Port, e.Down, e.Host)
		default:
			panic(fmt.Sprintf("unhandled event type: %#v", e))
		}
		return nil
	}
}

func SubConfig(
	log *logrus.Logger,
	path string,
	only []string,
) (Subscriber, error) {
	var conf Config
	if _, err := toml.DecodeFile(path, &conf); err != nil {
		return nil, err
	}
	// TODO: validate config, e.g. not on event and on events, etc.

	triggers := make(map[string]Trigger)
	onlySet := stringSet(only)
	for name, spec := range conf.Subscribers {
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

func stringSet(slice []string) map[string]bool {
	m := make(map[string]bool)
	for _, s := range slice {
		m[s] = true
	}
	return m
}

type Trigger struct {
	Sub      Subscriber
	ShouldDo func(e Event) bool
}

func newTriggerFromConfig(
	log *logrus.Logger,
	name string,
	spec SubSpec,
) Trigger {
	var sub Subscriber
	if spec.DoBuiltin != "" {
		sub = newSubFromBuiltin(log, spec.DoBuiltin)
	}
	if spec.DoShell != "" {
		sub = newSubFromShell(context.TODO(), log, spec.DoShell)
	}
	if sub == nil {
		log.Fatalf("failed to define trigger from spec.Do: %#v", spec)
	}
	return Trigger{
		Sub: sub,
		ShouldDo: func(e Event) bool {
			if spec.OnAny {
				return true
			}
			if spec.OnEvent != Invalid {
				return spec.OnEvent == e.Type
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
	case "log":
		sub = SubLogger(log)
	default:
		panic(fmt.Sprintf("unknown sub name: '%s'", builtin))
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
			return err
		}
		out := strings.TrimSpace(string(b))
		fmt.Println(out)
		return nil
	}
}

type eventInfo struct {
	Host Host
	Port Port
	Up   time.Duration
	Down time.Duration
}

func newEventInfo(e Event) eventInfo {
	var info eventInfo
	switch e.Type {
	case HostTouch:
		e := e.Body.(EventHostTouch)
		info.Host = *e.Host
	case HostNew:
		e := e.Body.(EventHostNew)
		info.Host = *e.Host
	case HostLost:
		e := e.Body.(EventHostLost)
		info.Host = *e.Host
		info.Up = e.Up
	case HostFound:
		e := e.Body.(EventHostFound)
		info.Host = *e.Host
		info.Down = e.Down
	case PortTouch:
		e := e.Body.(EventPortTouch)
		info.Port = *e.Port
		info.Host = *e.Host
	case PortNew:
		e := e.Body.(EventPortNew)
		info.Port = *e.Port
		info.Host = *e.Host
	case PortLost:
		e := e.Body.(EventPortDrop)
		info.Port = *e.Port
		info.Up = e.Up
		info.Host = *e.Host
	case PortFound:
		e := e.Body.(EventPortReturn)
		info.Port = *e.Port
		info.Down = e.Down
		info.Host = *e.Host
	default:
		panic(fmt.Sprintf("unhandled event type: %#v", e))
	}
	return info
}
