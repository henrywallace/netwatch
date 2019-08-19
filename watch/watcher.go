package watch

import (
	"context"
	"fmt"
	"os"
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
		case HostNew:
			e := e.Body.(EventHostNew)
			log.Infof("new %s", e.Host)
		case HostLost:
			e := e.Body.(EventHostLost)
			log.Infof("drop %s (up %s)", e.Host, e.Up)
		case HostFound:
			e := e.Body.(EventHostFound)
			log.Infof("return %s (down %s)", e.Host, e.Down)
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

func SubConfig(log *logrus.Logger, path string) (Subscriber, error) {
	var conf Config
	if _, err := toml.DecodeFile(path, &conf); err != nil {
		return nil, err
	}
	// TODO: validate config, e.g. not on event and on events, etc.

	triggers := make(map[string]Trigger)
	for name, spec := range conf.Subscribers {
		log.Debugf("loading subscriber %s", name)
		triggers[name] = newTriggerFromConfig(log, name, spec)
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

type Trigger struct {
	Sub      Subscriber
	ShouldDo func(e Event) bool
}

func newTriggerFromConfig(log *logrus.Logger, name string, spec SubSpec) Trigger {
	var sub Subscriber
	switch strings.ToLower(spec.Do) {
	case "log":
		sub = SubLogger(log)
	default:
		panic(fmt.Sprintf("unknown sub name: '%s'", name))
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
			for _, ty := range spec.OnEvents {
				if ty == e.Type {
					return true
				}
			}
			return false
		},
	}
}
