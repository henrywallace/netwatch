package watch

import (
	"context"
	"fmt"
	"os"
	"time"

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
		subs = []Subscriber{Logger(log)}
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

func Logger(log *logrus.Logger) Subscriber {
	return func(e Event) error {
		switch e.Type {
		case HostNew:
			e := e.Body.(EventHostNew)
			log.Infof("new %s", e.Host)
		case HostDrop:
			e := e.Body.(EventHostDrop)
			log.Infof("drop %s (up %s)", e.Host, e.Up)
		case HostReturn:
			e := e.Body.(EventHostReturn)
			log.Infof("return %s (down %s)", e.Host, e.Down)
		case PortNew:
			e := e.Body.(EventPortNew)
			log.Infof("new %s on %s", e.Port, e.Host)
		case PortDrop:
			e := e.Body.(EventPortDrop)
			log.Infof("drop %s (up %s) on %s", e.Port, e.Up, e.Host)
		case PortReturn:
			e := e.Body.(EventPortReturn)
			log.Infof("return %s (down %s) on %s", e.Port, e.Down, e.Host)
		default:
			panic(fmt.Sprintf("unhandled event type: %#v", e))
		}
		return nil
	}
}
