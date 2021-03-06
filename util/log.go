package util

import (
	"os"

	"github.com/sirupsen/logrus"
)

// NewLogger creates a new logger whose level can be controlled with the env
// WATCHER_LOGLEVEL.
func NewLogger() *logrus.Logger {
	log := logrus.StandardLogger()

	format := new(logrus.TextFormatter)
	format.TimestampFormat = "2006-01-02 15:04:05"
	format.FullTimestamp = true
	log.SetFormatter(format)

	val := os.Getenv("WATCHER_LOGLEVEL")
	if val == "" {
		val = "INFO"
	}
	lvl, err := logrus.ParseLevel(val)
	if err != nil {
		log.Fatalf("failed to parse level: %v", val)
	}
	log.SetLevel(lvl)

	return log
}
