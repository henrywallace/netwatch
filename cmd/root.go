package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/henrywallace/netwatch/util"
	"github.com/henrywallace/netwatch/watch"
)

var rootCmd = &cobra.Command{
	Use:   "netwatch",
	Short: "Watch for activity on a LAN",
	RunE:  main,
}

func init() {
	rootCmd.Flags().StringP("config", "c", "config.toml", "toml file to trigger config")
	rootCmd.Flags().StringSliceP("only", "o", nil, "config trigger names to only run")
	rootCmd.Flags().StringP("iface", "i", "", "which network interface to use, if not first active")
	rootCmd.Flags().StringP("pcap", "p", "", "whether to read from pcap file instead of live interface")
}

func main(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	log := util.NewLogger()

	var subs []watch.Subscriber
	path := mustString(log, cmd, "config")
	only := mustStringSlice(log, cmd, "only")
	if path != "" {
		sub, err := watch.NewSubConfig(log, path, only)
		if err != nil {
			return err
		}
		subs = append(subs, sub)
	}

	iface := mustString(log, cmd, "iface")
	pcap := mustString(log, cmd, "pcap")
	if iface != "" && pcap != "" {
		return errors.Errorf(
			"cannot specify both --iface=%s and --pcap=%s",
			iface,
			pcap,
		)
	}

	w := watch.NewWatcher(log, subs...)
	if pcap != "" {
		return w.WatchPCAP(ctx, pcap)
	}
	if iface == "" {
		var err error
		iface, err = firstLiveInterface()
		if err != nil {
			return err
		}
		log.Infof("using first up interface: %s", iface)
	}
	return w.WatchLive(ctx, iface)
}

// return the name of the first live interface
// https://unix.stackexchange.com/a/335082/162041
func firstLiveInterface() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if strings.Contains(iface.Name, "docker") {
			continue
		}
		return iface.Name, nil
	}
	return "", errors.Errorf("failed to find interface to scan")
}

// Execute adds all child commands to the root command and sets flags
// appropriately. This is called by main.main(). It only needs to happen once
// to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func mustString(
	log *logrus.Logger,
	cmd *cobra.Command,
	name string,
) string {
	val, err := cmd.Flags().GetString(name)
	if err != nil {
		log.Fatal(err)
	}
	return val
}

func mustStringSlice(
	log *logrus.Logger,
	cmd *cobra.Command,
	name string,
) []string {
	val, err := cmd.Flags().GetStringSlice(name)
	if err != nil {
		log.Fatal(err)
	}
	return val
}
