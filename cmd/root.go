package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/henrywallace/homelab/go/netwatch/util"
	"github.com/henrywallace/homelab/go/netwatch/watch"
)

var rootCmd = &cobra.Command{
	Use:   "netwatch",
	Short: "Watch for activity on a LAN",
	RunE:  main,
}

func init() {
	rootCmd.Flags().StringP("config", "c", "config.toml", "toml file to exec config")
}

func main(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	log := util.NewLogger()

	var subs []watch.Subscriber
	path := mustString(log, cmd, "config")
	if path != "" {
		sub, err := watch.SubConfig(log, path)
		if err != nil {
			return err
		}
		subs = append(subs, sub)
	}

	return watch.NewWatcher(log, subs...).Watch(ctx)
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
