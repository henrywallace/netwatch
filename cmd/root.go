package cmd

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"

	"github.com/henrywallace/homelab/go/netwatch/watch"
)

var rootCmd = &cobra.Command{
	Use:   "netwatch",
	Short: "Watch for activity on a LAN",
	RunE:  main,
}

func main(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	sess, err := watch.StartSession()
	if err != nil {
		log.Fatalf("failed to start session: %v", err)
	}
	defer sess.Close()

	return watch.NewWatcher(sess).Watch(ctx)
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
