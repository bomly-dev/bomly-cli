package cli

import (
	"fmt"

	"github.com/bomly/bomly-cli/internal/plugin"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func newPluginCmd(_ string, options *globalOptions) *cobra.Command {
	pluginCmd := &cobra.Command{
		Use:   "plugin",
		Short: "Plugin management commands",
	}

	pluginCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List discovered plugins",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := commandLogger(cmd, options, "plugin")
			streams := newCommandStreams(cmd, options.current().Quiet, options.current().Verbosity)
			logger.Info("Discovering plugins")
			plugins, err := plugin.Discover(plugin.DiscoverOptions{})
			if err != nil {
				logger.Error(fmt.Sprintf("Plugin discovery failed: %v", err))
				logger.Debug("plugin discovery failed", zap.Error(err))
				return fmt.Errorf("discover plugins: %w", err)
			}
			logger.Info(fmt.Sprintf("Discovered %d plugin(s)", len(plugins)))
			logger.Debug("plugin discovery completed", zap.Int("plugin_count", len(plugins)))
			for _, p := range plugins {
				fmt.Fprintf(streams.reportWriter(), "%s\t%s\t%s\n", p.Metadata.Name, p.Metadata.Version, p.Path)
			}
			return nil
		},
	})

	return pluginCmd
}
