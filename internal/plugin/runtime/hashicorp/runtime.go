package hashicorp

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/sdk"
	"github.com/hashicorp/go-hclog"
	hplugin "github.com/hashicorp/go-plugin"
)

// Client wraps one live managed plugin subprocess.
type Client struct {
	client *hplugin.Client
	raw    sdk.Client
}

// Start launches a managed plugin binary and dispenses the shared client.
func Start(ctx context.Context, executable string, env []string, verbosity int) (*Client, error) {
	cmd := exec.CommandContext(ctx, executable)
	cmd.Env = append(cmd.Env, env...)
	workingDir, _ := os.Getwd()
	eventLogger := pluginLogger(verbosity)
	eventLogger.Debug("starting plugin subprocess",
		"executable", executable,
		"args", logging.SanitizeArgs(cmd.Args[1:]),
		"working_dir", workingDir,
	)
	client := hplugin.NewClient(&hplugin.ClientConfig{
		HandshakeConfig:  sdk.HandshakeConfig(),
		AllowedProtocols: []hplugin.Protocol{hplugin.ProtocolGRPC},
		Cmd:              cmd,
		// Managed plugin stderr is visible only with debug logging. The plugin
		// owns this output, so users must treat debug logs as sensitive.
		Logger:          pluginLogger(verbosity),
		Plugins:         sdk.ClientPluginMap(),
		Managed:         true,
		GRPCDialOptions: nil,
	})

	rpcClient, err := client.Client()
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("start plugin client: %w", err)
	}
	raw, err := rpcClient.Dispense("bomly")
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("dispense plugin client: %w", err)
	}
	typed, ok := raw.(sdk.Client)
	if !ok {
		client.Kill()
		return nil, fmt.Errorf("unexpected plugin client type %T", raw)
	}
	return &Client{client: client, raw: typed}, nil
}

func pluginLogger(verbosity int) hclog.Logger {
	if verbosity < 2 {
		return hclog.NewNullLogger()
	}
	return hclog.New(&hclog.LoggerOptions{
		Name:  "plugin",
		Level: hclog.Debug,
	})
}

// Raw returns the typed shared client.
func (c *Client) Raw() sdk.Client {
	if c == nil {
		return nil
	}
	return c.raw
}

// Close terminates the plugin subprocess.
func (c *Client) Close() {
	if c == nil || c.client == nil {
		return
	}
	c.client.Kill()
}
