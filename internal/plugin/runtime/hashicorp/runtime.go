package hashicorp

import (
	"context"
	"fmt"
	"os/exec"

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
	client := hplugin.NewClient(&hplugin.ClientConfig{
		HandshakeConfig:  sdk.HandshakeConfig(),
		AllowedProtocols: []hplugin.Protocol{hplugin.ProtocolGRPC},
		Cmd:              cmd,
		Logger:           pluginLogger(verbosity),
		Plugins:          sdk.ClientPluginMap(),
		Managed:          true,
		GRPCDialOptions:  nil,
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
	if verbosity <= 0 {
		return hclog.NewNullLogger()
	}
	level := hclog.Info
	if verbosity >= 2 {
		level = hclog.Debug
	}
	return hclog.New(&hclog.LoggerOptions{
		Name:  "plugin",
		Level: level,
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
