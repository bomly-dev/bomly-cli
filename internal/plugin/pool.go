package plugin

import (
	"context"
	"fmt"
	"sync"

	plugschema "github.com/bomly-dev/bomly-sdk"
)

// pooledClient is the subset of runtimeClient the pool needs. It exists so
// tests can substitute fakes without launching real subprocesses.
type pooledClient interface {
	Raw() plugschema.Client
	Exited() bool
	Close()
}

// maxPoolRestarts bounds subprocess restarts per plugin per pool lifetime.
const maxPoolRestarts = 1

// ClientPool keeps one live managed-plugin subprocess per plugin ID so
// repeated component calls within a command reuse a warm process instead of
// paying a full handshake per RPC.
type ClientPool struct {
	mu      sync.Mutex
	entries map[string]*poolEntry
	// startFn launches a subprocess; overridable in tests.
	startFn func(ctx context.Context, executable, pluginID string, kind plugschema.PluginKind) (pooledClient, error)
}

type poolEntry struct {
	mu       sync.Mutex
	client   pooledClient
	restarts int
	err      error
}

// NewClientPool creates an empty plugin subprocess pool.
func NewClientPool() *ClientPool {
	return &ClientPool{
		entries: make(map[string]*poolEntry),
		startFn: func(ctx context.Context, executable, pluginID string, kind plugschema.PluginKind) (pooledClient, error) {
			return startPlugin(ctx, executable, pluginID, kind)
		},
	}
}

// Acquire returns a live client for the plugin, starting the subprocess on
// first use and restarting it at most once per pool lifetime when it died.
// The returned client is shared: callers must not close it; the pool owns the
// subprocess until Shutdown.
func (p *ClientPool) Acquire(ctx context.Context, executable, pluginID string, kind plugschema.PluginKind) (plugschema.Client, error) {
	if p == nil {
		return nil, fmt.Errorf("plugin client pool is nil")
	}
	p.mu.Lock()
	if p.entries == nil {
		p.entries = make(map[string]*poolEntry)
	}
	entry, ok := p.entries[pluginID]
	if !ok {
		entry = &poolEntry{}
		p.entries[pluginID] = entry
	}
	p.mu.Unlock()

	// The entry mutex is held only for start and liveness checks, never
	// across RPCs: gRPC connections are safe for concurrent use.
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.err != nil {
		return nil, entry.err
	}
	if entry.client != nil {
		if !entry.client.Exited() {
			return entry.client.Raw(), nil
		}
		entry.client.Close()
		entry.client = nil
		entry.restarts++
		if entry.restarts > maxPoolRestarts {
			entry.err = fmt.Errorf("plugin %s subprocess exited after %d restarts; not restarting again", pluginID, maxPoolRestarts)
			return nil, entry.err
		}
	}
	client, err := p.startFn(ctx, executable, pluginID, kind)
	if err != nil {
		return nil, fmt.Errorf("start pooled plugin %s: %w", pluginID, err)
	}
	entry.client = client
	return client.Raw(), nil
}

// Shutdown terminates every pooled subprocess and runs config-file cleanups.
// The pool remains usable afterwards, but callers are expected to drop it.
func (p *ClientPool) Shutdown() {
	if p == nil {
		return
	}
	p.mu.Lock()
	entries := p.entries
	p.entries = make(map[string]*poolEntry)
	p.mu.Unlock()
	for _, entry := range entries {
		entry.mu.Lock()
		if entry.client != nil {
			entry.client.Close()
			entry.client = nil
		}
		entry.mu.Unlock()
	}
}
