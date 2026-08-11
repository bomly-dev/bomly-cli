package plugin

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	plugschema "github.com/bomly-dev/bomly-sdk"
)

type fakePooledClient struct {
	exited atomic.Bool
	closed atomic.Bool
}

func (f *fakePooledClient) Raw() plugschema.Client { return nil }
func (f *fakePooledClient) Exited() bool           { return f.exited.Load() }
func (f *fakePooledClient) Close()                 { f.closed.Store(true) }

func poolWithFakeStart(t *testing.T, starts *atomic.Int32, clients *[]*fakePooledClient) *ClientPool {
	t.Helper()
	var mu sync.Mutex
	pool := NewClientPool()
	pool.startFn = func(_ context.Context, _, _ string, _ plugschema.PluginKind) (pooledClient, error) {
		starts.Add(1)
		client := &fakePooledClient{}
		mu.Lock()
		*clients = append(*clients, client)
		mu.Unlock()
		return client, nil
	}
	return pool
}

func TestClientPoolConcurrentAcquireStartsOneSubprocess(t *testing.T) {
	var starts atomic.Int32
	var clients []*fakePooledClient
	pool := poolWithFakeStart(t, &starts, &clients)

	const workers = 16
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := pool.Acquire(context.Background(), "/bin/fake", "acme.plugin", ""); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("Acquire() error = %v", err)
	}
	if got := starts.Load(); got != 1 {
		t.Fatalf("expected exactly one subprocess start, got %d", got)
	}
}

func TestClientPoolRestartsDeadSubprocessOnce(t *testing.T) {
	var starts atomic.Int32
	var clients []*fakePooledClient
	pool := poolWithFakeStart(t, &starts, &clients)
	ctx := context.Background()

	if _, err := pool.Acquire(ctx, "/bin/fake", "acme.plugin", ""); err != nil {
		t.Fatalf("first Acquire() error = %v", err)
	}
	// Kill the subprocess: the next Acquire must close it and restart once.
	clients[0].exited.Store(true)
	if _, err := pool.Acquire(ctx, "/bin/fake", "acme.plugin", ""); err != nil {
		t.Fatalf("Acquire() after death error = %v", err)
	}
	if !clients[0].closed.Load() {
		t.Fatal("expected dead client to be closed before restart")
	}
	if got := starts.Load(); got != 2 {
		t.Fatalf("expected exactly one restart, got %d starts", got)
	}

	// A second death exhausts the restart budget and persists the error.
	clients[1].exited.Store(true)
	if _, err := pool.Acquire(ctx, "/bin/fake", "acme.plugin", ""); err == nil || !strings.Contains(err.Error(), "not restarting again") {
		t.Fatalf("expected persisted restart-budget error, got %v", err)
	}
	if _, err := pool.Acquire(ctx, "/bin/fake", "acme.plugin", ""); err == nil || !strings.Contains(err.Error(), "not restarting again") {
		t.Fatalf("expected persisted error on later Acquire, got %v", err)
	}
	if got := starts.Load(); got != 2 {
		t.Fatalf("expected no further starts after budget exhaustion, got %d", got)
	}
}

func TestClientPoolShutdownClosesClients(t *testing.T) {
	var starts atomic.Int32
	var clients []*fakePooledClient
	pool := poolWithFakeStart(t, &starts, &clients)

	if _, err := pool.Acquire(context.Background(), "/bin/fake", "acme.one", ""); err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if _, err := pool.Acquire(context.Background(), "/bin/fake-two", "acme.two", ""); err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	pool.Shutdown()
	for idx, client := range clients {
		if !client.closed.Load() {
			t.Fatalf("expected Shutdown to close client %d", idx)
		}
	}
}
