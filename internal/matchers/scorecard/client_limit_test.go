package scorecard

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type responseRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn responseRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func scorecardResponseClient(status int, size int64, body string) *http.Client {
	return &http.Client{Transport: responseRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    status,
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: size,
			Header:        make(http.Header),
		}, nil
	})}
}

func TestClientRejectsOversizedResponse(t *testing.T) {
	client := NewClient(ClientConfig{
		APIBase:    "https://scorecard.example.test",
		HTTPClient: scorecardResponseClient(http.StatusOK, maxResponseBytes+1, ""),
	})
	_, err := client.FetchProject(context.Background(), "github.com/acme/example")
	if err == nil || !strings.Contains(err.Error(), "4 MiB limit exceeded") {
		t.Fatalf("FetchProject() error = %v", err)
	}
}

func TestClientErrorDoesNotExposeResponseBody(t *testing.T) {
	const privateDetail = "private upstream diagnostic"
	client := NewClient(ClientConfig{
		APIBase:    "https://scorecard.example.test",
		HTTPClient: scorecardResponseClient(http.StatusBadGateway, int64(len(privateDetail)), privateDetail),
	})
	_, err := client.FetchProject(context.Background(), "github.com/acme/example")
	if err == nil || !strings.Contains(err.Error(), "status 502") {
		t.Fatalf("FetchProject() error = %v", err)
	}
	if strings.Contains(err.Error(), privateDetail) {
		t.Fatalf("FetchProject() exposed response body: %v", err)
	}
}
