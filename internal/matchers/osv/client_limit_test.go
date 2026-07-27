package osv

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func oversizedClientResponse(status int, size int64, body string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    status,
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: size,
			Header:        make(http.Header),
		}, nil
	})}
}

func TestClientRejectsOversizedVulnerabilityResponse(t *testing.T) {
	client := NewClient(ClientConfig{
		APIBase:    "https://osv.example.test",
		HTTPClient: oversizedClientResponse(http.StatusOK, maxVulnerabilityResponseBytes+1, ""),
	})
	_, err := client.GetVuln("OSV-1")
	if err == nil || !strings.Contains(err.Error(), "4 MiB limit exceeded") {
		t.Fatalf("GetVuln() error = %v", err)
	}
}

func TestClientRejectsOversizedBatchResponse(t *testing.T) {
	client := NewClient(ClientConfig{
		APIBase:    "https://osv.example.test",
		HTTPClient: oversizedClientResponse(http.StatusOK, maxBatchResponseBytes+1, ""),
	})
	_, err := client.QueryBatch([]BatchQuery{{}})
	if err == nil || !strings.Contains(err.Error(), "64 MiB limit exceeded") {
		t.Fatalf("QueryBatch() error = %v", err)
	}
}

func TestFetchKEVCatalogRejectsOversizedResponse(t *testing.T) {
	client := oversizedClientResponse(http.StatusOK, maxKEVResponseBytes+1, "")
	_, err := FetchKEVCatalog(nil, client)
	if err == nil || !strings.Contains(err.Error(), "32 MiB limit exceeded") {
		t.Fatalf("FetchKEVCatalog() error = %v", err)
	}
}

func TestOSVAndKEVErrorsDoNotExposeResponseBodies(t *testing.T) {
	const privateDetail = "private upstream diagnostic"
	t.Run("vulnerability", func(t *testing.T) {
		client := NewClient(ClientConfig{
			APIBase:    "https://osv.example.test",
			HTTPClient: oversizedClientResponse(http.StatusBadGateway, int64(len(privateDetail)), privateDetail),
		})
		_, err := client.GetVuln("OSV-1")
		requireStatusWithoutBody(t, err, "status 502", privateDetail)
	})
	t.Run("batch", func(t *testing.T) {
		client := NewClient(ClientConfig{
			APIBase:    "https://osv.example.test",
			HTTPClient: oversizedClientResponse(http.StatusBadGateway, int64(len(privateDetail)), privateDetail),
		})
		_, err := client.QueryBatch([]BatchQuery{{}})
		requireStatusWithoutBody(t, err, "status 502", privateDetail)
	})
	t.Run("kev", func(t *testing.T) {
		client := oversizedClientResponse(http.StatusBadGateway, int64(len(privateDetail)), privateDetail)
		_, err := FetchKEVCatalog(nil, client)
		requireStatusWithoutBody(t, err, "status 502", privateDetail)
	})
}

func requireStatusWithoutBody(t *testing.T, err error, status, body string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), status) {
		t.Fatalf("error = %v, want %q", err, status)
	}
	if strings.Contains(err.Error(), body) {
		t.Fatalf("error exposed response body: %v", err)
	}
}
