package python

import "testing"

func TestDepGraphFromPipInspect(t *testing.T) {
	raw := []byte(`{
  "installed": [
    {
      "metadata": {
        "name": "demo-app",
        "version": "1.0.0",
        "requires_dist": ["requests>=2", "uvicorn; extra == 'server'"]
      },
      "requested": true,
      "requested_by": []
    },
    {
      "metadata": {
        "name": "requests",
        "version": "2.32.0",
        "requires_dist": ["certifi>=2024.0.0"]
      },
      "requested": false,
      "requested_by": ["demo-app"]
    },
    {
      "metadata": {
        "name": "certifi",
        "version": "2024.2.2",
        "requires_dist": []
      },
      "requested": false,
      "requested_by": ["requests"]
    }
  ]
}`)

	g, err := depGraphFromPipInspect(raw)
	if err != nil {
		t.Fatalf("depGraphFromPipInspect() error = %v", err)
	}
	if g.Size() != 4 {
		t.Fatalf("expected 4 packages, got %d", g.Size())
	}
}
