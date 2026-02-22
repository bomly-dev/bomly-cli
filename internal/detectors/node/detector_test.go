package node

import "testing"

func TestDepGraphFromNPMJSON(t *testing.T) {
	raw := []byte(`{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "react": {
      "version": "18.2.0",
      "dependencies": {
        "loose-envify": {
          "version": "1.4.0"
        }
      }
    },
    "zod": {
      "version": "3.23.0"
    }
  }
}`)

	g, err := depGraphFromNPMJSON(raw)
	if err != nil {
		t.Fatalf("depGraphFromNPMJSON() error = %v", err)
	}
	if g.Size() != 4 {
		t.Fatalf("expected 4 packages, got %d", g.Size())
	}
}

func TestDepGraphFromPNPMJSON(t *testing.T) {
	raw := []byte(`[
  {
    "name": "demo-app",
    "version": "1.0.0",
    "dependencies": {
      "react": {
        "version": "18.2.0",
        "dependencies": {
          "loose-envify": {
            "version": "1.4.0"
          }
        }
      }
    }
  }
]`)

	g, err := depGraphFromPNPMJSON(raw)
	if err != nil {
		t.Fatalf("depGraphFromPNPMJSON() error = %v", err)
	}
	if g.Size() != 3 {
		t.Fatalf("expected 3 packages, got %d", g.Size())
	}
}

func TestDepGraphFromYarnJSON(t *testing.T) {
	raw := []byte(`{"type":"tree","data":{"type":"list","trees":[{"name":"react@18.2.0","children":[{"name":"loose-envify@1.4.0","children":[]}]}]}}`)

	g, err := depGraphFromYarnJSON(raw)
	if err != nil {
		t.Fatalf("depGraphFromYarnJSON() error = %v", err)
	}
	if g.Size() != 3 {
		t.Fatalf("expected 3 packages, got %d", g.Size())
	}
}
