package main

import (
	"encoding/json"
	"math"
	"testing"
)

func TestNormalizeOutputRemovesOnlyVolatileJSONFields(t *testing.T) {
	first := normalizeOutput([]byte(`{"generated_at":"one","project":{"name":"demo"},"items":[{"timestamp":"one","id":"a"}]}`))
	second := normalizeOutput([]byte(`{"generated_at":"two","project":{"name":"demo"},"items":[{"timestamp":"two","id":"a"}]}`))
	if string(first) != string(second) {
		t.Fatalf("normalized outputs differ:\n%s\n%s", first, second)
	}
	var value map[string]any
	if err := json.Unmarshal(first, &value); err != nil {
		t.Fatal(err)
	}
	if _, exists := value["generated_at"]; exists {
		t.Fatal("generated_at survived normalization")
	}
}

func TestSummarizeModesReportsMedianDispersionAndConfidenceInterval(t *testing.T) {
	samples := []sample{
		{Mode: "cold", StageTimingsMS: map[string]float64{"command": 10}, StdoutBytes: 100, PeakMemoryBytes: 1000},
		{Mode: "cold", StageTimingsMS: map[string]float64{"command": 20}, StdoutBytes: 200, PeakMemoryBytes: 3000},
		{Mode: "cold", StageTimingsMS: map[string]float64{"command": 30}, StdoutBytes: 300, PeakMemoryBytes: 2000},
	}
	summary := summarizeModes(samples)
	if len(summary) != 1 {
		t.Fatalf("summary count = %d", len(summary))
	}
	got := summary[0]
	if got.MedianMS != 20 || got.MeanMS != 20 || got.MedianAbsoluteDevMS != 10 ||
		got.PeakMemoryBytes != 3000 || got.MedianOutputBytes != 200 {
		t.Fatalf("unexpected summary: %#v", got)
	}
	if got.StandardDeviationMS != 10 {
		t.Fatalf("standard deviation = %f", got.StandardDeviationMS)
	}
	if got.ConfidenceInterval95[0] >= got.MeanMS || got.ConfidenceInterval95[1] <= got.MeanMS {
		t.Fatalf("confidence interval does not contain mean: %#v", got.ConfidenceInterval95)
	}
}

func TestEvaluateGatesUsesNormalizedHashesAndStableCaps(t *testing.T) {
	samples := []sample{
		{Mode: "cold", ExitCode: 0, NormalizedSHA256: "same", StdoutBytes: 90},
		{Mode: "cold", ExitCode: 0, NormalizedSHA256: "same", StdoutBytes: 100},
		{Mode: "warm", ExitCode: 0, NormalizedSHA256: "warm", StdoutBytes: 95},
	}
	if gate := evaluateGates(samples, 100); !gate.Passed {
		t.Fatalf("stable samples failed: %#v", gate)
	}
	samples[1].NormalizedSHA256 = "changed"
	if gate := evaluateGates(samples, 100); gate.Passed || gate.NormalizedOutputStable {
		t.Fatalf("unstable output passed: %#v", gate)
	}
	samples[1].NormalizedSHA256 = "same"
	samples[1].StdoutBytes = 101
	if gate := evaluateGates(samples, 100); gate.Passed || gate.OutputCapPassed {
		t.Fatalf("oversized output passed: %#v", gate)
	}
}

func TestMedianHandlesEvenAndEmptyInputs(t *testing.T) {
	if median(nil) != 0 || median([]float64{4, 2}) != 3 {
		t.Fatal("median boundary behavior changed")
	}
	if mean, deviation := meanAndDeviation([]float64{7}); mean != 7 || math.Abs(deviation) > 0 {
		t.Fatalf("single sample statistics = %f, %f", mean, deviation)
	}
}
