package assurance

import (
	"bytes"
	"testing"

	testutil "github.com/bomly-dev/bomly-sdk/testkit"
)

func FuzzParseCheckResult(f *testing.F) {
	for _, seed := range []string{
		"",
		"{}",
		`{"schema_version":"bomly.assurance-check/v1","id":"smoke","instance":"go","stage":"prerequisites",` +
			`"level":"gate","status":"pass","summary":"18 of 18 tests passed.","metrics":{"tests_total":18},` +
			`"details":[{"name":"smoke.TestScan","status":"pass","duration_ms":41000}]}`,
		`{"schema_version":"bomly.assurance-check/v1","id":"SMOKE","stage":"whenever","status":"green"}`,
		`{"schema_version":"bomly.assurance-check/v1","id":"smoke","stage":"prerequisites","status":"pass"`,
		`{"schema_version":"bomly.assurance-check/v1","id":"smoke","stage":"prerequisites","status":"pass","summary":"ok"} {}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		first, firstErr := ParseCheckResult(data)
		second, secondErr := ParseCheckResult(data)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("ParseCheckResult changed success state: first=%v second=%v", firstErr, secondErr)
		}
		if firstErr != nil {
			if firstErr.Error() != secondErr.Error() {
				t.Fatalf("ParseCheckResult changed error: first=%v second=%v", firstErr, secondErr)
			}
			return
		}
		if err := first.Validate(); err != nil {
			t.Fatalf("accepted an invalid check result: %v", err)
		}
		encodedFirst, err := first.Encode()
		if err != nil {
			t.Fatalf("encode accepted result: %v", err)
		}
		encodedSecond, err := second.Encode()
		if err != nil {
			t.Fatalf("encode accepted result: %v", err)
		}
		if !bytes.Equal(encodedFirst, encodedSecond) {
			t.Fatal("ParseCheckResult produced different documents for identical input")
		}
		if _, err := ParseCheckResult(encodedFirst); err != nil {
			t.Fatalf("re-parsing an accepted result failed: %v", err)
		}
	})
}

func FuzzParseCatalog(f *testing.F) {
	valid := `{"schema_version":"bomly.assurance-catalog/v1",` +
		`"areas":[{"id":"end-to-end","title":"End to end","description":"Real runs."}],` +
		`"checks":[{"id":"smoke","title":"Smoke","area":"end-to-end","stage":"prerequisites","level":"gate",` +
		`"description":"Runs scans.","source":{"workflow":"smoke.yml","job":"smoke"},` +
		`"proves":["It scans."],"limitations":["One project."]}],` +
		`"evidence":[{"id":"graph-go","title":"Go graph","area":"end-to-end","evidence_level":"release-artifact",` +
		`"check_id":"smoke","inputs":[{"kind":"release","location":"https://example.test"}],` +
		`"reproduce":[["make","smoke"]],"proves":["It resolves."],"limitations":["One toolchain."]}]}`
	for _, seed := range []string{"", "{}", valid, valid[:len(valid)/2], `{"schema_version":"bomly.assurance-catalog/v1","areas":[]}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		first, firstErr := ParseCatalog(data)
		_, secondErr := ParseCatalog(data)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("ParseCatalog changed success state: first=%v second=%v", firstErr, secondErr)
		}
		if firstErr != nil {
			if firstErr.Error() != secondErr.Error() {
				t.Fatalf("ParseCatalog changed error: first=%v second=%v", firstErr, secondErr)
			}
			return
		}
		if err := first.Validate(); err != nil {
			t.Fatalf("accepted an invalid catalog: %v", err)
		}
		// An accepted catalog must always produce a report, whatever it contains.
		BuildReport(first, nil, BuildOptions{Release: Release{Tag: "v0.0.0"}, IncludeEvidence: true})
	})
}

func FuzzParseGoTestEvents(f *testing.F) {
	for _, seed := range []string{
		"",
		`{"Action":"pass","Package":"p","Test":"TestOne","Elapsed":1}`,
		"{\"Action\":\"output\",\"Package\":\"p\",\"Test\":\"TestOne\",\"Output\":\"ok\\n\"}\n" +
			"{\"Action\":\"fail\",\"Package\":\"p\",\"Test\":\"TestOne/sub\",\"Elapsed\":2}\n",
		"# github.com/example\nsyntax error\n",
		"{\"Action\":\"pass\"",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		first, firstErr := ParseGoTestEvents(bytes.NewReader(data), nil)
		second, secondErr := ParseGoTestEvents(bytes.NewReader(data), nil)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("ParseGoTestEvents changed success state: first=%v second=%v", firstErr, secondErr)
		}
		if firstErr != nil {
			return
		}
		if first.Total != second.Total || first.Failed != second.Failed {
			t.Fatal("ParseGoTestEvents produced different counts for identical input")
		}
		base := CheckResult{
			SchemaVersion: CheckSchema, ID: "smoke", Stage: StagePrerequisites, Level: LevelGate,
		}
		result := first.ToCheckResult(base, 0)
		if err := result.Validate(); err != nil {
			t.Fatalf("converted result is invalid: %v", err)
		}
		if len(result.Details) > MaxGoTestDetails {
			t.Fatalf("detail count %d exceeds the cap", len(result.Details))
		}
	})
}
