package jvmreach

import (
	"bytes"
	"reflect"
	"testing"

	testutil "github.com/bomly-dev/bomly-sdk/testkit"
)

func FuzzScanImports(f *testing.F) {
	for _, seed := range []string{
		"",
		"import java.util.List;\nimport com.fasterxml.jackson.databind.ObjectMapper;\n",
		"/* block\nimport hidden.In.Comment;\n*/\nimport real.Thing; // tail\n",
		"package com.example;\nimport static org.junit.Assert.assertTrue;\nimport scala.collection.mutable._\n",
		"import unterminated\n/* open comment\nimport swallowed\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		first, firstErr := scanImports(bytes.NewReader(data))
		second, secondErr := scanImports(bytes.NewReader(data))
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("scan changed success state: first=%v second=%v", firstErr, secondErr)
		}
		if firstErr != nil {
			return
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatal("scan changed result for identical input")
		}
	})
}
