package mcp

import (
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func TestJSONResultDoesNotExposeEncodingDetails(t *testing.T) {
	result, err := jsonResult(make(chan string))
	if err != nil {
		t.Fatalf("jsonResult() error = %v", err)
	}
	if !result.IsError || len(result.Content) != 1 {
		t.Fatalf("jsonResult() = %#v", result)
	}
	text, ok := result.Content[0].(mcplib.TextContent)
	if !ok {
		t.Fatalf("jsonResult() content type = %T", result.Content[0])
	}
	if text.Text != "encode tool response failed" {
		t.Fatalf("jsonResult() text = %q", text.Text)
	}
}
