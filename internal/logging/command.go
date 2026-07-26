package logging

import (
	"net/url"
	"os"
	"strings"
	"unicode"

	"go.uber.org/zap"
)

const redactedArgument = "[REDACTED]"

// SanitizeArgs returns a copy of args with credential values and URL user
// information removed. Non-secret arguments remain unchanged so DEBUG logs can
// still reproduce the command.
func SanitizeArgs(args []string) []string {
	sanitized := make([]string, len(args))
	redactNext := false
	for index, argument := range args {
		if redactNext {
			sanitized[index] = redactedArgument
			redactNext = false
			continue
		}
		if flag, value, found := strings.Cut(argument, "="); found {
			if sensitiveFlag(flag) {
				sanitized[index] = flag + "=" + redactedArgument
				continue
			}
			sanitized[index] = flag + "=" + redactURLUserinfo(value)
			continue
		}
		if strings.Contains(argument, "://") {
			sanitized[index] = redactURLUserinfo(argument)
			continue
		}
		if sensitiveFlag(argument) {
			sanitized[index] = argument
			redactNext = true
			continue
		}
		sanitized[index] = redactURLUserinfo(argument)
	}
	return sanitized
}

// CommandFields returns the standard secret-safe DEBUG fields for a subprocess.
// Args are sanitized. The executable must be a resolved binary path or name,
// not a command string containing arguments or credentials.
func CommandFields(executable string, args []string, workingDir string) []zap.Field {
	if strings.TrimSpace(workingDir) == "" {
		if current, err := os.Getwd(); err == nil {
			workingDir = current
		}
	}
	return []zap.Field{
		zap.String("executable", executable),
		zap.Strings("args", SanitizeArgs(args)),
		zap.String("working_dir", workingDir),
	}
}

// SanitizeURL removes user information from a URL before it is logged. It
// fails closed when URL parsing fails. Query values are not inspected, so
// callers must not use this helper as a general query-string redactor.
func SanitizeURL(value string) string {
	if !strings.Contains(value, "://") {
		return value
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return redactedArgument
	}
	parsed.User = nil
	return parsed.String()
}

func sensitiveFlag(value string) bool {
	if value == "" {
		return false
	}
	parts := strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	for _, part := range parts {
		switch part {
		case "password", "passwd", "token", "authtoken", "secret",
			"credential", "credentials", "apikey", "username", "login",
			"auth", "authorization", "bearer", "pat", "passphrase", "pass",
			"pwd", "header":
			return true
		}
	}
	return len(parts) == 1 && parts[0] == "key"
}

func redactURLUserinfo(value string) string {
	if !strings.Contains(value, "://") {
		return value
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return redactedArgument
	}
	if parsed.User == nil {
		return value
	}
	parsed.User = url.User(redactedArgument)
	return parsed.String()
}
