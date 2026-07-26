package logging

import (
	"reflect"
	"strings"
	"testing"
)

func TestSanitizeArgsRedactsCredentialValuesAndURLUserinfo(t *testing.T) {
	input := []string{
		"install",
		"--token", "plain-token",
		"--password=plain-password",
		"-Drepo.password=maven-password",
		"--registry=https://user:registry-password@example.test/packages",
		"git+https://git-user:git-token@example.test/repo.git",
		"--auth", "auth-secret",
		"--authorization=authorization-secret",
		"--bearer", "bearer-secret",
		"--pat=pat-secret",
		"--passphrase", "passphrase-secret",
		"--pass=pass-secret",
		"--pwd", "pwd-secret",
		"--header", "Authorization: Bearer header-secret",
		"//registry.npmjs.org/:_authToken=npm-secret",
		"--color=always",
		"package-name",
	}
	original := append([]string(nil), input...)

	got := SanitizeArgs(input)

	if !reflect.DeepEqual(input, original) {
		t.Fatalf("SanitizeArgs() mutated input:\nwant %#v\ngot  %#v", original, input)
	}
	for _, secret := range []string{
		"plain-token", "plain-password", "maven-password",
		"registry-password", "git-token", "git-user", "auth-secret",
		"authorization-secret", "bearer-secret", "pat-secret",
		"passphrase-secret", "pass-secret", "pwd-secret", "header-secret",
		"npm-secret",
	} {
		if strings.Contains(strings.Join(got, " "), secret) {
			t.Fatalf("SanitizeArgs() retained %q in %#v", secret, got)
		}
	}
	wantUnchanged := []string{"install", "--token", "--color=always", "package-name"}
	for _, value := range wantUnchanged {
		if !containsArgument(got, value) {
			t.Fatalf("SanitizeArgs() removed reproducible argument %q from %#v", value, got)
		}
	}
	if got[2] != redactedArgument ||
		got[3] != "--password="+redactedArgument ||
		got[4] != "-Drepo.password="+redactedArgument ||
		got[20] != "//registry.npmjs.org/:_authToken="+redactedArgument {
		t.Fatalf("SanitizeArgs() credential forms = %#v", got)
	}
}

func TestSanitizeArgsDoesNotTreatOrdinaryAuthoredFlagsAsCredentials(t *testing.T) {
	input := []string{
		"--author", "example",
		"--user-agent=bomly",
		"--sort-key", "name",
		"--ssh-key=/tmp/id_ed25519.pub",
		"https://example.test/public",
	}
	if got := SanitizeArgs(input); !reflect.DeepEqual(got, input) {
		t.Fatalf("SanitizeArgs() changed ordinary args:\nwant %#v\ngot  %#v", input, got)
	}
}

func TestSanitizeArgsDoesNotTreatPositionalArgumentsAsCredentialFlags(t *testing.T) {
	input := []string{
		"install", "pass", "some-pkg",
		"auth", "another-pkg",
		"token", "final-pkg",
	}
	if got := SanitizeArgs(input); !reflect.DeepEqual(got, input) {
		t.Fatalf("SanitizeArgs() changed positional args:\nwant %#v\ngot  %#v", input, got)
	}
}

func TestSanitizeURLFailsClosedAndDoesNotInspectQueryValues(t *testing.T) {
	if got := SanitizeURL("https://user:%zz@example.test/path"); got != redactedArgument {
		t.Fatalf("SanitizeURL(malformed) = %q, want %q", got, redactedArgument)
	}

	got := SanitizeURL("https://user:password@example.test/path?access_token=query-value")
	if strings.Contains(got, "user") || strings.Contains(got, "password") {
		t.Fatalf("SanitizeURL() retained user information: %q", got)
	}
	if !strings.Contains(got, "access_token=query-value") {
		t.Fatalf("SanitizeURL() unexpectedly changed query values: %q", got)
	}
}

func containsArgument(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
