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
		"registry-password", "git-token", "git-user",
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
		got[4] != "-Drepo.password="+redactedArgument {
		t.Fatalf("SanitizeArgs() credential forms = %#v", got)
	}
}

func TestSanitizeArgsDoesNotTreatOrdinaryAuthoredFlagsAsCredentials(t *testing.T) {
	input := []string{"--author", "example", "--user-agent=bomly", "https://example.test/public"}
	if got := SanitizeArgs(input); !reflect.DeepEqual(got, input) {
		t.Fatalf("SanitizeArgs() changed ordinary args:\nwant %#v\ngot  %#v", input, got)
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
