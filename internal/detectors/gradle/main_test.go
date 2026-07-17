package gradle

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/system"
)

// TestMain builds the package's fake gradle and java executables once, per
// the repo convention that fake binaries are built in TestMain (see
// internal/cli/root_cmd_test.go for the reference pattern). Per-test behavior
// is parameterized through BOMLY_FAKE_GRADLE_* / BOMLY_FAKE_JAVA_*
// environment variables, which the spawned processes inherit via t.Setenv.
var (
	fakeGradleBinPath string
	fakeJavaBinPath   string
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "bomly-gradle-testbin-*")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "create test helper dir: %v\n", err)
		os.Exit(1)
	}

	fakeGradleBinPath = filepath.Join(dir, executableName("gradle"))
	fakeJavaBinPath = filepath.Join(dir, executableName("java"))
	if err := buildHelperBinary(fakeGradleBinPath, fakeGradleSource()); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "build fake gradle: %v\n", err)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	if err := buildHelperBinary(fakeJavaBinPath, fakeJavaSource()); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "build fake java: %v\n", err)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}

	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func buildHelperBinary(outputPath, source string) error {
	srcDir, err := os.MkdirTemp("", "bomly-gradle-fakesrc-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(srcDir) }()

	srcPath := filepath.Join(srcDir, "main.go")
	if err := os.WriteFile(srcPath, []byte(source), 0o644); err != nil {
		return err
	}
	buildCmd := system.Command("go", "build", "-o", outputPath, srcPath)
	buildCmd.Env = append(os.Environ(), "GOFLAGS=-modcacherw")
	if buildOutput, err := buildCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build failed: %w (%s)", err, string(buildOutput))
	}
	return nil
}

func executableName(base string) string {
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	return base
}

// fakeGradleSource is the fake gradle executable. It records its argument
// list when BOMLY_FAKE_GRADLE_ARGS_FILE is set, fails when the arguments
// contain BOMLY_FAKE_GRADLE_FAIL_ON, and prints the report named by
// BOMLY_FAKE_GRADLE_FIXTURE on success.
func fakeGradleSource() string {
	return `package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	args := strings.Join(os.Args[1:], " ")
	if argsFile := os.Getenv("BOMLY_FAKE_GRADLE_ARGS_FILE"); argsFile != "" {
		f, err := os.OpenFile(argsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			_, _ = fmt.Fprintln(f, args)
			_ = f.Close()
		}
	}
	if failOn := os.Getenv("BOMLY_FAKE_GRADLE_FAIL_ON"); failOn != "" && strings.Contains(args, failOn) {
		fmt.Fprintf(os.Stderr, "task %q not found\n", failOn)
		os.Exit(1)
	}
	if fixture := os.Getenv("BOMLY_FAKE_GRADLE_FIXTURE"); fixture != "" {
		raw, err := os.ReadFile(fixture)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		_, _ = os.Stdout.Write(raw)
		return
	}
	fmt.Fprintln(os.Stderr, "ok")
}
`
}

func fakeJavaSource() string {
	return `package main

import (
	"fmt"
	"os"
)

func main() {
	if os.Getenv("BOMLY_FAKE_JAVA_FAIL") == "1" {
		fmt.Fprintln(os.Stderr, "The operation couldn't be completed. Unable to locate a Java Runtime.")
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "openjdk version \"21-test\"")
}
`
}

// fakeToolDir copies the requested TestMain-built fakes ("gradle", "java")
// into a fresh directory suitable for t.Setenv("PATH", ...).
func fakeToolDir(t *testing.T, tools ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, tool := range tools {
		var src string
		switch tool {
		case "gradle":
			src = fakeGradleBinPath
		case "java":
			src = fakeJavaBinPath
		default:
			t.Fatalf("unknown fake tool %q", tool)
		}
		copyExecutable(t, src, filepath.Join(dir, executableName(tool)))
	}
	return dir
}

func copyExecutable(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("open %s: %v", src, err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatalf("create %s: %v", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		t.Fatalf("copy %s: %v", dst, err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close %s: %v", dst, err)
	}
}

// fakeGradleReportFixture writes a dependency report for the fake gradle to
// print and returns its path for BOMLY_FAKE_GRADLE_FIXTURE.
func fakeGradleReportFixture(t *testing.T, report string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gradle-report.txt")
	if err := os.WriteFile(path, []byte(report), 0o644); err != nil {
		t.Fatalf("write gradle report fixture: %v", err)
	}
	return path
}

const fakeGradleSingleReport = "runtimeClasspath - Runtime classpath of source set 'main'.\n\\--- org.springframework:spring-core:6.1.1\n"
