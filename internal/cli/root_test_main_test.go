package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bomly/bomly-cli/pkg/system"
)

var (
	testHelperBinDir  string
	fakePluginBinPath string
	fakeGradleBinPath string
	fakeGoBinPath     string
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "bomly-cli-testbin-*")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "create test helper dir: %v\n", err)
		os.Exit(1)
	}
	testHelperBinDir = dir

	if err := buildSharedTestHelpers(dir); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "build shared test helpers: %v\n", err)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}

	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func buildSharedTestHelpers(dir string) error {
	npmPath := filepath.Join(dir, executableName("npm"))
	if err := buildHelperBinary(dir, npmPath, fakeNPMSource()); err != nil {
		return err
	}

	gradlePath := filepath.Join(dir, executableName("gradle"))
	if err := buildHelperBinary(dir, gradlePath, fakeGradleSource()); err != nil {
		return err
	}
	fakeGradleBinPath = gradlePath

	goPath := filepath.Join(dir, executableName("go"))
	if err := buildHelperBinary(dir, goPath, fakeGoSource()); err != nil {
		return err
	}
	fakeGoBinPath = goPath

	pluginPath := filepath.Join(dir, executableName("bomly-fake-helper"))
	if err := buildHelperBinary(dir, pluginPath, fakePluginSource()); err != nil {
		return err
	}
	fakePluginBinPath = pluginPath
	return nil
}

func executableName(base string) string {
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	return base
}

func fakePluginSource() string {
	return `package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type cmd struct {
	Name string ` + "`json:\"name\"`" + `
	Summary string ` + "`json:\"summary\"`" + `
}

type meta struct {
	Name string ` + "`json:\"name\"`" + `
	Version string ` + "`json:\"version\"`" + `
	Protocol string ` + "`json:\"protocol\"`" + `
	Commands []cmd ` + "`json:\"commands\"`" + `
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--bomly-plugin-info" {
		_ = json.NewEncoder(os.Stdout).Encode(meta{
			Name: "fake",
			Version: "0.1.0",
			Protocol: "v1",
			Commands: []cmd{{Name: "deps", Summary: "fake deps"}},
		})
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "deps" {
		fmt.Printf("{\"cmd\":\"deps\",\"protocol\":\"%s\",\"core\":\"%s\"}\n", os.Getenv("BOMLY_PROTOCOL"), os.Getenv("BOMLY_CORE_VERSION"))
		return
	}

	fmt.Fprintln(os.Stderr, "unknown command")
	os.Exit(2)
}
`
}

func fakeNPMSource() string {
	return `package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "ls" {
		fmt.Fprintln(os.Stderr, "unsupported command")
		os.Exit(1)
	}

	if os.Getenv("BOMLY_FAKE_NPM_MODE") == "dynamic" {
		raw, err := os.ReadFile("package.json")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		content := string(raw)
		if strings.Contains(content, "\"react\": \"19.0.0\"") {
			fmt.Print("{\"name\":\"demo-app\",\"version\":\"1.0.0\",\"dependencies\":{\"react\":{\"version\":\"19.0.0\"},\"zod\":{\"version\":\"3.23.0\"}}}")
			return
		}
		fmt.Print("{\"name\":\"demo-app\",\"version\":\"1.0.0\",\"dependencies\":{\"react\":{\"version\":\"18.2.0\"}}}")
		return
	}

	fmt.Print(os.Getenv("BOMLY_FAKE_NPM_JSON"))
}
`
}

func fakeGradleSource() string {
	return `package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	for _, arg := range os.Args[1:] {
		if arg == "dependencies" {
			if os.Getenv("BOMLY_FAKE_GRADLE_FAIL") == "1" {
				fmt.Fprintln(os.Stderr, "unexpected gradle fallback invocation")
				os.Exit(23)
			}
			if outputFile := os.Getenv("BOMLY_FAKE_GRADLE_OUTPUT_FILE"); outputFile != "" {
				data, err := os.ReadFile(outputFile)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				fmt.Print(string(data))
				return
			}
			fmt.Print(os.Getenv("BOMLY_FAKE_GRADLE_OUTPUT"))
			return
		}
	}
	fmt.Fprintf(os.Stderr, "unsupported command: %s\n", strings.Join(os.Args[1:], " "))
	os.Exit(1)
}
`
}

func fakeGoSource() string {
	return `package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	args := os.Args[1:]
	if len(args) == 2 && args[0] == "mod" && args[1] == "graph" {
		fmt.Print(os.Getenv("BOMLY_FAKE_GO_GRAPH_OUTPUT"))
		return
	}
	fmt.Fprintf(os.Stderr, "unsupported command: %s\n", strings.Join(args, " "))
	os.Exit(1)
}
`
}

func copyExecutableFile(dst, src string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		return os.Chmod(dst, 0o755)
	}
	return nil
}

func buildHelperBinary(dir, outputPath, source string) error {
	srcPath := filepath.Join(dir, filepath.Base(outputPath)+".go")
	if err := os.WriteFile(srcPath, []byte(source), 0o644); err != nil {
		return err
	}
	buildCmd := system.Command("go", "build", "-o", outputPath, srcPath)
	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go build failed: %w (%s)", err, string(buildOutput))
	}
	return nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
