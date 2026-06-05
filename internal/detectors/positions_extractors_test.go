package detectors_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors/cargo"
	"github.com/bomly-dev/bomly-cli/internal/detectors/cocoapods"
	"github.com/bomly-dev/bomly-cli/internal/detectors/composer"
	"github.com/bomly-dev/bomly-cli/internal/detectors/gradle"
	"github.com/bomly-dev/bomly-cli/internal/detectors/maven"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/npm"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/pnpm"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/yarn"
	"github.com/bomly-dev/bomly-cli/internal/detectors/ruby"
	"github.com/bomly-dev/bomly-cli/internal/detectors/sbt"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustPkg(t *testing.T, g *sdk.Graph, name, version string, extra ...func(*sdk.Dependency)) *sdk.Dependency {
	t.Helper()
	d := sdk.Dependency{Name: name, Version: version, Ecosystem: "test"}
	for _, f := range extra {
		f(&d)
	}
	dep := sdk.NewDependency(d)
	if err := g.AddNode(dep); err != nil {
		t.Fatal(err)
	}
	return dep
}

func TestRubyGemfileLockPositions(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Gemfile.lock", `GEM
  remote: https://rubygems.org/
  specs:
    activesupport (8.0.0)
      i18n (~> 1.6)
    nokogiri (1.16.0)
    rack (3.0.6)

PLATFORMS
  ruby
`)
	g := sdk.New()
	for _, n := range []string{"activesupport", "nokogiri", "rack", "unimported"} {
		mustPkg(t, g, n, "1.0")
	}
	ruby.AttachGemfileLockPositions(g, filepath.Join(dir, "Gemfile.lock"), dir)
	expect := map[string]int{"activesupport": 4, "nokogiri": 6, "rack": 7}
	for name, wantLine := range expect {
		p, _ := g.Node(name + "@1.0")
		if p == nil {
			t.Fatalf("missing %s", name)
		}
		if len(p.Locations) != 1 {
			t.Fatalf("%s Locations = %d, want 1", name, len(p.Locations))
		}
		if p.Locations[0].Position == nil || p.Locations[0].Position.Line != wantLine {
			t.Errorf("%s Position = %+v, want line %d", name, p.Locations[0].Position, wantLine)
		}
	}
	un, _ := g.Node("unimported@1.0")
	if un != nil && len(un.Locations) > 0 {
		t.Errorf("unimported should have no Locations; got %v", un.Locations)
	}
}

func TestNpmPackageLockPositions(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package-lock.json", `{
  "name": "demo",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "demo"
    },
    "node_modules/lodash": {
      "version": "4.17.21"
    },
    "node_modules/@scope/pkg": {
      "version": "1.0.0"
    },
    "node_modules/foo/node_modules/lodash": {
      "version": "3.10.1"
    }
  }
}
`)
	g := sdk.New()
	mustPkg(t, g, "lodash", "4.17.21")
	mustPkg(t, g, "@scope/pkg", "1.0.0")
	npm.AttachPackageLockPositions(g, dir)

	lodash, _ := g.Node("lodash@4.17.21")
	if lodash == nil || len(lodash.Locations) == 0 {
		t.Fatal("lodash missing Location")
	}
	if lodash.Locations[0].Position.Line != 8 {
		t.Errorf("lodash line = %d, want 8", lodash.Locations[0].Position.Line)
	}

	scoped, _ := g.Node("@scope/pkg@1.0.0")
	if scoped == nil || len(scoped.Locations) == 0 {
		t.Fatal("scoped pkg missing Location")
	}
	if scoped.Locations[0].Position.Line != 11 {
		t.Errorf("scoped pkg line = %d, want 11", scoped.Locations[0].Position.Line)
	}
}

func TestPnpmLockPositions(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pnpm-lock.yaml", `lockfileVersion: '6.0'

importers:
  .:
    dependencies:
      foo: 1.0.0

packages:

  /foo@1.0.0:
    resolution: {integrity: sha512-xxx}

  '/bar@2.0.0(peer@3.0.0)':
    resolution: {integrity: sha512-yyy}
`)
	g := sdk.New()
	mustPkg(t, g, "foo", "1.0.0")
	mustPkg(t, g, "bar", "2.0.0")
	pnpm.AttachPnpmLockPositions(g, dir)
	for _, c := range []struct {
		name string
		line int
	}{{"foo", 10}, {"bar", 13}} {
		p, _ := g.Node(c.name + "@" + (map[string]string{"foo": "1.0.0", "bar": "2.0.0"})[c.name])
		if p == nil || len(p.Locations) == 0 {
			t.Fatalf("%s missing Location", c.name)
		}
		if p.Locations[0].Position.Line != c.line {
			t.Errorf("%s line = %d, want %d", c.name, p.Locations[0].Position.Line, c.line)
		}
	}
}

func TestYarnLockPositions(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "yarn.lock", `# yarn lockfile v1

"@scope/pkg@^1.0.0":
  version "1.0.0"

lodash@^4.0.0, lodash@^4.17.0:
  version "4.17.21"
`)
	g := sdk.New()
	mustPkg(t, g, "@scope/pkg", "1.0.0")
	mustPkg(t, g, "lodash", "4.17.21")
	yarn.AttachYarnLockPositions(g, dir)
	scoped, _ := g.Node("@scope/pkg@1.0.0")
	if scoped == nil || len(scoped.Locations) == 0 || scoped.Locations[0].Position.Line != 3 {
		t.Errorf("@scope/pkg location wrong: %+v", scoped.Locations)
	}
	lod, _ := g.Node("lodash@4.17.21")
	if lod == nil || len(lod.Locations) == 0 || lod.Locations[0].Position.Line != 6 {
		t.Errorf("lodash location wrong: %+v", lod.Locations)
	}
}

func TestMavenPomPositions(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pom.xml", `<project>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.17.0</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
    </dependency>
  </dependencies>
</project>
`)
	g := sdk.New()
	mustPkg(t, g, "jackson-databind", "2.17.0", func(p *sdk.Dependency) { p.Org = "com.fasterxml.jackson.core" })
	mustPkg(t, g, "junit", "4.13.2", func(p *sdk.Dependency) { p.Org = "junit" })
	maven.AttachPomPositions(g, dir)
	jd, _ := g.Node("com.fasterxml.jackson.core:jackson-databind@2.17.0")
	if jd == nil || len(jd.Locations) == 0 || jd.Locations[0].Position.Line != 5 {
		t.Errorf("jackson-databind location wrong: %+v", jd)
	}
	ju, _ := g.Node("junit:junit@4.13.2")
	if ju == nil || len(ju.Locations) == 0 || ju.Locations[0].Position.Line != 10 {
		t.Errorf("junit location wrong: %+v", ju)
	}
}

func TestGradlePositions(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "build.gradle", `dependencies {
    implementation 'com.fasterxml.jackson.core:jackson-databind:2.17.0'
    implementation("org.springframework:spring-core:6.0.0")
    testImplementation group: 'junit', name: 'junit', version: '4.13.2'
}
`)
	g := sdk.New()
	mustPkg(t, g, "jackson-databind", "2.17.0")
	mustPkg(t, g, "spring-core", "6.0.0")
	mustPkg(t, g, "junit", "4.13.2")
	gradle.AttachGradlePositions(g, dir)

	cases := map[string]int{"jackson-databind": 2, "spring-core": 3, "junit": 4}
	for name, wantLine := range cases {
		p, _ := g.Node(name + "@" + (map[string]string{"jackson-databind": "2.17.0", "spring-core": "6.0.0", "junit": "4.13.2"})[name])
		if p == nil || len(p.Locations) == 0 {
			t.Fatalf("%s missing", name)
		}
		if p.Locations[0].Position.Line != wantLine {
			t.Errorf("%s line = %d, want %d", name, p.Locations[0].Position.Line, wantLine)
		}
	}
}

func TestSBTPositions(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "build.sbt", `name := "demo"

libraryDependencies ++= Seq(
  "org.scalatest" %% "scalatest" % "3.2.15" % Test,
  "com.typesafe.akka" %% "akka-actor" % "2.6.20"
)
`)
	g := sdk.New()
	mustPkg(t, g, "scalatest_2.13", "3.2.15")
	mustPkg(t, g, "akka-actor_2.13", "2.6.20")
	sbt.AttachSBTPositions(g, dir)
	st, _ := g.Node("scalatest_2.13@3.2.15")
	if st == nil || len(st.Locations) == 0 || st.Locations[0].Position.Line != 4 {
		t.Errorf("scalatest location wrong: %+v", st)
	}
	ak, _ := g.Node("akka-actor_2.13@2.6.20")
	if ak == nil || len(ak.Locations) == 0 || ak.Locations[0].Position.Line != 5 {
		t.Errorf("akka location wrong: %+v", ak)
	}
}

func TestCargoLockPositions(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Cargo.lock", `# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "serde"
version = "1.0.150"

[[package]]
name = "tokio"
version = "1.0.0"
`)
	g := sdk.New()
	mustPkg(t, g, "serde", "1.0.150")
	mustPkg(t, g, "tokio", "1.0.0")
	cargo.AttachCargoLockPositions(g, dir)
	se, _ := g.Node("serde@1.0.150")
	if se == nil || len(se.Locations) == 0 || se.Locations[0].Position.Line != 5 {
		t.Errorf("serde location wrong: %+v", se)
	}
	to, _ := g.Node("tokio@1.0.0")
	if to == nil || len(to.Locations) == 0 || to.Locations[0].Position.Line != 9 {
		t.Errorf("tokio location wrong: %+v", to)
	}
}

func TestPodfileLockPositions(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Podfile.lock", `PODS:
  - AFNetworking (4.0.1):
    - AFNetworking/NSURLSession (= 4.0.1)
  - AFNetworking/NSURLSession (4.0.1)
  - Alamofire (5.6.4)

DEPENDENCIES:
  - AFNetworking
`)
	g := sdk.New()
	mustPkg(t, g, "AFNetworking", "4.0.1")
	mustPkg(t, g, "Alamofire", "5.6.4")
	cocoapods.AttachPodfileLockPositions(g, dir)
	af, _ := g.Node("AFNetworking@4.0.1")
	if af == nil || len(af.Locations) == 0 || af.Locations[0].Position.Line != 2 {
		t.Errorf("AFNetworking location wrong: %+v", af)
	}
	al, _ := g.Node("Alamofire@5.6.4")
	if al == nil || len(al.Locations) == 0 || al.Locations[0].Position.Line != 5 {
		t.Errorf("Alamofire location wrong: %+v", al)
	}
}

func TestComposerLockPositions(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "composer.lock", `{
  "packages": [
    {
      "name": "symfony/console",
      "version": "v6.0.0"
    },
    {
      "name": "monolog/monolog",
      "version": "3.0.0"
    }
  ]
}
`)
	g := sdk.New()
	mustPkg(t, g, "console", "v6.0.0", func(p *sdk.Dependency) { p.Org = "symfony" })
	mustPkg(t, g, "monolog", "3.0.0", func(p *sdk.Dependency) { p.Org = "monolog" })
	composer.AttachComposerLockPositions(g, dir)
	sc, _ := g.Node("symfony:console@v6.0.0")
	if sc == nil || len(sc.Locations) == 0 || sc.Locations[0].Position.Line != 4 {
		t.Errorf("symfony/console location wrong: %+v", sc)
	}
	mn, _ := g.Node("monolog:monolog@3.0.0")
	if mn == nil || len(mn.Locations) == 0 || mn.Locations[0].Position.Line != 8 {
		t.Errorf("monolog location wrong: %+v", mn)
	}
}
