# Example Plugin: Go Module Detector

This example plugin demonstrates the Bomly managed plugin SDK with the smallest useful detector implementation.

It:

- implements `sdk`
- exposes detector metadata plus a typed detector descriptor for the managed plugin runtime
- declares component type and supported modes in the same descriptor contract used by built-ins
- declares package-manager support and evidence patterns for runtime subproject discovery
- reads a local `go.mod`
- returns a single package representing the module itself

Build it from the repo root:

```bash
go build -o ./bin/bomly-example-gomod-detector ./examples/plugins/go-module-detector
```

On Windows, Go writes `./bin/bomly-example-gomod-detector.exe`. Bomly now accepts either path, so both of these work:

```powershell
bin/bomly plugin install ./bin/bomly-example-gomod-detector --dev
bin/bomly plugin install ./bin/bomly-example-gomod-detector.exe --dev
```

Install it for development:

```bash
bomly plugin install ./bin/bomly-example-gomod-detector --dev
bomly plugin enable bomly.example.gomod-detector
```

Run it explicitly:

```bash
bomly scan --path ./some-go-module --detectors bomly.example.gomod-detector --format json
```

For the full plugin workflow, see [docs/PLUGINS.md](../../../docs/PLUGINS.md). For the detector authoring walkthrough, see [How To Implement A Detector Plugin](../../../docs/plugins/how-to-implement-detector.md).
