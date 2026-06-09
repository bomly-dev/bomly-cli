package plugin

import "context"

// Doctor runs verification and runtime readiness checks for one plugin (external or built-in).
// builtins should be the full list returned by ListPluginInfos for the current binary.
// For built-in plugins the verify step is skipped (there is no external binary to inspect)
// and readiness is reported as healthy without launching an external process.
func Doctor(ctx context.Context, root, id string, builtins []Info) (*DoctorResult, error) {
	testResult, err := Test(ctx, root, id, builtins)
	if err != nil {
		return nil, err
	}

	// Built-in: no external binary to verify.
	if testResult.BuiltIn {
		return &DoctorResult{
			Info:    testResult.Info,
			Checks:  []string{"built-in: no external binary to verify"},
			Ready:   true,
			Healthy: true,
			Probe:   testResult.Probe,
		}, nil
	}

	verifyResult, err := Verify(ctx, root, id)
	if err != nil {
		return nil, err
	}

	return &DoctorResult{
		Info:    testResult.Info,
		Checks:  append([]string(nil), verifyResult.Checks...),
		Ready:   testResult.Ready,
		Healthy: testResult.Ready,
		Probe:   testResult.Probe,
	}, nil
}
