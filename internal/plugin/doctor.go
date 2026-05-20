package plugin

import "context"

// Doctor runs verification and runtime readiness checks for one installed plugin.
func Doctor(ctx context.Context, root, id string) (*DoctorResult, error) {
	verifyResult, err := Verify(ctx, root, id)
	if err != nil {
		return nil, err
	}
	testResult, err := Test(ctx, root, id)
	if err != nil {
		return nil, err
	}

	return &DoctorResult{
		PluginInfo: testResult.PluginInfo,
		Checks:     append([]string(nil), verifyResult.Checks...),
		Ready:      testResult.Ready,
		Healthy:    testResult.Ready,
		Probe:      testResult.Probe,
	}, nil
}
