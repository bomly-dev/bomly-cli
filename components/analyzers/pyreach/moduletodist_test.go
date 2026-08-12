package pyreach

import "testing"

func TestModuleToDistribution(t *testing.T) {
	cases := []struct {
		module string
		want   string
	}{
		// Identity normalization.
		{"requests", "requests"},
		{"flask", "flask"},
		{"NumPy", "numpy"},
		{"my_underscore_pkg", "my-underscore-pkg"},
		// Static overrides.
		{"yaml", "pyyaml"},
		{"PIL", "pillow"},
		{"cv2", "opencv-python"},
		{"sklearn", "scikit-learn"},
		{"bs4", "beautifulsoup4"},
		{"jwt", "pyjwt"},
		// Stdlib drops to "".
		{"os", ""},
		{"sys", ""},
		{"typing", ""},
		// Dotted modules reduce to top-level segment.
		{"urllib3.util", "urllib3"},
		{"flask.cli", "flask"},
		// Relative-import dots are stripped.
		{".foo", "foo"},
		// Empty input.
		{"", ""},
		{"   ", ""},
	}
	for _, tc := range cases {
		t.Run(tc.module, func(t *testing.T) {
			got := moduleToDistribution(tc.module)
			if got != tc.want {
				t.Errorf("moduleToDistribution(%q) = %q, want %q", tc.module, got, tc.want)
			}
		})
	}
}

func TestCanonicalDistName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Requests", "requests"},
		{"my_pkg", "my-pkg"},
		{"my.pkg", "my-pkg"},
		{"My-Pkg", "my-pkg"},
		{"my___pkg", "my-pkg"},
		{"_leading", "leading"},
		{"trailing_", "trailing"},
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := canonicalDistName(tc.in); got != tc.want {
				t.Errorf("canonicalDistName(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
