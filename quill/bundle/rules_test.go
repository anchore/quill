package bundle

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "strips Contents prefix",
			path:     "Contents/Resources/foo.txt",
			expected: "Resources/foo.txt",
		},
		{
			name:     "leaves other paths alone",
			path:     "Resources/foo.txt",
			expected: "Resources/foo.txt",
		},
		{
			name:     "does not strip Contents as a full component",
			path:     "Contents",
			expected: "Contents",
		},
		{
			name:     "converts backslashes",
			path:     `Contents\Resources\foo.txt`,
			expected: "Resources/foo.txt",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, normalizePath(tt.path))
		})
	}
}

func TestFindRule(t *testing.T) {
	tests := []struct {
		name            string
		path            string
		expectNoMatch   bool
		expectedPattern string
		expectedNested  bool
		expectedOmit    bool
		expectedOpt     bool
	}{
		{
			name:            "catch-all matches any path",
			path:            "some/random/file",
			expectedPattern: `^.*`,
		},
		{
			name:            "top-level entries are nested",
			path:            "PlugIns",
			expectedPattern: `^[^/]+$`,
			expectedNested:  true,
		},
		{
			name:            "MacOS content is nested code",
			path:            "MacOS/helper",
			expectedPattern: `^(Frameworks|SharedFrameworks|PlugIns|Plug-ins|XPCServices|Helpers|MacOS|Library/(Automator|Spotlight|LoginItems))/`,
			expectedNested:  true,
		},
		{
			name:            "frameworks are nested code",
			path:            "Frameworks/libfoo.dylib",
			expectedPattern: `^(Frameworks|SharedFrameworks|PlugIns|Plug-ins|XPCServices|Helpers|MacOS|Library/(Automator|Spotlight|LoginItems))/`,
			expectedNested:  true,
		},
		{
			name:            "DS_Store is omitted even in nested dirs",
			path:            "MacOS/.DS_Store",
			expectedPattern: `^(.*/)?\.DS_Store$`,
			expectedOmit:    true,
		},
		{
			name:            "Info.plist is omitted",
			path:            "Info.plist",
			expectedPattern: `^Info\.plist$`,
			expectedOmit:    true,
		},
		{
			name:            "resources are plain files (not nested), by weight",
			path:            "Resources/app.icns",
			expectedPattern: `^Resources/`,
		},
		{
			name:            "lproj resources are optional",
			path:            "Resources/en.lproj/Main.strings",
			expectedPattern: `^Resources/.*\.lproj/`,
			expectedOpt:     true,
		},
		{
			name:            "Base.lproj resources are required",
			path:            "Resources/Base.lproj/Main.strings",
			expectedPattern: `^Resources/Base\.lproj/`,
		},
		{
			name:            "locversion.plist is omitted",
			path:            "Resources/en.lproj/locversion.plist",
			expectedPattern: `^Resources/.*\.lproj/locversion.plist$`,
			expectedOmit:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := findRule(defaultRulesV2(), tt.path)
			if tt.expectNoMatch {
				require.Nil(t, r)
				return
			}
			require.NotNil(t, r)
			assert.Equal(t, tt.expectedPattern, r.pattern.String())
			assert.Equal(t, tt.expectedNested, r.nested, "nested")
			assert.Equal(t, tt.expectedOmit, r.omit, "omit")
			assert.Equal(t, tt.expectedOpt, r.optional, "optional")
		})
	}
}

func TestFindRule_exclusionsWin(t *testing.T) {
	rules := defaultRulesV2()
	excl, err := excludePathRule("MacOS/my-app")
	require.NoError(t, err)
	rules = append(rules, excl)

	r := findRule(rules, "MacOS/my-app")
	require.NotNil(t, r)
	assert.True(t, r.exclude, "exclusion rules take precedence regardless of weight")

	r = findRule(rules, "MacOS/other")
	require.NotNil(t, r)
	assert.False(t, r.exclude)
	assert.True(t, r.nested)
}
