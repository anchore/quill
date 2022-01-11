package sign

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_generatePList(t *testing.T) {

	tests := []struct {
		name          string
		input         []string
		expectedPlist string
	}{
		{
			name: "plist contains cd hashes",
			input: []string{
				"ce0f6c28b5869ff166714da5fe08554c70c731a335ff9702e38b00f81ad348c6",
				"58da67f67fd35f245e872227fe38340c9f7f6f5dfac962e5c8197cb54a8e8326",
				"73c9c98668a34c54d131ff609d0bf129068d1b5ed3efd7cdfe753f909596456c",
			},
			expectedPlist: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
	<dict>
		<key>cdhashes</key>
		<array>
			<data>Y2UwZjZjMjhiNTg2OWZmMTY2NzE0ZGE1ZmUwODU1NGM3MGM3MzFhMzM1ZmY5NzAyZTM4YjAwZjgxYWQzNDhjNg==</data>
			<data>NThkYTY3ZjY3ZmQzNWYyNDVlODcyMjI3ZmUzODM0MGM5ZjdmNmY1ZGZhYzk2MmU1YzgxOTdjYjU0YThlODMyNg==</data>
			<data>NzNjOWM5ODY2OGEzNGM1NGQxMzFmZjYwOWQwYmYxMjkwNjhkMWI1ZWQzZWZkN2NkZmU3NTNmOTA5NTk2NDU2Yw==</data>
		</array>
	</dict>
</plist>`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var data [][]byte
			for _, hs := range tt.input {
				data = append(data, []byte(hs))
			}
			actualPlist, err := generatePList(data)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedPlist, string(actualPlist))
		})
	}
}
