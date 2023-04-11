package main

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

func Test_findCALinks(t *testing.T) {

	tests := []struct {
		name    string
		fixture string
		want    *AppleCALinks
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:    "happy path",
			fixture: "test-fixtures/index.html",
			want: &AppleCALinks{
				Roots: []Link{
					{
						Name: "Apple Inc. Root",
						URL:  "https://www.apple.com/appleca/AppleIncRootCertificate.cer",
					},
					{
						Name: "Apple Computer, Inc. Root",
						URL:  "https://www.apple.com/certificateauthority/AppleComputerRootCertificate.cer",
					},
					{
						Name: "Apple Root CA - G2 Root",
						URL:  "https://www.apple.com/certificateauthority/AppleRootCA-G2.cer",
					},
					{
						Name: "Apple Root CA - G3 Root",
						URL:  "https://www.apple.com/certificateauthority/AppleRootCA-G3.cer",
					},
				},
				Intermediates: []Link{
					{
						Name: "Apple IST CA 2 - G1",
						URL:  "https://www.apple.com/certificateauthority/AppleISTCA2G1.cer",
					},
					{
						Name: "Apple IST CA 8 - G1",
						URL:  "https://www.apple.com/certificateauthority/AppleISTCA8G1.cer",
					},
					{
						Name: "Application Integration",
						URL:  "https://www.apple.com/certificateauthority/AppleAAICA.cer",
					},
					{
						Name: "Application Integration 2",
						URL:  "https://www.apple.com/certificateauthority/AppleAAI2CA.cer",
					},
					{
						Name: "Application Integration - G3",
						URL:  "https://www.apple.com/certificateauthority/AppleAAICAG3.cer",
					},
					{
						Name: "Apple Application Integration CA 5 - G1",
						URL:  "https://www.apple.com/certificateauthority/AppleApplicationIntegrationCA5G1.cer",
					},
					{
						Name: "Developer Authentication",
						URL:  "https://www.apple.com/certificateauthority/DevAuthCA.cer",
					},
					{
						Name: "Developer ID - G1 (Expiring 02/01/2027 22:12:15 UTC)",
						URL:  "https://www.apple.com/certificateauthority/DeveloperIDCA.cer",
					},
					{
						Name: "Developer ID - G2 (Expiring 09/17/2031 00:00:00 UTC)",
						URL:  "https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer",
					},
					{
						Name: "Software Update",
						URL:  "https://www.apple.com/certificateauthority/AppleSoftwareUpdateCertificationAuthority.cer",
					},
					{
						Name: "Timestamp",
						URL:  "https://www.apple.com/certificateauthority/AppleTimestampCA.cer",
					},
					{
						Name: "Worldwide Developer Relations - G2 (Expiring 05/06/2029 23:43:24 UTC)",
						URL:  "https://www.apple.com/certificateauthority/AppleWWDRCAG2.cer",
					},
					{
						Name: "Worldwide Developer Relations - G3 (Expiring 02/20/2030 00:00:00 UTC)",
						URL:  "https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer",
					},
					{
						Name: "Worldwide Developer Relations - G4 (Expiring 12/10/2030 00:00:00 UTC)",
						URL:  "https://www.apple.com/certificateauthority/AppleWWDRCAG4.cer",
					},
					{
						Name: "Worldwide Developer Relations - G5 (Expiring 12/10/2030 00:00:00 UTC)",
						URL:  "https://www.apple.com/certificateauthority/AppleWWDRCAG5.cer",
					},
					{
						Name: "Worldwide Developer Relations - G6 (Expiring 03/19/2036 00:00:00 UTC)",
						URL:  "https://www.apple.com/certificateauthority/AppleWWDRCAG6.cer",
					},
					{
						Name: "Worldwide Developer Relations - G7 (Expiring 11/17/2023 20:40:52 UTC)",
						URL:  "https://www.apple.com/certificateauthority/AppleWWDRCAG7.cer",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			// read all bytes from the fixture file
			html, err := os.ReadFile(tt.fixture)
			require.NoError(t, err)

			got, err := findCALinks(html, AppleCaURL)
			tt.wantErr(t, err)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("findCALinks() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
