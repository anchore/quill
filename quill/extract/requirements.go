package extract

import (
	"fmt"
	"strings"

	"github.com/blacktop/go-macho/pkg/codesign/types"
)

type RequirementDetails struct {
	Blob         BlobDetails         `json:"blob"`
	Requirements []types.Requirement `json:"requirements"`
}

func getRequirements(m File) []RequirementDetails {
	return []RequirementDetails{
		{
			// TODO: extract blob
			Requirements: m.blacktopFile.CodeSignature().Requirements,
		},
	}
}

func (r RequirementDetails) String() string {
	var reqs []string
	for idx, req := range r.Requirements {
		reqs = append(reqs, fmt.Sprintf("Req %d (type=%s): %s", idx, req.Type, req.Detail))
	}

	return tprintf(
		`{{.FormattedRequirements}}
`,
		struct {
			RequirementDetails
			RequirementsCount     string
			FormattedRequirements string
		}{
			RequirementDetails:    r,
			FormattedRequirements: strings.Join(reqs, "\n"),
		},
	)
}
