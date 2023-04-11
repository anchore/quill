package extract

import (
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/anchore/quill/quill/macho"
)

type CodeDirectoryDetails struct {
	Blob           BlobDetails     `json:"blob"`
	SpecialDigests []SectionDigest `json:"specialDigests"`
	Version        DescribedValue  `json:"version"`
	PageDigests    []SectionDigest `json:"pageDigests"`
	DeclaredDigest SectionDigest   `json:"declaredDigest"`
	TeamID         string          `json:"teamID"`
	ID             string          `json:"id"`
	Platform       uint8           `json:"platform"`
	Flags          DescribedValue  `json:"flags"`
}

type DescribedValue struct {
	Value       interface{} `json:"value"`
	Description string      `json:"description"`
}

type SectionDigest struct {
	Index  int64  `json:"index"`
	Offset uint64 `json:"offset"`
	Digest
}

func (d SectionDigest) String() string {
	return fmt.Sprintf("idx=%-3d @0x%-5x %s:%s", d.Index, d.Offset, d.Algorithm, d.Value)
}

func getCodeDirectories(m File) (cdObjs []CodeDirectoryDetails) {
	for idx, cd := range m.blacktopFile.CodeSignature().CodeDirectories {
		b, err := m.internalFile.CDBytes(macho.SigningOrder, idx)
		if err != nil {
			// TODO
			panic(err)
		}

		var hashes []SectionDigest
		for _, cs := range cd.CodeSlots {
			hashes = append(hashes, SectionDigest{
				Digest: Digest{
					Algorithm: cleanAlgorithmName(cd.Header.HashType.String()),
					Value:     hex.EncodeToString(cs.Hash),
				},
				Index:  int64(cs.Index),
				Offset: uint64(cs.Page),
			})
		}

		var specialHashes []SectionDigest
		for _, cs := range cd.SpecialSlots {
			specialHashes = append(specialHashes, SectionDigest{
				Digest: Digest{
					Algorithm: cleanAlgorithmName(cd.Header.HashType.String()),
					Value:     hex.EncodeToString(cs.Hash),
				},
				Index: -int64(cs.Index),
			})
		}

		hashObj := crypto.SHA256
		hasher := hashObj.New()
		hasher.Write(b)
		hash := hasher.Sum(nil)
		cdObjs = append(cdObjs,
			CodeDirectoryDetails{
				Blob: BlobDetails{
					Base64: base64.StdEncoding.EncodeToString(b),
					Digest: Digest{
						Algorithm: algorithmName(hashObj),
						Value:     hex.EncodeToString(hash),
					},
				},
				PageDigests:    hashes,
				SpecialDigests: specialHashes,
				DeclaredDigest: SectionDigest{
					Index:  int64(cd.Header.ExecSegBase),
					Offset: cd.Header.ExecSegLimit,
					Digest: Digest{
						Algorithm: cleanAlgorithmName(cd.Header.HashType.String()),
						Value:     cd.CDHash,
					},
				},
				TeamID:   cd.TeamID,
				ID:       cd.ID,
				Platform: uint8(cd.Header.Platform),
				Version: DescribedValue{
					Value:       cd.Header.Version,
					Description: cd.Header.Version.String(),
				},
				Flags: DescribedValue{
					Value:       cd.Header.Flags,
					Description: cd.Header.Flags.String(),
				},
			},
		)
	}
	return cdObjs
}

func (c CodeDirectoryDetails) String(hideVerboseData bool) string {
	var specialDigests []string
	for _, d := range c.SpecialDigests {
		specialDigests = append(specialDigests, d.String())
	}

	var pageDigests []string
	for _, d := range c.PageDigests {
		pageDigests = append(pageDigests, d.String())
	}

	var pageDigestStr string
	if hideVerboseData {
		pageDigestStr = "  (hidden)"
	} else {
		pageDigestStr = doIndent(strings.Join(pageDigests, "\n"), "  ")
	}

	var specialDigestStr string
	if hideVerboseData {
		specialDigestStr = "  (hidden)"
	} else {
		specialDigestStr = doIndent(strings.Join(specialDigests, "\n"), "  ")
	}

	return tprintf(
		`Version:  {{.Version.Description}}
Flags:    {{.Flags.Description}}
ID:       {{.ID}}
TeamID:   {{.TeamID}}
Digest:   {{.DeclaredDigest.Algorithm}}:{{.DeclaredDigest.Value}}
SpecialDigests: count={{.SpecialDigestCount}}
{{.FormattedSpecialDigests}}
PageDigests: count={{.PageDigestCount}}
{{.FormattedPageDigests}}
`,
		struct {
			CodeDirectoryDetails
			SpecialDigestCount      int
			PageDigestCount         int
			FormattedSpecialDigests string
			FormattedPageDigests    string
		}{
			CodeDirectoryDetails:    c,
			SpecialDigestCount:      len(c.SpecialDigests),
			PageDigestCount:         len(c.PageDigests),
			FormattedSpecialDigests: specialDigestStr,
			FormattedPageDigests:    pageDigestStr,
		},
	)
}
