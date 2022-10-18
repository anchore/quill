package extract

type SuperBlobDetails struct {
	Offset          uint32                 `json:"offset"`
	Size            uint32                 `json:"size"`
	CodeDirectories []CodeDirectoryDetails `json:"codeDirectories"`
	Requirements    []RequirementDetails   `json:"requirements"`
	Entitlements    []EntitlementDetails   `json:"entitlements"`
	Signatures      []SignatureDetails     `json:"signatures"`
}

func getSuperBlobDetails(m File) *SuperBlobDetails {
	signingLoadCmd := m.blacktopFile.CodeSignature()
	if signingLoadCmd == nil {
		return nil
	}
	return &SuperBlobDetails{
		Offset:          signingLoadCmd.Offset,
		Size:            signingLoadCmd.Size,
		CodeDirectories: getCodeDirectories(m),
		Requirements:    getRequirements(m),
		Entitlements:    getEntitlements(m),
		Signatures:      getSignatures(m),
	}
}
