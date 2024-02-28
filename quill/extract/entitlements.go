package extract

type EntitlementDetails struct {
	Blob            BlobDetails `json:"blob"`
	Entitlements    string      `json:"entitlements,omitempty"`
	EntitlementsDER []byte      `json:"entitlements_der,omitempty"`
}

func getEntitlements(m File) *EntitlementDetails {
	entitlements := m.blacktopFile.CodeSignature().Entitlements
	entitlementsDER := m.blacktopFile.CodeSignature().EntitlementsDER
	if entitlements == "" && entitlementsDER == nil {
		return nil
	}
	return &EntitlementDetails{
		Entitlements:    entitlements,
		EntitlementsDER: entitlementsDER,
	}
}

func (e EntitlementDetails) String() string {
	return e.Entitlements
}
