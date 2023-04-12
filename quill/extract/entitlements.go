package extract

type EntitlementDetails struct {
	Blob BlobDetails `json:"blob"`
}

func getEntitlements(_ File) []EntitlementDetails {
	// TODO
	return nil
}
