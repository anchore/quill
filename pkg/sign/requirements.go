package sign

import "github.com/fullsailor/pkcs7"

func generateRequirements(cmsObj pkcs7.SignedData) []byte {
	// TODO: replace empty requirement set with real requirements derived from CMS input
	return []byte{}
}
