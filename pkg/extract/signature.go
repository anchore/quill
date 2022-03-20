package extract

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/github/smimesign/ietf-cms/oid"

	"github.com/github/smimesign/ietf-cms/protocol"

	"github.com/anchore/quill/pkg/macho"
	cms "github.com/github/smimesign/ietf-cms"
)

type SignatureDetails struct {
	Blob          BlobDetails          `json:"blob"`
	Base64        string               `json:"base64"`
	CMSValidation CMSValidationDetails `json:"cmsValidation"`
	Certificates  []Certificate        `json:"certificates"`
	Signers       []Signer             `json:"signers"`
}

type Certificate struct {
	PEM    string            `json:"pem"`
	Parsed *x509.Certificate `json:"parsed"`
}

type Signer struct {
	ID               string             `json:"id"`
	Signature        AlgorithmWithValue `json:"signature"`
	SignedAttributes []Attribute        `json:"signedAttributes"`
	DigestAlgorithm  Algorithm          `json:"digestAlgorithm"`
}

type Attribute struct {
	OID    string `json:"oid"`
	Base64 string `json:"base64"`
}

type Algorithm struct {
	AlgorithmOID     string `json:"algorithmOID"`
	Base64Parameters string `json:"base64Parameters"`
}

type AlgorithmWithValue struct {
	Base64 string `json:"base64"`
	Algorithm
}

type CMSValidationDetails struct {
	IsValid              bool                    `json:"isValid"`
	ErrorMessage         string                  `json:"errorMessage"`
	VerifiedCertificates [][][]*x509.Certificate `json:"verifiedCertificates"`
}

func getSignatures(m file) []SignatureDetails {
	b, err := m.internalFile.CMSBlobBytes(macho.SigningOrder)
	if err != nil {
		// TODO
		panic(err)
	}

	hashObj := crypto.SHA256
	hasher := hashObj.New()
	hasher.Write(b)
	hash := hasher.Sum(nil)

	superBlob := m.blacktopFile.CodeSignature()

	ci, err := protocol.ParseContentInfo(superBlob.CMSSignature)
	if err != nil {
		// TODO
		panic(err)
	}

	sd, err := cms.ParseSignedData(superBlob.CMSSignature)
	if err != nil {
		// TODO
		panic(err)
	}

	psd, err := ci.SignedDataContent()
	if err != nil {
		// TODO
		panic(err)
	}

	// TODO: support multiple CDs
	cdBytes, err := m.internalFile.CDBytes(macho.SigningOrder)
	if err != nil {
		// TODO
		panic(err)
	}

	// TODO: allow for specifying a root of trust

	// TODO: add verify options
	verifiedCerts, cmsErr := sd.VerifyDetached(cdBytes, x509.VerifyOptions{})
	cmsValid := cmsErr == nil
	var cmsErrorStr string
	if cmsErr != nil {
		cmsErrorStr = cmsErr.Error()
	}

	parsedCerts, err := psd.X509Certificates()
	if err != nil {
		// TODO
		panic(err)
	}

	var certs []Certificate
	for idx, cert := range parsedCerts {
		certs = append(certs, Certificate{
			PEM:    base64.StdEncoding.EncodeToString(psd.Certificates[idx].Bytes),
			Parsed: cert,
		})
	}

	var signers []Signer
	for _, s := range psd.SignerInfos {
		var atts []Attribute
		for _, att := range s.SignedAttrs {
			atts = append(atts, Attribute{
				OID:    att.Type.String(),
				Base64: base64.StdEncoding.EncodeToString(att.RawValue.Bytes),
			})
		}
		signers = append(signers, Signer{
			ID: string(s.SID.Bytes),
			Signature: AlgorithmWithValue{
				Base64: base64.StdEncoding.EncodeToString(s.Signature),
				Algorithm: Algorithm{
					AlgorithmOID:     s.SignatureAlgorithm.Algorithm.String(),
					Base64Parameters: base64.StdEncoding.EncodeToString(s.SignatureAlgorithm.Parameters.Bytes),
				},
			},
			SignedAttributes: atts,
			DigestAlgorithm: Algorithm{
				AlgorithmOID:     s.DigestAlgorithm.Algorithm.String(),
				Base64Parameters: base64.StdEncoding.EncodeToString(s.DigestAlgorithm.Parameters.Bytes),
			},
		})
	}

	return []SignatureDetails{
		{
			Blob: BlobDetails{
				Base64: base64.StdEncoding.EncodeToString(b),
				Digest: Digest{
					Algorithm: algorithmName(hashObj),
					Value:     hex.EncodeToString(hash),
				},
			},
			Base64: base64.StdEncoding.EncodeToString(superBlob.CMSSignature),
			CMSValidation: CMSValidationDetails{
				IsValid:              cmsValid,
				ErrorMessage:         cmsErrorStr,
				VerifiedCertificates: verifiedCerts,
			},
			Certificates: certs,
			Signers:      signers,
		},
	}
}

func (a Attribute) String() string {
	var oidHint string
	switch a.OID {
	case oid.AttributeSigningTime.String():
		oidHint = "(signing timestamp)"
	case oid.AttributeMessageDigest.String():
		oidHint = "(message digest)"
	case oid.AttributeContentType.String():
		oidHint = "(content type)"
	}
	return tprintf(
		`OID:        {{.OID}} {{.OIDHint}}
Base64:     {{.Base64}}
`,
		struct {
			Attribute
			OIDHint string
		}{
			Attribute: a,
			OIDHint:   oidHint,
		},
	)
}

func (av AlgorithmWithValue) String() string {
	return tprintf(
		`Algorithm: {{.AlgorithmOID}}
Base64:    {{.Base64}}
`,
		struct {
			AlgorithmWithValue
		}{
			AlgorithmWithValue: av,
		},
	)
}

func (s Signer) String() string {

	var atts []string
	for idx, a := range s.SignedAttributes {
		atts = append(atts, fmt.Sprintf("Attribute %d:\n%s", idx+1, doIndent(a.String(), "  ")))
	}

	return tprintf(
		`Signature: {{.FormattedSignature}}
{{.FormattedAttributes}}
`,
		struct {
			Signer
			FormattedAttributes string
			FormattedSignature  string
		}{
			Signer:              s,
			FormattedAttributes: strings.Join(atts, ""),
			FormattedSignature:  "\n" + strings.TrimRight(doIndent(s.Signature.String(), "  "), " \n"),
		},
	)
}

func (c Certificate) String() string {
	return tprintf(
		`Subject CN:        {{.Parsed.Subject.CommonName}}
Issuer CN:         {{.Parsed.Issuer.CommonName}}
Issuer Serial:         {{.Parsed.Issuer.SerialNumber}}
`,
		struct {
			Certificate
		}{
			Certificate: c,
		},
	)
}

func (s SignatureDetails) String() string {
	var validationError string
	if !s.CMSValidation.IsValid {
		validationError = fmt.Sprintf("(%s)", s.CMSValidation.ErrorMessage)
	}

	var certs []string
	for idx, c := range s.Certificates {
		certs = append(certs, fmt.Sprintf("Certificate %d:\n%s", idx+1, strings.TrimRight(doIndent(c.String(), "  "), " \n")))
	}

	var signers []string
	for idx, signer := range s.Signers {
		signers = append(signers, fmt.Sprintf("Signer %d:\n%s", idx+1, doIndent(signer.String(), "  ")))
	}

	return tprintf(
		`Valid: {{.CMSValidation.IsValid}} {{.ValidationError}}
{{.FormattedCerts}}
{{.FormattedSigners}}
`,
		struct {
			SignatureDetails
			ValidationError  string
			FormattedCerts   string
			CertificateCount string
			FormattedSigners string
			SignersCount     string
		}{
			SignatureDetails: s,
			ValidationError:  validationError,
			FormattedCerts:   strings.TrimRight(strings.Join(certs, ""), " \n"),
			FormattedSigners: strings.TrimRight(strings.Join(signers, ""), " \n"),
		},
	)
}
