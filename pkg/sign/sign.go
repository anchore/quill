package sign

import (
	"crypto/sha256"
	"encoding/asn1"
	"fmt"

	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/pkg/macho"
	"github.com/fullsailor/pkcs7"
	"github.com/go-restruct/restruct"
)

func Sign(id, path, keyFile, keyPassword, certFile string) error {
	m, err := macho.NewFile(path)
	if err != nil {
		return err
	}

	// check there already isn't a LcCodeSignature loader already (if there is, bail)
	if m.HasCodeSigningCmd() {
		return fmt.Errorf("already has code signing cmd")
	}

	if certFile == "" {
		log.Warnf("only ad-hoc signing, which means that anyone can alter the binary contents without you knowing (there is no cryptographic signature)")
	}

	// [A] (patch) add **dummy** LcCodeSignature loader
	if err = m.AddDummyCodeSigningCmd(); err != nil {
		return err
	}

	// first pass: add the signed data with the dummy loader
	numSbBytes, err := addSigningData(id, m, keyFile, keyPassword, certFile)
	if err != nil {
		return fmt.Errorf("failed to add signing data on pass=1: %w", err)
	}

	if err = updateSuperBlobOffsetReferences(m, numSbBytes); err != nil {
		return nil
	}

	// second pass: now that all of the sizing is right, let's do it again with the final contents (replacing the hashes and signature)
	_, err = addSigningData(id, m, keyFile, keyPassword, certFile)
	if err != nil {
		return fmt.Errorf("failed to add signing data on pass=2: %w", err)
	}

	return nil
}

func updateSuperBlobOffsetReferences(m *macho.File, numSbBytes uint64) error {
	// (patch) patch  LcCodeSignature loader referencing the superblob offset
	if err := m.UpdateCodeSigningCmdDataSize(int(numSbBytes)); err != nil {
		return fmt.Errorf("unable to update code signature loader data size: %w", err)
	}

	// (patch) update the __LINKEDIT segment sizes to be "oldsize + newsuperblobsize"
	linkEditSegment := m.Segment("__LINKEDIT")
	linkEditSegment.Filesz += numSbBytes
	for linkEditSegment.Filesz > linkEditSegment.Memsz {
		linkEditSegment.Memsz *= 2
	}
	if err := m.UpdateSegmentHeader(linkEditSegment.SegmentHeader); err != nil {
		return fmt.Errorf("failed to update linkedit segment size: %w", err)
	}
	return nil
}

func addSigningData(id string, m *macho.File, keyFile, keyPassword, certFile string) (uint64, error) {
	// generate the content digests each page in the binary (except the signature data)
	//  input:  entire binary
	//  output: array of hashes (for each page)
	hasher := sha256.New()

	// generate code directory
	//  input: binary pages (with load command, no signature)
	//  output: code directory

	var cdFlags macho.CdFlag
	if certFile != "" {
		cdFlags = macho.LinkerSigned | macho.Adhoc // TODO: revaluate
	} else {
		cdFlags = macho.LinkerSigned | macho.Adhoc // TODO: revaluate
	}

	cd, err := generateCodeDirectory(id, hasher, m, cdFlags)
	if err != nil {
		return 0, err
	}

	cdBytes, err := restruct.Pack(m.SigningByteOrder(), cd)
	if err != nil {
		return 0, fmt.Errorf("unable to encode code directory: %w", err)
	}

	cdHash, err := generateCdHash(cd)
	if err != nil {
		return 0, err
	}

	var cmsObj *pkcs7.SignedData
	var cmsBytes []byte
	if certFile != "" {
		// generate plist
		//  input: code directory hashes
		//  output: bytes

		plst, err := generatePList([][]byte{cdHash})
		if err != nil {
			return 0, err
		}

		// generate the entitlements
		//  output: bytes?
		// TODO

		// generate CMS
		//  input: plist, + ?
		//  output: bytes
		attrs := []pkcs7.Attribute{
			{
				// 1.2.840.113635.100.9.1 is the PLIST
				Type:  asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1},
				Value: plst,
			},
			// TODO: 1.2.840.113635.100.9.2 (what is this?)
		}

		// TODO: add certificate chain
		cmsObj, cmsBytes, err = generateCMS(keyFile, keyPassword, certFile, attrs)
		if err != nil {
			return 0, err
		}
	}

	// generate the requirements
	//  output: bytes?
	requirements := generateRequirements(cmsObj)

	// encode the superblob with the following blobs:

	// - code directory blob (magic 0xfade0c02)
	// - requirement set blob (magic 0xfade0c01)
	// - entitlements blob (magic 0xfade7171)... optional, for later
	// - blob wrapper for certificate chain + CMS message (magic 0xfade0b01)

	sb := macho.NewSuperBlob(macho.MagicEmbeddedSignature)

	sb.Add(macho.CsSlotCodedirectory, macho.NewBlob(macho.MagicCodedirectory, cdBytes))
	sb.Add(macho.CsSlotRequirements, macho.NewBlob(macho.MagicRequirements, requirements))
	if len(cmsBytes) > 0 {
		sb.Add(macho.CsSlotCmsSignature, macho.NewBlob(macho.MagicBlobwrapper, cmsBytes))
	}
	sb.Finalize()

	sbBytes, err := restruct.Pack(m.SigningByteOrder(), &sb)
	if err != nil {
		return 0, fmt.Errorf("unable to encode super blob: %w", err)
	}

	// (patch) append the superblob to the __LINKEDIT section
	codeSigningCmd, _, err := m.CodeSigningCmd()
	if err != nil {
		return 0, err
	}

	if err = m.Patch(sbBytes, len(sbBytes), uint64(codeSigningCmd.DataOffset)); err != nil {
		return 0, fmt.Errorf("failed to patch super blob onto macho binary: %w", err)
	}

	return uint64(len(sbBytes)), nil
}

//func showHashes(m *macho.File, reader io.Reader) {
//	hashes, err := hashBinaryPages(sha256.New(), m, reader)
//	if err != nil {
//		panic(err)
//	}
//	for idx, h := range hashes {
//		fmt.Printf("hash %d: %x\n", idx, h)
//	}
//}

//func showCMS(b []byte) {
//	p7, err := pkcs7.Parse(b)
//	if err != nil {
//		panic(err)
//	}
//
//	if p7 == nil {
//		panic("no p7")
//	}
//
//	fmt.Printf("\nCMS Signature has %d certificates:\n", len(p7.Certificates))
//	for _, cert := range p7.Certificates {
//		fmt.Printf("\tCN: %q\n", cert.Subject.CommonName)
//	}
//
//	fmt.Printf("\nCMS Signature has %d signers:\n", len(p7.Signers))
//	for idx, signer := range p7.Signers {
//		fmt.Printf("\tSigner %d:\n", idx)
//		fmt.Println("\t\tIssuerAndSerialNumber: ")
//		fmt.Printf("\t\t\tName: %q\n", string(signer.IssuerAndSerialNumber.IssuerName.FullBytes))
//		fmt.Printf("\t\t\tSerial: 0x%x\n", signer.IssuerAndSerialNumber.SerialNumber)
//		fmt.Printf("\t\tDigest Algorithm: %+v\n", signer.DigestAlgorithm)
//
//		fmt.Printf("\t\tUnauthenticated Attributes (%d):\n", len(signer.UnauthenticatedAttributes))
//		for ui, att := range signer.UnauthenticatedAttributes {
//			fmt.Printf("\t\t\tAttribute %d\n", ui)
//			fmt.Printf("\t\t\tType: %+v\n", att.Type)
//			fmt.Printf("\t\t\tCompound?: %+v\n", att.Value.IsCompound)
//			fmt.Printf("\t\t\tValue: %q\n\n", string(att.Value.Bytes))
//		}
//
//		fmt.Printf("\t\tAuthenticated Attributes (%d):\n", len(signer.AuthenticatedAttributes))
//		for ui, att := range signer.AuthenticatedAttributes {
//			fmt.Printf("\t\t\tAttribute %d\n", ui)
//			fmt.Printf("\t\t\tType: %+v\n", att.Type)
//			fmt.Printf("\t\t\tCompound?: %+v\n", att.Value.IsCompound)
//			fmt.Printf("\t\t\tValue: %q\n\n", string(att.Value.Bytes))
//		}
//
//	}
//}
