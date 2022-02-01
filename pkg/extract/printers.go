package extract

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/blacktop/go-macho"
	ctypes "github.com/blacktop/go-macho/pkg/codesign/types"
	"github.com/blacktop/go-macho/types"
	"github.com/dustin/go-humanize/english"
	"github.com/fullsailor/pkcs7"
)

// original source is from: https://github.com/RedMapleTech/machodump

// printFileDetails prints the general file details to console
func printFileDetails(m *macho.File) {
	fmt.Printf("File Details:\n"+
		"\tMagic: %s\n"+
		"\tType: %s\n"+
		"\tCPU: %s, %s\n"+
		"\tCommands: %d (Size: %d)\n"+
		"\tFlags: %s\n"+
		"\tUUID: %s\n",
		m.FileHeader.Magic,
		m.FileHeader.Type,
		m.FileHeader.CPU, m.FileHeader.SubCPU.String(m.FileHeader.CPU),
		m.FileHeader.NCommands,
		m.FileHeader.SizeCommands,
		m.FileHeader.Flags.Flags(),
		m.UUID())
}

// printLoads prints the interesting load commands to console
func printLoads(loads []macho.Load) {
	fmt.Printf("File has %s. Interesting %s:\n", english.Plural(len(loads), "load command", "load commands"), english.PluralWord(len(loads), "command", "commands"))

	for i, load := range loads {
		switch load.Command() {
		case types.LC_VERSION_MIN_IPHONEOS:
			fallthrough
		case types.LC_ENCRYPTION_INFO:
			fallthrough
		case types.LC_ENCRYPTION_INFO_64:
			fallthrough
		case types.LC_SOURCE_VERSION:
			fmt.Printf("\tLoad %d (%s): %s\n", i, load.Command(), load.String())
		}
	}
}

// printCDs prints the code directory details to console
func printCDs(cds []ctypes.CodeDirectory) {
	fmt.Printf("Binary has %s:\n", english.Plural(len(cds), "Code Directory", "Code Directories"))

	for i, dir := range cds {
		fmt.Printf("\tCodeDirectory %d:\n", i)

		fmt.Printf("\t\tIdent: \"%s\"\n", dir.ID)

		if len(dir.TeamID) > 0 && isASCII(dir.TeamID) {
			fmt.Printf("\t\tTeam ID: %q\n", dir.TeamID)
		}

		fmt.Printf("\t\tCD Hash: %s\n", dir.CDHash)
		fmt.Printf("\t\tCode slots: %d\n", len(dir.CodeSlots))
		// for _, slot := range dir.CodeSlots {
		//  	fmt.Printf("\t\t\t%s\n", slot.Desc)
		// }

		fmt.Printf("\t\tSpecial slots: %d\n", len(dir.SpecialSlots))

		for _, slot := range dir.SpecialSlots {
			fmt.Printf("\t\t\t%s\n", slot.Desc)
		}
	}
}

// printRequirements prints the requirement sections to console
func printRequirements(reqs []ctypes.Requirement) {
	fmt.Printf("Binary has %s:\n", english.Plural(len(reqs), "requirement", "requirements"))

	for i, req := range reqs {
		fmt.Printf("\tRequirement %d (%s): %s\n", i, req.Type, req.Detail)
	}
}

// printEnts prints the entitlements to console
// nolint: funlen
func printEnts(ents *entsStruct) {
	if ents == nil {
		fmt.Printf("Binary has no entitlements\n")
		return
	}

	entries := false

	// print the boolean entries
	if ents.BooleanValues != nil && len(ents.BooleanValues) > 0 {
		fmt.Printf("Binary has %s:\n", english.Plural(len(ents.BooleanValues), "boolean entitlement", "boolean entitlements"))

		for _, ent := range ents.BooleanValues {
			fmt.Printf("\t%s: %t\n", ent.Name, ent.Value)
		}

		entries = true
	}

	// print the string entries
	if ents.StringValues != nil && len(ents.StringValues) > 0 {
		fmt.Printf("Binary has %s:\n", english.Plural(len(ents.StringValues), "string entitlement", "string entitlements"))

		for i, ent := range ents.StringValues {
			fmt.Printf("\t%d %s: %q\n", i, ent.Name, ent.Value)
		}

		entries = true
	}

	// print the integer entries
	if ents.IntegerValues != nil && len(ents.IntegerValues) > 0 {
		fmt.Printf("Binary has %s:\n", english.Plural(len(ents.IntegerValues), "integer entitlement", "integer entitlements"))

		for i, ent := range ents.IntegerValues {
			fmt.Printf("\t%d %s: %d\n", i, ent.Name, ent.Value)
		}

		entries = true
	}

	// print the string array entries
	if ents.StringArrayValues != nil && len(ents.StringArrayValues) > 0 {
		fmt.Printf("Binary has %s:\n", english.Plural(len(ents.StringArrayValues), "string array entitlement", "string array entitlements"))

		for i, ent := range ents.StringArrayValues {
			valueList := ""

			for _, str := range ent.Values {
				valueList = valueList + str + ", "
			}

			valueList = strings.TrimSuffix(valueList, ", ")

			fmt.Printf("\t%d %s: [%q]\n", i, ent.Name, valueList)
		}

		entries = true
	}

	if !entries {
		fmt.Printf("Binary has no entitlements\n")
	}
}

// printCMSSig parses the PKCS7 blob, extracting the certificate common names
func printCMSSig(data []byte) error {
	p7, err := pkcs7.Parse(data)
	if err != nil {
		return fmt.Errorf("unable to parse CMS: %w", err)
	}

	if p7 == nil {
		fmt.Printf("No certificates found")
		return nil
	}

	fmt.Printf("\nCMS Signature has %d certificates:\n", len(p7.Certificates))
	for _, cert := range p7.Certificates {
		fmt.Printf("\tCN: %q\n", cert.Subject.CommonName)
	}

	fmt.Printf("\nCMS Signature has %d signers:\n", len(p7.Signers))
	for idx, signer := range p7.Signers {
		fmt.Printf("\tSigner %d:\n", idx+1)
		fmt.Println("\t\tIssuerAndSerialNumber: ")
		fmt.Printf("\t\t\tName: %q\n", string(signer.IssuerAndSerialNumber.IssuerName.FullBytes))
		fmt.Printf("\t\t\tSerial: 0x%x\n", signer.IssuerAndSerialNumber.SerialNumber)
		fmt.Printf("\t\tDigest Algorithm: %+v\n", signer.DigestAlgorithm.Algorithm)

		fmt.Printf("\t\tUnauthenticated Attributes (%d):\n", len(signer.UnauthenticatedAttributes))
		for ui, att := range signer.UnauthenticatedAttributes {
			fmt.Printf("\t\t\tAttribute %d\n", ui)
			fmt.Printf("\t\t\tType: %+v\n", att.Type)
			// fmt.Printf("\t\t\tCompound?: %+v\n", att.Value.IsCompound)
			// fmt.Printf("\t\t\tValue: %q\n\n", string(att.Value.Bytes))
		}

		fmt.Printf("\t\tAuthenticated Attributes (%d):\n", len(signer.AuthenticatedAttributes))
		for ui, att := range signer.AuthenticatedAttributes {
			fmt.Printf("\t\t\tAttribute %d\n", ui)
			fmt.Printf("\t\t\tType: %+v\n", att.Type)
			fmt.Printf("\t\t\tCompound?: %+v\n", att.Value.IsCompound)
			fmt.Printf("\t\t\tValue: %q\n\n", fmt.Sprintf("%x", att.Value.Bytes))
		}
	}

	return nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}
