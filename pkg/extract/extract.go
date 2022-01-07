package extract

import (
	"fmt"
	"io"

	"github.com/anchore/quill/internal/log"
	"github.com/blacktop/go-macho"
)

// original source is from: https://github.com/RedMapleTech/machodump

func Show(reader io.ReaderAt) error {

	machoFile, err := macho.NewFile(reader)

	if err != nil {
		return fmt.Errorf("unable to parse macho formatted file: %w", err)
	}

	// get code signature
	sig := machoFile.CodeSignature()

	if sig == nil {
		// print file details
		printFileDetails(machoFile)
		//printLibs(machoFile.ImportedLibraries())
		printLoads(machoFile.Loads)

		fmt.Println("no code signing section in binary")
		return nil
	}

	// get array of entitlements
	ents, err := getEntsFromXMLString(sig.Entitlements)
	if err != nil {
		log.Warnf("unable to extract entities: %s\n", err.Error())
	}

	// print the details
	printCDs(sig.CodeDirectories)

	printRequirements(sig.Requirements)

	if ents != nil {
		printEnts(ents)
	}

	// parse the CMS sig, if it's there
	if len(sig.CMSSignature) > 0 {
		if err = printCMSSig(sig.CMSSignature); err != nil {
			log.Warnf("unable to extract CMS signature: %s", err.Error())
		}
	} else {
		fmt.Println("code signing section does not contain any CMS signatures")
	}
	return nil
}
