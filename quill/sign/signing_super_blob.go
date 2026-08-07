package sign

import (
	"crypto/sha256"
	"fmt"

	"github.com/go-restruct/restruct"

	"github.com/anchore/quill/quill/macho"
	"github.com/anchore/quill/quill/pki"
)

type SpecialSlot struct {
	Type      macho.SlotType
	Blob      *macho.Blob
	HashBytes []byte
}

// NewExternalContentSpecialSlot creates a special slot for content that lives outside of the
// binary (e.g. a bundle's Info.plist or CodeResources file): the hash of the content is
// recorded in the code directory, but no blob is embedded in the superblob.
func NewExternalContentSpecialSlot(slotType macho.SlotType, content []byte) SpecialSlot {
	h := sha256.New()
	h.Write(content)
	return SpecialSlot{Type: slotType, HashBytes: h.Sum(nil)}
}

// GenerateSigningSuperBlob generates the superblob holding the code directory, entitlements,
// requirements, and CMS signature for the given binary. Any additionalSlots provided are
// recorded in the code directory alongside the generated slots (used when the binary is the
// main executable of a bundle).
func GenerateSigningSuperBlob(id string, m *macho.File, signingMaterial pki.SigningMaterial, entitlementsData string, additionalSlots []SpecialSlot, paddingTarget int) (int, []byte, error) {
	var cdFlags macho.CdFlag
	if signingMaterial.Signer != nil {
		// TODO: add options to enable more strict rules (such as macho.Hard)
		// note: we must at least support the runtime option for notarization (requirement introduced in macOS 10.14 / Mojave).
		// cdFlags = macho.Runtime | macho.Hard
		cdFlags = macho.Runtime
	} else {
		cdFlags = macho.Adhoc
	}

	specialSlots := append([]SpecialSlot{}, additionalSlots...)

	entitlements, err := generateEntitlements(sha256.New(), entitlementsData)
	if err != nil {
		return 0, nil, fmt.Errorf("unable to create entitlements: %w", err)
	}
	if entitlements != nil {
		specialSlots = append(specialSlots, *entitlements)
	}

	requirements, err := generateRequirements(id, sha256.New(), signingMaterial)
	if err != nil {
		return 0, nil, fmt.Errorf("unable to create requirements: %w", err)
	}
	if requirements != nil {
		specialSlots = append(specialSlots, *requirements)
	}

	// derive team ID from the leaf certificate's Organizational Unit (OU) field
	var teamID string
	if leaf := signingMaterial.Leaf(); leaf != nil && len(leaf.Subject.OrganizationalUnit) > 0 {
		teamID = leaf.Subject.OrganizationalUnit[0]
	}

	cdBlob, err := generateCodeDirectory(id, teamID, sha256.New(), m, cdFlags, specialSlots)
	if err != nil {
		return 0, nil, fmt.Errorf("unable to create code directory: %w", err)
	}

	cmsBlob, err := generateCMS(signingMaterial, cdBlob)
	if err != nil {
		return 0, nil, fmt.Errorf("unable to create signature block: %w", err)
	}

	sb := macho.NewSuperBlob(macho.MagicEmbeddedSignature)
	sb.Add(macho.CsSlotCodedirectory, cdBlob)
	for _, slot := range specialSlots {
		if slot.Blob == nil {
			// the slot content lives outside the binary (e.g. Info.plist); only its hash
			// is recorded in the code directory
			continue
		}
		sb.Add(slot.Type, slot.Blob)
	}

	sb.Add(macho.CsSlotCmsSignature, cmsBlob)

	sb.Finalize(paddingTarget)

	sbBytes, err := restruct.Pack(macho.SigningOrder, &sb)
	if err != nil {
		return 0, nil, fmt.Errorf("unable to encode super blob: %w", err)
	}

	return int(sb.Length), sbBytes, nil
}

func UpdateSuperBlobOffsetReferences(m *macho.File, numSbBytes uint64) error {
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
