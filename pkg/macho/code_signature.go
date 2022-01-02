package macho

const (
	// Magic numbers used by Code Signing
	CsMagicRequirement             CsMagic = 0xfade0c00 // single Requirement blob
	CsMagicRequirements            CsMagic = 0xfade0c01 // Requirements vector (internal requirements)
	CsMagicCodedirectory           CsMagic = 0xfade0c02 // CodeDirectory blob
	CsMagicEmbeddedSignature       CsMagic = 0xfade0cc0 // embedded form of signature data
	CsMagicEmbeddedSignatureOld    CsMagic = 0xfade0b02 /* XXX */
	CsMagicLibraryDependencyBlob   CsMagic = 0xfade0c05
	CsMagicEmbeddedEntitlements    CsMagic = 0xfade7171 /* embedded entitlements */
	CsMagicEmbeddedEntitlementsDer CsMagic = 0xfade7172 /* embedded entitlements */
	CsMagicDetachedSignature       CsMagic = 0xfade0cc1 // multi-arch collection of embedded signatures
	CsMagicBlobwrapper             CsMagic = 0xfade0b01 // used for the cms blob
)

const (
	CsSlotCodedirectory               SlotType = 0
	CsSlotInfoslot                    SlotType = 1 // Info.plist
	CsSlotRequirements                SlotType = 2 // internal requirements
	CsSlotResourcedir                 SlotType = 3 // resource directory
	CsSlotApplication                 SlotType = 4 // Application specific slot/Top-level directory list
	CsSlotEntitlements                SlotType = 5 // embedded entitlement configuration
	CsSlotRepSpecific                 SlotType = 6 // for use by disk rep
	CsSlotEntitlementsDer             SlotType = 7 // DER representation of entitlements
	CsSlotAlternateCodedirectories    SlotType = 0x1000
	CsSlotAlternateCodedirectoryMax            = 5
	CsSlotAlternateCodedirectoryLimit          = CsSlotAlternateCodedirectories + CsSlotAlternateCodedirectoryMax
	CsSlotCmsSignature                SlotType = 0x10000
	CsSlotIdentificationslot          SlotType = 0x10001
	CsSlotTicketslot                  SlotType = 0x10002
)

type CsMagic uint32
