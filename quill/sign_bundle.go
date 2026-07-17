package quill

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path"
	"path/filepath"

	blacktopMacho "github.com/blacktop/go-macho"
	blacktopMachoTypes "github.com/blacktop/go-macho/pkg/codesign/types"

	macholibre "github.com/anchore/go-macholibre"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill/bundle"
	"github.com/anchore/quill/quill/event"
	"github.com/anchore/quill/quill/macho"
	"github.com/anchore/quill/quill/sign"
)

const cdHashSize = 20 // code directory hashes are truncated to 20 bytes, regardless of hash algorithm

// signAppBundle signs an application bundle (.app directory):
//  1. nested code (e.g. dylibs and helper executables) is signed in place
//  2. all bundle resources are sealed into Contents/_CodeSignature/CodeResources
//  3. the main executable is signed, binding the Info.plist and resource seal hashes into
//     its code directory
func signAppBundle(cfg SigningConfig) error {
	log.WithFields("bundle", cfg.Path).Info("signing application bundle")

	b, err := bundle.New(cfg.Path)
	if err != nil {
		return err
	}

	mon := bus.PublishTask(
		event.Title{
			Default:      "Seal bundle resources",
			WhileRunning: "Sealing bundle resources",
			OnSuccess:    "Sealed bundle resources",
		},
		cfg.Path,
		-1,
	)

	resourcesData, err := sealBundleResources(cfg, b)
	if err != nil {
		mon.SetError(err)
		return err
	}
	mon.SetCompleted()

	exeCfg := cfg
	exeCfg.Path = b.MainExecutablePath()
	if cfg.Identity == "" || cfg.Identity == path.Base(cfg.Path) {
		// no explicit identity was given (the default is the bundle directory name), so
		// follow codesign behavior: use the bundle identifier from the Info.plist
		if b.Info.Identifier != "" {
			exeCfg.Identity = b.Info.Identifier
		} else {
			exeCfg.Identity = b.Info.Executable
		}
	}
	exeCfg.specialSlots = []sign.SpecialSlot{
		sign.NewExternalContentSpecialSlot(macho.CsSlotInfoslot, b.InfoPlistData()),
		sign.NewExternalContentSpecialSlot(macho.CsSlotResourcedir, resourcesData),
	}

	return signBinary(exeCfg)
}

// sealBundleResources signs all nested code within the bundle, then writes the resource
// seal to Contents/_CodeSignature/CodeResources, returning its content.
func sealBundleResources(cfg SigningConfig, b *bundle.Bundle) ([]byte, error) {
	builder := bundle.NewResourcesBuilder()

	// the main executable is sealed by the signature we write to it after the resource
	// seal is finalized, so it must not appear in the CodeResources file
	if err := builder.ExcludePath("MacOS/" + b.Info.Executable); err != nil {
		return nil, err
	}

	if err := builder.WalkAndSeal(b.Root, nestedMachOSigner{cfg: cfg}); err != nil {
		return nil, fmt.Errorf("unable to seal bundle resources: %w", err)
	}

	resourcesData, err := builder.Assemble()
	if err != nil {
		return nil, err
	}

	resourcesPath := b.CodeResourcesPath()
	if err := os.MkdirAll(filepath.Dir(resourcesPath), 0o755); err != nil {
		return nil, fmt.Errorf("unable to create bundle _CodeSignature directory: %w", err)
	}
	if err := os.WriteFile(resourcesPath, resourcesData, 0o644); err != nil { //nolint:gosec // the resource seal is world-readable by convention
		return nil, fmt.Errorf("unable to write bundle CodeResources file: %w", err)
	}

	log.WithFields("path", resourcesPath).Debug("wrote bundle resource seal")

	return resourcesData, nil
}

// nestedMachOSigner signs nested binaries discovered within a bundle using the same signing
// material as the bundle itself.
type nestedMachOSigner struct {
	cfg SigningConfig
}

func (s nestedMachOSigner) SignMachO(binPath string) (*bundle.SignedBinaryInfo, error) {
	cfg := s.cfg
	cfg.Path = binPath
	// nested binaries are identified by their own name, never the user-provided identity
	// (which belongs to the main executable) ...
	cfg.Identity = path.Base(binPath)
	// ... and entitlements only apply to the main executable
	cfg.Entitlements = ""
	cfg.specialSlots = nil

	if err := signBinary(cfg); err != nil {
		return nil, err
	}

	return readSignedBinaryInfo(binPath)
}

// readSignedBinaryInfo extracts the code directory hash and designated requirement (in text
// form) from a signed binary. For universal binaries the first architecture is used, which
// matches the behavior of Apple's tooling.
func readSignedBinaryInfo(binPath string) (*bundle.SignedBinaryInfo, error) {
	f, err := os.Open(binPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	thinPath := binPath
	if macholibre.IsUniversalMachoBinary(f) {
		dir, err := os.MkdirTemp("", "quill-bundle-nested-"+path.Base(binPath))
		if err != nil {
			return nil, fmt.Errorf("unable to create temp directory to extract multi-arch binary: %w", err)
		}
		defer os.RemoveAll(dir)

		extractedFiles, err := macholibre.Extract(f, dir)
		if err != nil {
			return nil, fmt.Errorf("unable to extract multi-arch binary: %w", err)
		}
		if len(extractedFiles) == 0 {
			return nil, fmt.Errorf("no architectures found in multi-arch binary: %s", binPath)
		}
		thinPath = extractedFiles[0].Path
	}

	m, err := macho.NewReadOnlyFile(thinPath)
	if err != nil {
		return nil, fmt.Errorf("unable to parse signed nested binary: %w", err)
	}
	defer m.Close()

	cdHash, err := m.HashCD(sha256.New())
	if err != nil {
		return nil, fmt.Errorf("unable to hash code directory of nested binary: %w", err)
	}
	if len(cdHash) > cdHashSize {
		cdHash = cdHash[:cdHashSize]
	}

	requirement, err := readDesignatedRequirement(thinPath)
	if err != nil {
		return nil, err
	}

	return &bundle.SignedBinaryInfo{
		CDHash:      cdHash,
		Requirement: requirement,
	}, nil
}

func readDesignatedRequirement(binPath string) (string, error) {
	bf, err := blacktopMacho.Open(binPath)
	if err != nil {
		return "", fmt.Errorf("unable to parse signed nested binary: %w", err)
	}
	defer bf.Close()

	cs := bf.CodeSignature()
	if cs == nil {
		return "", fmt.Errorf("no code signature found on signed nested binary: %s", binPath)
	}

	for _, req := range cs.Requirements {
		if req.Type == blacktopMachoTypes.DesignatedRequirementType && req.Detail != "" && req.Detail != "empty requirement set" {
			return req.Detail, nil
		}
	}

	return "", nil
}
