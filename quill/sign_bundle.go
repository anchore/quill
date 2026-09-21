package quill

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	blacktopMacho "github.com/blacktop/go-macho"
	blacktopMachoTypes "github.com/blacktop/go-macho/pkg/codesign/types"
	cms "github.com/github/smimesign/ietf-cms"

	macholibre "github.com/anchore/go-macholibre"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill/bundle"
	"github.com/anchore/quill/quill/event"
	"github.com/anchore/quill/quill/macho"
	"github.com/anchore/quill/quill/pki"
	"github.com/anchore/quill/quill/sign"
)

const cdHashSize = 20 // code directory hashes are truncated to 20 bytes, regardless of hash algorithm

// signAppBundle signs an application bundle (.app directory):
//  1. nested code (e.g. dylibs and helper executables) is signed in place, and nested bundles
//     (e.g. .appex, .framework), which must already be signed, are sealed by reference
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
	if !cfg.identityExplicit {
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
	excludePaths := []string{"MacOS/" + b.Info.Executable}

	if err := builder.WalkAndSeal(b.Root, excludePaths, nestedMachOSigner{cfg: cfg}); err != nil {
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

// SealNestedBundle reports the signature of an already-signed nested bundle, so the parent
// can seal it by reference.
//
// The nested bundle is not signed here. Nested bundles usually need signing options of their
// own -- an app extension, for instance, must carry its own sandbox entitlements -- so, as
// Apple recommends, each is signed explicitly, inside-out, before the bundle containing it.
//
// Because the existing signature is sealed as-is, it is checked against the signing material
// of the outer bundle: an ad-hoc signed nested bundle inside a bundle signed with a
// certificate is rejected, since it is almost always a leftover development signature and
// Apple's notary service rejects it.
func (s nestedMachOSigner) SealNestedBundle(bundlePath string) (*bundle.SignedBinaryInfo, error) {
	exe, err := bundle.MainExecutableOf(bundlePath)
	if err != nil {
		return nil, err
	}

	// The presence of a signature is established by reading it rather than by calling
	// IsSigned, which reports whether a binary carries a CMS blob. An ad-hoc signature has
	// no CMS blob but is still a signature with a code directory to hash, and refusing to
	// seal one would make ad-hoc signing unusable for any bundle with nested code.
	info, err := readSignedBinaryInfo(exe)
	if err != nil {
		return nil, fmt.Errorf(
			"unable to read the signature of nested bundle %q (sign it before signing the bundle that contains it): %w",
			path.Base(bundlePath), err)
	}

	if err := checkNestedSignature(path.Base(bundlePath), exe, s.cfg.SigningMaterial); err != nil {
		return nil, err
	}

	return info, nil
}

var (
	// errAdhocNestedBundle indicates a nested bundle is ad-hoc signed while its container is
	// being signed with a certificate.
	errAdhocNestedBundle = errors.New("nested bundle is ad-hoc signed but its container is being signed with a certificate")

	// errNestedBundleWithoutRuntime indicates a nested bundle is signed without the hardened
	// runtime while its container is being signed with a certificate.
	errNestedBundleWithoutRuntime = errors.New("nested bundle is signed without the hardened runtime")
)

// checkNestedSignature compares the existing signature of a nested bundle's main executable
// (every architecture slice) with the signing material of the outer bundle. When the outer
// bundle is signed with a certificate, and so with the hardened runtime, an ad-hoc signature
// or one without the hardened runtime is an error, since Apple's notary service rejects both.
// A signature from a different certificate is only a warning, since nested code from a third
// party (e.g. a vendor framework) legitimately keeps its own signature.
func checkNestedSignature(name, exe string, material pki.SigningMaterial) error {
	if material.Signer == nil {
		// an ad-hoc signed container places no requirements on its nested code
		return nil
	}

	signatures, err := codeSignatures(exe)
	if err != nil {
		return fmt.Errorf("unable to read the signature of nested bundle %q: %w", name, err)
	}

	outerLeaf := material.Leaf()
	warned := false
	for _, cs := range signatures {
		if cs == nil || len(cs.CMSSignature) == 0 {
			return fmt.Errorf("%w: re-sign %q with the certificate before signing the bundle that contains it", errAdhocNestedBundle, name)
		}

		if !hasHardenedRuntime(cs) {
			return fmt.Errorf("%w: re-sign %q with the hardened runtime (e.g. with quill, or codesign --options runtime) before signing the bundle that contains it", errNestedBundleWithoutRuntime, name)
		}

		leaf, err := cmsLeafCertificate(cs.CMSSignature)
		if err != nil {
			return fmt.Errorf("unable to read the signing certificate of nested bundle %q: %w", name, err)
		}
		if warned || outerLeaf == nil || leaf == nil || leaf.Equal(outerLeaf) {
			continue
		}

		msg := fmt.Sprintf("nested bundle %q is signed with a different certificate (%q) than its container (%q)",
			name, leaf.Subject.CommonName, outerLeaf.Subject.CommonName)
		bus.Notify("Warning: " + msg)
		log.Warn(msg)
		warned = true
	}
	return nil
}

// hasHardenedRuntime indicates if every code directory of the signature enables the hardened
// runtime.
func hasHardenedRuntime(cs *blacktopMacho.CodeSignature) bool {
	if len(cs.CodeDirectories) == 0 {
		return false
	}
	for _, cd := range cs.CodeDirectories {
		if cd.Header.Flags&blacktopMachoTypes.RUNTIME == 0 {
			return false
		}
	}
	return true
}

// codeSignatures returns the code signature of every architecture slice of the given binary
// (an entry is nil for an unsigned slice).
func codeSignatures(binPath string) ([]*blacktopMacho.CodeSignature, error) {
	f, err := os.Open(binPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if macholibre.IsUniversalMachoBinary(f) {
		ff, err := blacktopMacho.NewFatFile(f)
		if err != nil {
			return nil, fmt.Errorf("unable to parse universal binary: %w", err)
		}
		defer ff.Close()

		var signatures []*blacktopMacho.CodeSignature
		for _, arch := range ff.Arches {
			signatures = append(signatures, arch.CodeSignature())
		}
		return signatures, nil
	}

	mf, err := blacktopMacho.NewFile(f)
	if err != nil {
		return nil, fmt.Errorf("unable to parse binary: %w", err)
	}
	defer mf.Close()
	return []*blacktopMacho.CodeSignature{mf.CodeSignature()}, nil
}

// cmsLeafCertificate returns the signing (non-CA) certificate embedded in a CMS signature, or
// nil if there is none.
func cmsLeafCertificate(cmsSignature []byte) (*x509.Certificate, error) {
	sd, err := cms.ParseSignedData(cmsSignature)
	if err != nil {
		return nil, err
	}
	certs, err := sd.GetCertificates()
	if err != nil {
		return nil, err
	}
	for _, c := range certs {
		if !c.IsCA {
			return c, nil
		}
	}
	return nil, nil
}

// readSignedBinaryInfo computes the code directory hash of a signed binary and a designated
// requirement satisfied by it. For universal binaries, every architecture slice is hashed and
// the requirement is a disjunction across all of them (matching Apple's own tooling): only one
// slice is loaded at runtime, and the seal must be satisfied regardless of which one that is.
// The requirement is synthesized directly from the cdhash(es) rather than read back from the
// binary's own embedded signature, since an ad-hoc signature carries no designated requirement
// at all.
func readSignedBinaryInfo(binPath string) (*bundle.SignedBinaryInfo, error) {
	f, err := os.Open(binPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	thinPaths := []string{binPath}
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
		thinPaths = thinPaths[:0]
		for _, extracted := range extractedFiles {
			thinPaths = append(thinPaths, extracted.Path)
		}
	}

	cdHashes := make([][]byte, 0, len(thinPaths))
	for _, thinPath := range thinPaths {
		cdHash, err := hashCodeDirectory(thinPath)
		if err != nil {
			return nil, err
		}
		cdHashes = append(cdHashes, cdHash)
	}

	return &bundle.SignedBinaryInfo{
		CDHash:      cdHashes[0],
		Requirement: cdHashRequirement(cdHashes),
	}, nil
}

func hashCodeDirectory(binPath string) ([]byte, error) {
	m, err := macho.NewReadOnlyFile(binPath)
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
	return cdHash, nil
}

// cdHashRequirement renders a designated requirement satisfied by any of the given code
// directory hashes, in the same form codesign emits for multi-architecture nested code, e.g.
// `cdhash H"..." or cdhash H"..."`.
func cdHashRequirement(cdHashes [][]byte) string {
	parts := make([]string, len(cdHashes))
	for i, h := range cdHashes {
		parts[i] = fmt.Sprintf(`cdhash H"%s"`, hex.EncodeToString(h))
	}
	return strings.Join(parts, " or ")
}
