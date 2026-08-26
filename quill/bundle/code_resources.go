package bundle

import (
	"crypto/sha1" //nolint:gosec // sha1 is required by the CodeResources format (version 1 "files" hashes)
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"howett.net/plist"

	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill/macho"
)

// SignedBinaryInfo describes the code signature of a nested Mach-O binary, used to seal
// the binary into the CodeResources file by its signature instead of a content hash.
type SignedBinaryInfo struct {
	// CDHash is the code directory hash (truncated to 20 bytes)
	CDHash []byte

	// Requirement is the designated requirement in text form (empty for ad-hoc signatures)
	Requirement string
}

// MachOSigner signs a nested Mach-O binary in place and reports the resulting signature info.
type MachOSigner interface {
	SignMachO(path string) (*SignedBinaryInfo, error)
}

// NestedBundleSealer reports the code signature of a nested bundle (a .appex, .framework,
// .xpc, or nested .app) that has already been signed.
//
// Nested bundles are sealed by reference rather than by content: the parent records the
// cdhash and designated requirement of the nested bundle's main executable, and nothing
// inside the nested bundle appears in the parent's seal. That is what Apple's codesign
// produces, and it is why nested code must be signed before its container -- the parent's
// seal depends on the child's signature, so signing in the other order would embed a hash
// of an unsigned binary.
//
// A signer that does not implement this interface keeps the previous behavior: sealing a
// bundle that contains nested bundles is refused rather than silently producing a seal
// that omits them.
type NestedBundleSealer interface {
	SealNestedBundle(bundlePath string) (*SignedBinaryInfo, error)
}

// ResourcesBuilder walks a bundle directory and seals its contents into a CodeResources
// plist (conventionally written to Contents/_CodeSignature/CodeResources).
type ResourcesBuilder struct {
	// rulesV1 and rulesV2 drive file matching and include internal exclusion rules
	rulesV1 []rule
	rulesV2 []rule

	// emittedRulesV1 and emittedRulesV2 are written to the "rules"/"rules2" plist sections
	emittedRulesV1 []rule
	emittedRulesV2 []rule

	files  map[string]any
	files2 map[string]any
}

// NewResourcesBuilder creates a builder seeded with the default application bundle resource
// rules plus exclusions for signing artifacts (the _CodeSignature directory and friends).
func NewResourcesBuilder() *ResourcesBuilder {
	v1 := defaultRulesV1()
	v2 := defaultRulesV2()

	// these paths are byproducts of signing and notarization and must never be sealed
	exclusions := []rule{
		newRule(`^_CodeSignature/`).asExcluded(),
		newRule(`^CodeResources$`).asExcluded(),
		newRule(`^_MASReceipt$`).asExcluded(),
	}

	return &ResourcesBuilder{
		rulesV1:        append(append([]rule{}, v1...), exclusions...),
		rulesV2:        append(append([]rule{}, v2...), exclusions...),
		emittedRulesV1: v1,
		emittedRulesV2: v2,
		files:          map[string]any{},
		files2:         map[string]any{},
	}
}

// ExcludePath excludes an exact normalized path (relative to the bundle Contents directory)
// from sealing. This is used for the bundle's main executable, which is signed after (and
// therefore cannot be part of) the resources seal.
func (b *ResourcesBuilder) ExcludePath(normalizedPath string) error {
	r, err := excludePathRule(normalizedPath)
	if err != nil {
		return err
	}
	b.rulesV1 = append(b.rulesV1, r)
	b.rulesV2 = append(b.rulesV2, r)
	return nil
}

// WalkAndSeal walks the bundle rooted at the given directory, signing nested Mach-O
// binaries with the given signer and recording a seal for every matched file.
func (b *ResourcesBuilder) WalkAndSeal(root string, signer MachOSigner) error {
	return filepath.WalkDir(root, func(fullPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if fullPath == root {
			return nil
		}

		rel, err := filepath.Rel(root, fullPath)
		if err != nil {
			return fmt.Errorf("unable to determine relative path for %q: %w", fullPath, err)
		}
		normalized := normalizePath(filepath.ToSlash(rel))

		if d.IsDir() {
			return b.processDir(fullPath, normalized, d, signer)
		}

		isSymlink := d.Type()&fs.ModeSymlink != 0
		if isSymlink {
			return b.processSymlink(fullPath, normalized)
		}

		if !d.Type().IsRegular() {
			log.WithFields("path", normalized).Warn("skipping irregular file within bundle")
			return nil
		}

		return b.processFile(fullPath, normalized, signer)
	})
}

func (b *ResourcesBuilder) processDir(fullPath, normalized string, d fs.DirEntry, signer MachOSigner) error {
	r := findRule(b.rulesV2, normalized)
	if r == nil {
		return nil
	}
	if r.exclude {
		log.WithFields("path", normalized).Trace("excluding directory from bundle resources")
		return fs.SkipDir
	}
	if r.nested && strings.Contains(d.Name(), ".") {
		// directories with an extension matched by a nested rule are bundles in their own
		// right (e.g. frameworks, plugins, or nested apps) and carry their own signature
		return b.sealNestedBundle(fullPath, normalized, signer)
	}
	return nil
}

// sealNestedBundle records an already-signed nested bundle in the parent's seal and skips
// its contents.
//
// The entry holds the nested bundle's cdhash and designated requirement and nothing else;
// the files within it are covered by its own signature, so repeating them here would both
// duplicate work and diverge from what codesign emits.
func (b *ResourcesBuilder) sealNestedBundle(fullPath, normalized string, signer MachOSigner) error {
	sealer, ok := signer.(NestedBundleSealer)
	if !ok {
		return fmt.Errorf("signing nested bundles is not supported (found %q): sign it separately before signing this bundle", normalized)
	}

	log.WithFields("path", normalized).Trace("sealing nested bundle")

	info, err := sealer.SealNestedBundle(fullPath)
	if err != nil {
		return fmt.Errorf("unable to seal nested bundle %q: %w", normalized, err)
	}

	entry := map[string]any{
		"cdhash": info.CDHash,
	}
	if info.Requirement != "" {
		entry["requirement"] = info.Requirement
	}
	// Nested bundles are sealed only in files2. Apple's codesign does not record them in
	// the version 1 "files" section, which predates nested code.
	b.files2[normalized] = entry

	return fs.SkipDir
}

func (b *ResourcesBuilder) processSymlink(fullPath, normalized string) error {
	r := findRule(b.rulesV2, normalized)
	if r == nil || r.exclude {
		return nil
	}
	if r.omit {
		return nil
	}
	target, err := os.Readlink(fullPath)
	if err != nil {
		return fmt.Errorf("unable to read symlink %q: %w", normalized, err)
	}
	log.WithFields("path", normalized, "target", target).Trace("sealing symlink")
	b.files2[normalized] = map[string]any{
		"symlink": filepath.ToSlash(target),
	}
	return nil
}

func (b *ResourcesBuilder) processFile(fullPath, normalized string, signer MachOSigner) error {
	// version 2 rules: seal by content hash, or by signature for nested code
	rV2 := findRule(b.rulesV2, normalized)
	if rV2 != nil && rV2.exclude {
		log.WithFields("path", normalized).Trace("excluding file from bundle resources")
		return nil
	}

	if rV2 != nil {
		if rV2.nested {
			if err := b.sealNestedMachO(fullPath, normalized, rV2.optional, signer); err != nil {
				return err
			}
		} else if !rV2.omit {
			if err := b.sealFileV2(fullPath, normalized, rV2.optional); err != nil {
				return err
			}
		}
	}

	// version 1 rules: seal regular files by SHA-1 content hash only
	rV1 := findRule(b.rulesV1, normalized)
	if rV1 != nil && !rV1.exclude && !rV1.omit {
		if err := b.sealFileV1(fullPath, normalized, rV1.optional); err != nil {
			return err
		}
	}

	return nil
}

func (b *ResourcesBuilder) sealNestedMachO(fullPath, normalized string, optional bool, signer MachOSigner) error {
	isMachO, err := macho.IsMachoFile(fullPath)
	if err != nil {
		return err
	}
	if !isMachO {
		return fmt.Errorf("file %q matches a nested code resource rule but is not a mach-o binary", normalized)
	}

	log.WithFields("path", normalized).Trace("signing and sealing nested binary")

	info, err := signer.SignMachO(fullPath)
	if err != nil {
		return fmt.Errorf("unable to sign nested binary %q: %w", normalized, err)
	}

	entry := map[string]any{
		"cdhash": info.CDHash,
	}
	if info.Requirement != "" {
		entry["requirement"] = info.Requirement
	}
	if optional {
		entry["optional"] = true
	}
	b.files2[normalized] = entry
	return nil
}

func (b *ResourcesBuilder) sealFileV2(fullPath, normalized string, optional bool) error {
	hash, err := hashFile(fullPath, sha256.New())
	if err != nil {
		return err
	}
	log.WithFields("path", normalized).Trace("sealing file")
	entry := map[string]any{
		"hash2": hash,
	}
	if optional {
		entry["optional"] = true
	}
	b.files2[normalized] = entry
	return nil
}

func (b *ResourcesBuilder) sealFileV1(fullPath, normalized string, optional bool) error {
	hash, err := hashFile(fullPath, sha1.New()) //nolint:gosec // sha1 is required by the CodeResources format
	if err != nil {
		return err
	}
	if optional {
		b.files[normalized] = map[string]any{
			"hash":     hash,
			"optional": true,
		}
	} else {
		b.files[normalized] = hash
	}
	return nil
}

// Assemble renders the accumulated seals and rules as a CodeResources XML plist.
func (b *ResourcesBuilder) Assemble() ([]byte, error) {
	content := map[string]any{
		"files":  b.files,
		"files2": b.files2,
		"rules":  rulesPlistValue(b.emittedRulesV1),
		"rules2": rulesPlistValue(b.emittedRulesV2),
	}

	data, err := plist.MarshalIndent(content, plist.XMLFormat, "\t")
	if err != nil {
		return nil, fmt.Errorf("unable to encode CodeResources plist: %w", err)
	}
	return append(data, '\n'), nil
}

func rulesPlistValue(rules []rule) map[string]any {
	out := map[string]any{}
	for _, r := range rules {
		out[r.pattern.String()] = r.plistValue()
	}
	return out
}

func (r rule) plistValue() any {
	if !r.nested && !r.omit && !r.optional && r.weight == 1 {
		return true
	}
	d := map[string]any{}
	if r.nested {
		d["nested"] = true
	}
	if r.omit {
		d["omit"] = true
	}
	if r.optional {
		d["optional"] = true
	}
	if r.weight != 1 {
		d["weight"] = float64(r.weight)
	}
	return d
}

func hashFile(path string, hasher hash.Hash) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open %q for hashing: %w", path, err)
	}
	defer f.Close()
	if _, err := io.Copy(hasher, f); err != nil {
		return nil, fmt.Errorf("unable to hash %q: %w", path, err)
	}
	return hasher.Sum(nil), nil
}
