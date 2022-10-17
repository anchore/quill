package quill

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"

	macholibre "github.com/anchore/go-macholibre"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill/event/monitor"
	"github.com/anchore/quill/quill/macho"
	"github.com/anchore/quill/quill/pem"
	"github.com/anchore/quill/quill/sign"
)

type SigningConfig struct {
	SigningMaterial pem.SigningMaterial
	Identity        string
	Path            string
}

func NewSigningConfigFromPEMs(binaryPath, certificate, privateKey, password string) (*SigningConfig, error) {
	var signingMaterial pem.SigningMaterial
	if certificate != "" {
		sm, err := pem.NewSigningMaterialFromPEMs(certificate, privateKey, password)
		if err != nil {
			return nil, err
		}

		signingMaterial = *sm
	}

	return &SigningConfig{
		Path:            binaryPath,
		Identity:        path.Base(binaryPath),
		SigningMaterial: signingMaterial,
	}, nil
}

func NewSigningConfigFromP12(binaryPath, p12, password string) (*SigningConfig, error) {
	signingMaterial, err := pem.NewSigningMaterialFromP12(p12, password)
	if err != nil {
		return nil, err
	}

	return &SigningConfig{
		Path:            binaryPath,
		Identity:        path.Base(binaryPath),
		SigningMaterial: *signingMaterial,
	}, nil
}

func (c *SigningConfig) WithIdentity(id string) *SigningConfig {
	if id != "" {
		c.Identity = id
	}
	return c
}

func (c *SigningConfig) WithTimestampServer(url string) *SigningConfig {
	c.SigningMaterial.TimestampServer = url
	return c
}

func Sign(cfg SigningConfig) error {
	f, err := os.Open(cfg.Path)
	if err != nil {
		return err
	}
	defer f.Close()

	if macholibre.IsUniversalMachoBinary(f) {
		return signMultiarchBinary(cfg)
	}

	mon := bus.PublishTask(
		monitor.Title{
			Default:      "Sign binary",
			WhileRunning: "Signing binary",
			OnSuccess:    "Signed binary",
		},
		cfg.Path,
		-1,
	)

	err = signSingleBinary(cfg)
	if err != nil {
		mon.Err = err
	} else {
		mon.SetCompleted()
	}
	return err
}

//nolint:funlen
func signMultiarchBinary(cfg SigningConfig) error {
	log.WithFields("binary", cfg.Path).Info("signing multi-arch binary")

	f, err := os.Open(cfg.Path)
	if err != nil {
		return err
	}
	defer f.Close()

	dir, err := ioutil.TempDir("", "quill-extract-"+path.Base(cfg.Path))
	if err != nil {
		return fmt.Errorf("unable to create temp directory to extract multi-arch binary: %w", err)
	}
	defer os.RemoveAll(dir)

	extractMon := bus.PublishTask(
		monitor.Title{
			Default:      "Extract universal binary",
			WhileRunning: "Extracting universal binary",
			OnSuccess:    "Extracted universal binary",
		},
		cfg.Path,
		-1,
	)

	extractedFiles, err := macholibre.Extract(f, dir)
	if err != nil {
		extractMon.Err = err
		return fmt.Errorf("unable to extract multi-arch binary: %w", err)
	}

	extractMon.Stage.Current = fmt.Sprintf("%d nested binaries", len(extractedFiles))

	extractMon.SetCompleted()

	log.WithFields("binary", cfg.Path, "arches", len(extractedFiles)).Trace("discovered nested binaries within multi-arch binary")

	var cfgs []SigningConfig
	for _, ef := range extractedFiles {
		c := cfg
		c.Path = ef.Path
		cfgs = append(cfgs, c)
	}

	signMon := bus.PublishTask(
		monitor.Title{
			Default:      "Sign binaries",
			WhileRunning: "Signing binaries",
			OnSuccess:    "Signed binaries",
		},
		cfg.Path,
		len(cfgs),
	)

	packMon := bus.PublishTask(
		monitor.Title{
			Default:      "Repack universal binary",
			WhileRunning: "Repacking universal binary",
			OnSuccess:    "Repacked universal binary",
		},
		cfg.Path,
		-1,
	)

	defer signMon.SetCompleted()

	for _, c := range cfgs {
		signMon.Stage.Current = path.Base(c.Path)
		if err := signSingleBinary(c); err != nil {
			signMon.Err = err
			return err
		}
		signMon.N++
	}

	signMon.Stage.Current = ""

	var paths []string
	for _, c := range cfgs {
		paths = append(paths, c.Path)
	}

	log.WithFields("binary", cfg.Path, "arches", len(cfgs)).Debug("packaging signed binaries into single multi-arch binary")

	defer packMon.SetCompleted()

	if err := macholibre.Package(cfg.Path, paths...); err != nil {
		packMon.Err = err
		return err
	}

	return nil
}

func signSingleBinary(cfg SigningConfig) error {
	log.WithFields("binary", cfg.Path).Info("signing binary")

	m, err := macho.NewFile(cfg.Path)
	if err != nil {
		return err
	}

	// check there already isn't a LcCodeSignature loader already (if there is, bail)
	if m.HasCodeSigningCmd() {
		log.Debug("binary already signed, removing signature...")
		if err := m.RemoveSigningContent(); err != nil {
			return fmt.Errorf("unable to remove existing code signature: %+v", err)
		}
	}

	if cfg.SigningMaterial.Signer == nil {
		bus.Notify("Warning: performed ad-hoc sign, which means that anyone can alter the binary contents without you knowing (there is no cryptographic signature)")
		log.Warnf("only ad-hoc signing, which means that anyone can alter the binary contents without you knowing (there is no cryptographic signature)")
	}

	// (patch) add empty LcCodeSignature loader (offset and size references are not set)
	if err = m.AddEmptyCodeSigningCmd(); err != nil {
		return err
	}

	// first pass: add the signed data with the dummy loader
	log.Debugf("estimating signing material size")
	superBlobSize, sbBytes, err := sign.GenerateSigningSuperBlob(cfg.Identity, m, cfg.SigningMaterial, 0)
	if err != nil {
		return fmt.Errorf("failed to add signing data on pass=1: %w", err)
	}

	// (patch) make certain offset and size references to the superblob are finalized in the binary
	log.Debugf("patching binary with updated superblob offsets")
	if err = sign.UpdateSuperBlobOffsetReferences(m, uint64(len(sbBytes))); err != nil {
		return nil
	}

	// second pass: now that all of the sizing is right, let's do it again with the final contents (replacing the hashes and signature)
	log.Debug("creating signature for binary")
	_, sbBytes, err = sign.GenerateSigningSuperBlob(cfg.Identity, m, cfg.SigningMaterial, superBlobSize)
	if err != nil {
		return fmt.Errorf("failed to add signing data on pass=2: %w", err)
	}

	// (patch) append the superblob to the __LINKEDIT section
	log.Debugf("patching binary with signature")

	codeSigningCmd, _, err := m.CodeSigningCmd()
	if err != nil {
		return err
	}

	if err = m.Patch(sbBytes, len(sbBytes), uint64(codeSigningCmd.DataOffset)); err != nil {
		return fmt.Errorf("failed to patch super blob onto macho binary: %w", err)
	}

	return nil
}
