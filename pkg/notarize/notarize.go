package notarize

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/anchore/quill/internal/log"
)

type Config struct {
	Timeout     time.Duration
	Poll        time.Duration
	httpTimeout time.Duration
	tokenConfig tokenConfig
}

func NewConfig(issuer, privateKeyID, privateKey string) Config {
	timeout := 10 * time.Minute
	return Config{
		Timeout:     timeout,
		Poll:        10 * time.Second,
		httpTimeout: 30 * time.Second,
		tokenConfig: tokenConfig{
			issuer:        issuer,
			privateKeyID:  privateKeyID,
			tokenLifetime: timeout + (2 * time.Minute),
			privateKey:    privateKey,
		},
	}
}

/*

Source: https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution

Apple's notary service requires you to adopt the following protections:

- Enable code-signing for all of the executables you distribute, and ensure that executables have valid code signatures,
  as described in Ensure a valid code signature.
  See https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution/resolving_common_notarization_issues#3087735

- Use a “Developer ID” application, kernel extension, system extension, or installer certificate for your code-signing
  signature. (Don't use a Mac Distribution, ad hoc, Apple Developer, or local development certificate.) Verify the
  certificate type before submitting, as described in Use a valid Developer ID certificate.
  See https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution/resolving_common_notarization_issues#3087721
  For more information, see Create, export, and delete signing certificates: https://help.apple.com/xcode/mac/current/#/dev154b28f09

- Enable the Hardened Runtime capability for your app and command line targets, as described in Enable hardened runtime.
  See https://help.apple.com/xcode/mac/current/#/devf87a2ac8f

- Include a secure timestamp with your code-signing signature. (The Xcode distribution workflow includes a secure
  timestamp by default. For custom workflows, see Include a secure timestamp.)
  See https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution/resolving_common_notarization_issues#3087733

- Don’t include the com.apple.security.get-task-allow entitlement with the value set to any variation of true. If your
  software hosts third-party plug-ins and needs this entitlement to debug the plug-in in the context of a host
  executable, see Avoid the get-task-allow entitlement.
  See https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution/resolving_common_notarization_issues#3087731

- Link against the macOS 10.9 or later SDK, as described in Use the macOS 10.9 SDK or later.
  See https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution/resolving_common_notarization_issues#3087723

- Ensure your processes have properly-formatted XML, ASCII-encoded entitlements as described in Ensure properly
  formatted entitlements.
  See https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution/resolving_common_notarization_issues#3561456

*/

func Notarize(path string, cfg Config) error {
	log.Infof("notarizing %q", path)

	token, err := newSignedToken(cfg.tokenConfig)
	if err != nil {
		return err
	}

	a, err := newAPIClient(token, cfg.httpTimeout)
	if err != nil {
		return fmt.Errorf("unable to initialize submission API session: %+v", err)
	}

	bin, err := newPayload(path)
	if err != nil {
		return err
	}

	sub := newSubmission(a, bin)

	if err := sub.start(context.Background()); err != nil {
		return fmt.Errorf("unable to start submission: %+v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	var status SubmissionStatus = PendingStatus

	for !status.isCompleted() {
		select {
		case <-ctx.Done():
			return errors.New("timeout waiting for notarize submission response")

		default:
			time.Sleep(cfg.Poll)

			status, err = sub.status(ctx)
			if err != nil {
				return err
			}
		}
	}

	if !status.isSuccessful() {
		logs, err := sub.logs(ctx)
		if err != nil {
			return err
		}
		return fmt.Errorf("submission result is %+v: %+v", status, logs)
	}

	return nil
}
