# Quill

Simple mac binary signing and notarization from any platform (replacing the `codesign` utility for simple use cases).

![quill-demo](https://user-images.githubusercontent.com/590471/196287753-35f3de6c-cd37-4ec1-a67c-05be5f4ed95b.gif)

```bash
$ quill sign-and-notarize --p12 [path-to-p12] [path-to-unsigned-binary]
```

## Installation

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/quill/main/install.sh | sh -s -- -b /usr/local/bin
```

... or, you can specify a release version and destination directory for the installation:

```
curl -sSfL https://raw.githubusercontent.com/anchore/quill/main/install.sh | sh -s -- -b <DESTINATION_DIR> <RELEASE_VERSION>
```


## Usage

First you need to download the signing private key and certificate from Apple (this is in the form of a ".p12" file). 

```bash
# run on **any platform** to sign the binary

$ export QUILL_SIGN_P12=[path-to-p12]         # can also be base64 encoded contents instead of a file path
$ export QUILL_SIGN_PASSWORD=[p12-password]

$ quill sign [path/to/binary]
```

**Note**: The signing certificate must be issued by Apple and the full certificate chain must be available at 
signing time. See the section below on ["Attaching the full certificate chain"](#attaching-the-full-certificate-chain) if you do not wish to rely on the 
[Apple intermediate and root certificates](https://www.apple.com/certificateauthority/) embedded into the Quill binary.

After signing you can notarize the binary against Apple's notary service:

```bash
$ export QUILL_NOTARY_KEY=[path-to-private-key-file-from-apple]   # can also be base64 encoded contents instead of a file path
$ export QUILL_NOTARY_KEY_ID=[apple-private-key-id]               # e.g. XS319FABCD
$ export QUILL_NOTARY_ISSUER=[apple-notary-issuer-id]             # e.g. a1234b5-1234-5f5d-b0c8-1234bedc5678

$ quill notarize [path/to/binary]
```

...or you can sign and notarize in one step:

```bash
$ quill sign-and-notarize [path/to/binary]
```

Here's an example of using quill with goreleaser:
```yaml
# .goreleaser.yml
builds:
  - binary: my-app
    goos:
      - darwin
    goarch:
      - amd64
      - arm64
    hooks:
      post:
        # The binary is signed and notarized when running a production release, but for snapshot builds notarization is
        # skipped and only ad-hoc signing is performed (not cryptographic material is needed).
        #
        # note: environment variables required for signing and notarization (set in CI) but are not needed for snapshot builds
        #    QUILL_SIGN_P12, QUILL_SIGN_PASSWORD, QUILL_NOTARY_KEY, QUILL_NOTARY_KEY_ID, QUILL_NOTARY_ISSUER
        - cmd: quill sign-and-notarize "{{ .Path }}" --dry-run={{ .IsSnapshot }} --ad-hoc={{ .IsSnapshot }} -vv
          env:
            - QUILL_LOG_FILE=/tmp/quill-{{ .Target }}.log
```

### Attaching the full certificate chain

In order to pass notarization with Apple you must use:

1. A signing certificate that is issued by Apple
2. Have the full certificate chain available at signing time

Without the full chain, Apple will reject the notarization request with the following error:
```json
{
  "issues": [
    {
      "severity": "error",
      "code": null,
      "message": "The signature of the binary is invalid.",
      "docUrl": "https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution/resolving_common_notarization_issues#3087735"
    },
    {
      "severity": "error",
      "code": null,
      "message": "The signature does not include a secure timestamp.",
      "docUrl": "https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution/resolving_common_notarization_issues#3087733"
    }
  ]
}
```

Quill can attach the full certificate chain at signing time with the Apple root and intermediate certificates embedded 
into the Quill binary (obtained from [Apple](https://www.apple.com/certificateauthority/) directly). However, an
alternative to this approach is to attach the full certificate chain to your P12 file:

```bash
# run on a mac if you want to use certs from your keychain.
# otherwise this will embed any matching Apple certs that are found within Quill into the P12 file.

$ export QUILL_P12_PASSWORD=[p12-password]

$ quill p12 attach-chain [path-to-p12-from-apple]

# a new P12 file was created with the suffix `-with-chain.p12`
```

At this point you can use `quill p12 describe` to confirm the full certificate chain is attached.


## Commands

- `sign [binary-file]`: sign a mac executable binary
- `notarize [binary-file]`: notarize a signed a mac binary with Apple's Notary service
- `sign-and-notarize [binary-file]` sign and notarize a mac binary
- `submission list`: list previous submissions to Apple's Notary service
- `submission logs [id]`: fetch logs for an existing submission from Apple's Notary service
- `submission status [id]`: check against Apple's Notary service to see the status of a notarization submission request
- `describe [binary-file]`: show the details of a mac binary
- `extract certificates [binary-file]`:  extract certificates from a signed mac binary
- `p12 attach-chain [p12-file]`: attach the full Apple certificate chain into a p12 file (MUST run on a mac with keychain access)
- `p12 describe [p12-file]`: describe the contents of a p12 file


## Configuration
Search locations: `.quill.yaml`, `quill.yaml`, `.quill/config.yaml`, `~/.quill.yaml`, `~/quill.yaml`, `$XDG_CONFIG_HOME/quill/config.yaml`

```yaml
log:
  # suppress logging output (env var: "QUILL_LOG_QUIET")
  quiet: false
  
  # error, warn, info, debug, trace (env var: "QUILL_LOG_LEVEL")
  level: "info"
  
  # file to write all loge entries to (env var: "QUILL_LOG_FILE")
  file: ""
```

## Why make this?

The mac `codesign` utility is great, but it's not available on all platforms. For cross-platform toolchains like golang
this can get painful in subtle ways. Goreleaser is a great "one-shot" release solution, but requiring running on a mac
just for the signing step now forces the reset of your build steps to work on a mac as well -- and since this is part
of the release process, it needs to work in CI. This is a problem since, [due to licensing reasons, the default mac
runner for github actions cannot have docker installed by default](https://github.com/actions/runner-images/issues/17#issuecomment-614726536).
This means that you need to resort to installing docker on a mac in CI first before getting started, which can take
upwards of 20 minutes.

Unlike docker, which inherently needs to run on a linux host (docker on a mac is a VM), there is nothing inherently
mac-specific about signing a binary. This tool enables already cross-platform toolchains to run the signing step on
any platform.

