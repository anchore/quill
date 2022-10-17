# Quill

Simple mac binary signing and notarization from any platform (replacing the `codesign` utility for simple use cases).

![quill-demo](https://user-images.githubusercontent.com/590471/196287753-35f3de6c-cd37-4ec1-a67c-05be5f4ed95b.gif)

```bash
$ quill sign-and-notarize --p12 <path-to-p12> <path-to-unsigned-binary>
```

## Usage

First you need to download the signing private key and certificate from Apple. Once you do this you need to attach
the full certificate chain to a new P12 file:

```bash
# run on a mac
$ export QUILL_P12_PASSWORD=<p12-password>

$ quill p12 attach-chain <path-to-p12-from-apple>

# a new P12 file was created with the same name as the original but with the suffix `-with-chain.p12`
```

Note: this step only needs to be done once. This new P12 file (with the full certificate chain) can be used on any platform as many times as you need to sign binaries.

```bash
# run on **any platform** to sign the binary
$ export QUILL_SIGN_P12=<path-to-p12-with-chain>    # can also be base64 encoded contents instead of a file path
$ export QUILL_SIGN_PASSWORD=<p12-password>

$ quill sign <path/to/binary>
```

After signing you can notarize the binary:

```bash
# run on **any platform** to notarize a signed binary
$ export QUILL_NOTARY_KEY=<path-to-private-key-file-from-apple>   # can also be base64 encoded contents instead of a file path
$ export QUILL_NOTARY_KEY_ID=<apple-private-key-id>               # e.g. XS319FABCD
$ export QUILL_NOTARY_ISSUER=<apple-notary-issuer-id>             # e.g. a1234b5-1234-5f5d-b0c8-1234bedc5678

$ quill notarize <path/to/binary>
```

...or you can sign and notarize in one step:

```bash
$ quill sign-and-notarize <path/to/binary>
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

## Commands

- `sign <binary-file>`: sign a mac executable binary
- `notarize <binary-file>`: notarize a signed a mac binary with Apple's Notary service
- `sign-and-notarize <binary-file>` sign and notarize a mac binary
- `submission list`: list previous submissions to Apple's Notary service
- `submission logs <id-file>`: fetch logs for an existing submission from Apple's Notary service
- `submission status <id-file>`: check against Apple's Notary service to see the status of a notarization submission request
- `describe <binary-file>`: show the details of a mac binary
- `extract certificates <binary-file>`:  extract certificates from a signed mac binary
- `p12 attach-chain <p12-file>`: attach the full Apple certificate chain into a p12 file (MUST run on a mac with keychain access)
- `p12 describe <p12-file>`: describe the contents of a p12 file


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
