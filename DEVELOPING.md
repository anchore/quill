# Developing

There are a few useful things to know before diving into the codebase. 

## Getting started

After cloning do the following:
1. run `make bootstrap` to download go mod dependencies, create the `.tmp` dir, and download helper utilities.
2. run `git lfs install` to install git lfs hooks (see [git-lfs](https://git-lfs.github.com/) on how to install git LFS if you don't already have it)
3. run `git lfs pull` to get the test-fixture files from LFS
4. run `make` to run linting, tests, and other verifications to make certain everything is working alright.

The main make tasks for common static analysis and testing are `lint`, `format`, `lint-fix`, and `unit`.

Checkout `make help` to see what other actions you can take.

```
git lfs install
```

## Test fixtures

All test fixtures are stored in the same spot in the repo, `internal/test/test-fixtures/assets`, and are managed by git LFS. 
This is done to keep the repo size down, and to make it easier to manage the fixtures without worrying about storing 
binaries directly in the source repo. If a new fixture requires any specific setup, please create a `Makefile` in a separate
directory within `internal/test/test-fixtures/<NAME>` (where `NAME` is the name of the file created in the `assets` directory).
If there is more than 1 file created by the `Makefile`, ensure all files created and stored in `assets` have the same filename
prefix as `NAME`.

Helpers within tests should be able to use the fixtures by using the `test.Asset()` function (or `test.AssetCopy` if the
test mutates the file). 

## Background

### Macho files

Darwin executables are Mach-O formatted files that have the approximate layout:

```
   ┌──────────────────────────────┐      ┌──────────────────────────────┐
   │                              │      │                              │
   │ Header                       │      │ Header                       │
   │                              │      │                              │
   ├──────────────────────────────┤      ├──────────────────────────────┤
   │ Load Command 1               │      │ Load Command 1               │
   ├──────────────────────────────┤      ├──────────────────────────────┤
   │ Load Command 2               │      │ Load Command 2               │
   ├──────────────────────────────┤      ├──────────────────────────────┤
   │ Load Command ...             │      │ Load Command ...             │
   ├──────────────────────────────┤      ├──────────────────────────────┤
   │ Load Command N               │      │ Load Command N               │
   ├──────────────────────────────┤      ├──────────────────────────────┤
   │                              │      │ Code Signing Load Command    │   <--- added by codesign/quill
   │                              │      ├──────────────────────────────┤        note: this writes into the existing padding
   │           PADDING            │      │                              │        so that the existing section offsets don't
   │                              │      │           PADDING            │        need to be changed.
   │                              │      │                              │
   ├──────────────────────────────┤      ├──────────────────────────────┤
   │                              │      │                              │
   │ Segment 1:  __PAGEZERO       │      │ Segment 1:  __PAGEZERO       │
   │                              │      │                              │
   ├──────────────────────────────┤      ├──────────────────────────────┤
   │                              │      │                              │
   │ Segment 2:  __TEXT           │      │ Segment 2:  __TEXT           │
   │                              │      │                              │
   ├──────────────────────────────┤      ├──────────────────────────────┤
   │                              │      │                              │
   │ Segment ...                  │      │ Segment ...                  │
   │                              │      │                              │
   ├──────────────────────────────┤      ├──────────────────────────────┤
   │                              │      │                              │
   │ Segment N:  __LINKEDIT       │      │ Segment N:  __LINKEDIT       │
   │                              │      │                              │
   └──────────────────────────────┘      ├- - - - - - - - - - - - - - - ┤
                                         │ Code Signing "Super Blob"    │   <--- added by codesign/quill
                                         └──────────────────────────────┘        note: the binary size is expanded past the
                                                                                 end of the file to make room for this.
```

A few definitions:
 
- The header contains basic information about the binary (which architecture the binary expresses, how many load commands there are, etc.)

- A load command is responsible for loading information from raw segments into virtual memory

- A segment contains data references or code to be loaded and executed

- The `__LINKEDIT` segment is information used for dynamic linking and is required to be the last segment in the file (this is important for signing)


### iOS code signing

Code signing adds additional information to the binary that can be used to verify the integrity of the binary itself. 
There are generically two ways to "sign" a macho binary:

- "ad-hoc": checksum each page of the binary and append to the `__LINKEDIT` segment. This can be used to check if the binary has been non-malicously modified. This is **NOT** appropriate for distributing binaries since there is no element of trust.

- "cryptographically": this is usually what you'd think of when you hear "signing"; all of the same information from "ad-hoc" signing is done and additionally added to a PKCS7 envelope (CMS) as signed attributes. 

Signing a macho binary involves:
- adding the signing information to the end of the `__LINKEDIT` segment of the binary
- adding a new `LC_CODE_SIGNATURE` load command that references the signed data

To do this there must be enough existing padding in the binary you want to sign between the last load command and the 
first segment in order to add the new load command. Without this assumption there are several more offsets in other 
load commands and segments that must be updated, which complicates signing a binary considerably. Many compilers
tend to leave enough padding intentionally for the signing process.

The code signature data at the end of the `__LINKEDIT` segment can contain the following information:
- Entitlements blob: an XML PList enumerating the extra capabilities the binary requests access to when in use
- Requirements blob: additional conditions required for the signature to be valid
- Code directory blob: hashes of each page of the binary
- Signature blob: A CMS (PKCS7) envelope containing the cryptographic signature made against the code directory blob

All of these blobs are contained within a single "super blob".


### Historical Notes
- plist with CD hashes as a signed CMS attribute does not appear to be required (was implemented, and now removed)
- sha256 nested set as a signed CMS attribute does not appear to be required (was implemented, and now removed)

#### Useful resources

- Macho binary format: 
  - https://redmaple.tech/blogs/macho-files/
- Macho + iOS Code signing: 
  - https://blog.umangis.me/a-deep-dive-into-ios-code-signing/
  - https://engineering.linecorp.com/en/blog/ios-code-signing/
- Apple's docs on code signing: 
  - https://developer.apple.com/library/archive/technotes/tn2206/_index.html
  - https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements
  - https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes
- Apple's docs on notarization: 
  - https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution
  - https://developer.apple.com/documentation/notaryapi/submitting_software_for_notarization_over_the_web

## Architecture

Quill is designed to be used as a CLI application as well as a library. When used as a library, there are two main
ways to use it:

- Core API: the `github.com/anchore/quill/quill` package, which is where all of the core functionality resides. This is most common when using quill as a library.

- CLI API: the `github.com/anchore/quill/cmd/quill/cli` package, which is a wrapper around the core functionality that
  provides a CLI interface. This is helpful if you are trying to create a wrapping application that extends quill's functionality or are using the core API but want the same bubbletea UI interactions.

Here's the 10,000 foot view of the quill repo:

```
quill/
│
├── cmd/
│   └── quill/
│       ├── cli/              # the CLI API
│       │   ├── commands/       # produce cobra commands
│       │   ├── options/        # composable CLI options used by commands
│       │   ├── ui/             # reusable bubbletea event handler (plugs into a bubbletea application)
│       │   └── cli.go
│       ├── internal/         # internal concerns for the CLI         
│       │   └── ui/             # the bubbletea UI
│       └── main.go           # entrypoint and target for ldflags (version info)
│
├── internal/                 # internal concerns needed by both the CLI and core API
│   ├── bus/                    # global/singleton event bus
│   ├── log/                    # globa/singleton logger
│   ├── test/                   # common test assets and utilities
│   └── constants.go
│
├── quill                     # the "top-level" or "core" API
│   ├── event/                  # all events emitted by quill, with parsers, and parsed types
│   ├── extract/                # string display utils for macho binaries
│   ├── macho/                  # all macho binary types, parsing, and manipulation utils
│   ├── notary/                 # api client for Apple's notarization service
│   ├── pki/                    # all PKI manipulation utils
│   │   ├── apple/                # Apple's PKI material
│   │   ├── certchain/            # utils for searching, sorting, and representing certificate chains
│   │   └── load/                 # utils for reading certificates and key material safely
│   ├── sign/                   # functions for creating the code signature data for macho binaries
│   ├── notarize.go             # notarization API
│   ├── sign.go                 # signing API
│   └── lib.go
│
└── test                        # high-level tests
```

# Known issues

Unit test failure on main when using go 1.20+ with no changes (see [issue #35](https://github.com/anchore/quill/issues/35)):
```
--- FAIL: TestSign (4.84s)
    --- FAIL: TestSign/sign_the_syft_binary_(with_a_password) (0.02s)
        sign_test.go:219: 
                Error Trace:    /Users/wagoodman/code/quill/quill/sign_test.go:219
                Error:          Received unexpected error:
                                unable to parse certificate 1 of 1: x509: certificate contains duplicate extensions
                Test:           TestSign/sign_the_syft_binary_(with_a_password)
```
This is [new behavior in starting in go 1.20](https://groups.google.com/g/golang-checkins/c/nishT5TtWeo). The workaround 
is to use go 1.19 or earlier, but this test fixture will need to be regenerated.
