# Developing

There are a few useful things to know before diving into the codebase. 

## Getting started

After cloning do the following:
1. run `make bootstrap` to download go mod dependencies, create the `.tmp` dir, and download helper utilities.
2. run `make` to run linting, tests, and other verifications to make certain everything is working alright.

Checkout `make help` to see what other actions you can take.

There is data being referenced that is not checked into the source tree but instead residing in a separate store and is managed via [git-lfs](https://git-lfs.github.com/). You will need to install and initialize git-lfs to work with this repo:

```
git lfs install
```

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
   │                              │      ├──────────────────────────────┤
   │           PADDING            │      │                              │
   │                              │      │           PADDING            │
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
                                         └──────────────────────────────┘

```

A few definitions:
 
- The header contains basic information about the binary (which architecture the binary expresses, how many load commands there are, etc.)

- A load command is responsible for loading information from raw segments into virtual memory

- A segment contains data references or code to be loaded and executed

- The `__LINKEDIT` segment is information used for dynamic linking and is required to be the last segment in the file (this is important for signing)


### iOS code signing

Code signing adds additional information to the binary that can be used to verify the integrity of the binary itself. 
There are generically two ways to "sign" a macho binary:

- "ad-hoc": checksum each page of the binary and append to the `__LINKEDIT` segment. This can be used to check if the binary has been non-malicously modified. This is not appropriate for distributing binaries since there is no element of trust.

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

#### Useful resources

- Macho: https://redmaple.tech/blogs/macho-files/
- Macho + iOS Code signing: https://blog.umangis.me/a-deep-dive-into-ios-code-signing/
- Macho + iOS Code signing: https://engineering.linecorp.com/en/blog/ios-code-signing/
- Apple technical note on code signing: https://developer.apple.com/library/archive/technotes/tn2206/_index.html

