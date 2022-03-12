# Quill

Simple mac binary signing from any platform. This can replace the mac `codesign` utility for simple use cases.

```bash
# show signing information embedded in a macho-formatted (darwin) binary
$ quill show <path/to/binary>

# Do "ad-hoc" signing of the binary (same as codesign --force -s - <binary>)
# note: there is no crytographic signing info with this option!
$ quill sign <path/to/binary>

# sign the binary (this is probably what you want)
$ quill sign <path/to/binary> --key <path/to/PEM/key> --cert <path/to/PEM/cert>
```

CURRENT STATE: verified that adding requirements blob won't quite do the trick... there is something else that is wrong... but requirements are now hardcoded
... next... decode cms block from good hello signef binary and comb through diffs

## Troubleshooting Codesigning Validation
- Add empty requirements set to match that of other signed binaries
- Assert all attribute OIDs match
- Check that the first hash block is being set correctly
- Is the extra padding after the superblock causing issues? (not aligned? too small? too large?)
- Check "TeamIdentifier=not set" from codesign output (other is TeamIdentifier=not set, but syft signed is derived from cert info it seems)
- Check "Authority=(unavailable)" from codesign output (other is Authority=quill-test-hello)
- Diff: Time CMS attribute is local timezone, not zulu

Notes:
- PKCS7 digest differs for syft_signed vs hello_signed... this is because syft was signed with multiple code directories (sha1 and sha256)
- How can pkcs7 verify() work if apple overrides the digest for its own purposes? In short... it can't! Since the envelopes have no message (only attributes), the hash would be the same for all binaries.
- Verify "Signature size=1900" while the real signed one is "Signature size=1885"... these being different by itself seems alright, since this is not a fixed size block

## Not supported
- interacting with the keychain
- multiple code directories / multiple digest hashes

## TODO

- [x] unit tests
- [x] codesign comparison tests
- [x] ad-hoc signing entrypoint
- [ ] allow for cert chain to be provided and verified
- [x] fix: code signature offset for larger binaries
- [ ] add signing requirements derived from cert chain input
- [ ] add signing requirements from user input
- [ ] add signing entitlements from usr input
- [ ] add support for universal binaries (partially done, needs to wrap the signing function)
- [ ] Check that input 509 certs have the v3 extensions necessary for codesigning
- [ ] Support pkcs12 envelopes instead of key + cert input

*Future opportunities*
- could this be integrated with gon?
- could this also perform notarization?
- could we add windows signing support?