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


## Not supported
- interacting with the keychain
- multiple code directories / multiple digest hashes

## TODO

- [x] unit tests
- [x] codesign comparison tests
- [x] ad-hoc signing entrypoint
- [x] allow for cert chain to be provided and verified
- [x] fix: code signature offset for larger binaries
- [ ] add signing requirements derived from cert chain input
- [ ] add signing requirements from user input
- [ ] add signing entitlements from usr input
- [ ] add support for universal binaries (partially done, needs to wrap the signing function)
- [ ] Check that input 509 certs have the v3 extensions necessary for codesigning
- [ ] Support pkcs12 envelopes instead of key + cert + chain input

*Future opportunities*
- could this also perform notarization?
- could we add windows signing support?