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

# TODO
- unit tests
- codesign comparison tests
- ad-hoc signing entrypoint
- allow for multiple certs to be provided
- fix: code signature offset for larger binaries
- add signing requirements derived from cert input
- add signing requirements from user input
- add signing entitlements from usr input
- could this be integrated with gon?
- could this also perform notarization?
- could we add windows signing support?
