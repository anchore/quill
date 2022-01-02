package macho

const LcCodeSignature = 0x1d

// CodeSigningCmd is Mach-O LcCodeSignature load command.
type CodeSigningCmd struct {
	Cmd      uint32 // LcCodeSignature
	Cmdsize  uint32 // sizeof this command (16)
	Dataoff  uint32 // file offset of data in __LINKEDIT segment
	Datasize uint32 // file size of data in __LINKEDIT segment
}
