package macho

const (
	HashTypeNohash          HashType = 0
	HashTypeSha1            HashType = 1
	HashTypeSha256          HashType = 2
	HashTypeSha256Truncated HashType = 3
	HashTypeSha384          HashType = 4
	HashTypeSha512          HashType = 5
)

type HashType uint8
