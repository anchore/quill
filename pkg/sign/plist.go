package sign

import (
	"bytes"
	"fmt"

	"howett.net/plist"
)

func generatePList(hashes [][]byte) ([]byte, error) {
	buff := bytes.Buffer{}
	encoder := plist.NewEncoder(&buff)
	encoder.Indent("\t")

	if err := encoder.Encode(map[string][][]byte{"cdhashes": hashes}); err != nil {
		return nil, fmt.Errorf("unable to generate plist: %w", err)
	}

	return buff.Bytes(), nil
}
