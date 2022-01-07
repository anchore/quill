package macho

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewBlob(t *testing.T) {
	type args struct {
		magic   Magic
		payload []byte
	}
	tests := []struct {
		name string
		args args
		want Blob
	}{
		{
			name: "gocase",
			args: args{
				magic:   MagicCodedirectory,
				payload: []byte("payload!"),
			},
			want: Blob{
				BlobHeader: BlobHeader{
					Magic:  MagicCodedirectory,
					Length: 4 + 4 + 8, // magic + length + payload
				},
				Payload: []byte("payload!"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, NewBlob(tt.args.magic, tt.args.payload), "NewBlob(%v, %v)", tt.args.magic, tt.args.payload)
		})
	}
}
