package redact

import "github.com/anchore/go-logger/adapter/redact"

var (
	store redact.Store
)

func Set(s redact.Store) {
	store = s
}

func Add(vs ...string) {
	if store == nil {
		// if someone is trying to add values that should never be output and we don't have a store then something is wrong.
		// we should never accidentally output values that should be redacted, thus we panic here.
		panic("cannot add redactions without a store")
	}
	store.Add(vs...)
}

func Apply(value string) string {
	if store == nil {
		// if someone is trying to add values that should never be output and we don't have a store then something is wrong.
		// we should never accidentally output values that should be redacted, thus we panic here.
		panic("cannot apply redactions without a store")
	}
	return store.RedactString(value)
}
