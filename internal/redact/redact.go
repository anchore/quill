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
		panic("cannot add redactions without a store")
	}
	store.Add(vs...)
}

func Apply(value string) string {
	if store == nil {
		panic("cannot apply redactions without a store")
	}
	return store.RedactString(value)
}
