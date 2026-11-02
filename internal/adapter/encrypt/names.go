package encrypt

// Object-format names and the two legal native wrap names. They are exported
// because the fetch scope selects a reader by these strings; keeping one copy
// avoids drift between profile parsing, S3VCTR01 and the facade.
const (
	NameNone    = "none"
	NameNative  = "native"
	NameCommand = "command"

	WrapRSAOAEP = "rsa-oaep"
	WrapKeyfile = "keyfile"
)
