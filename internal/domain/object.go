package domain

import "time"

// ObjectMeta describes an S3 object. Identity fields (SHA256, Encrypted, …)
// come from the S3VCTR01 body header for new objects; legacy objects may still
// expose them via user-metadata on HEAD/GET.
type ObjectMeta struct {
	Key                 string
	Size                int64
	ETag                string
	LastModified        time.Time
	SHA256              string
	ContentSize         int64
	Encrypted           string // none / native / command
	Wrap                string // rsa-oaep / keyfile / ""
	Provider            string // command provider (e.g. cryptopro)
	FormatVersion       string
	CryptoProThumbprint string // SHA-1 of recipient cert when enc=command
	Exists              bool
}

// PutMeta carries upload hints and the plaintext identity of a containerless
// object. Identity for a container object lives in the S3VCTR01 body header;
// without a container there is nowhere to put it in the body, so it travels in
// PutMeta and the store exposes it on HEAD (S3 user-metadata).
type PutMeta struct {
	ContentType string
	// PlaintextSHA256 is the hex digest of the plaintext payload, set only when
	// the object is written without a container (encryption.mode=none). Empty for
	// container objects, whose header already carries it.
	PlaintextSHA256 string
	// PlaintextSize is the plaintext payload length, the same two values the
	// container header would carry. Used by identity.Decide to reject a digest
	// match against an object of a different size.
	PlaintextSize int64
}
