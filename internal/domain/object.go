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

// PutMeta is optional upload hints (Content-Type). Identity lives in the
// S3VCTR01 body header, not in S3 user-metadata.
type PutMeta struct {
	ContentType string
}
