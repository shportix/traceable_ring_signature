package curves

import (
	"trace_ring_sig/eccsecp256k1"
	"trace_ring_sig/ed25519"

	"github.com/ubiq/go-ubiq/crypto/secp256k1"
)

var (
	Secp256k1 = eccsecp256k1.ECCurve{Curve: secp256k1.S256()}
	Ed25519   = *new(ed25519.EdCurve)
)
