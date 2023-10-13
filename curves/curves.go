package curves

import (
	"github.com/shportix/traceable_ring_signature/eccsecp256k1"
	"github.com/shportix/traceable_ring_signature/ed25519"

	"github.com/ubiq/go-ubiq/crypto/secp256k1"
)

var (
	Secp256k1 = eccsecp256k1.ECCurve{Curve: secp256k1.S256()}
	Ed25519   = *new(ed25519.EdCurve)
)
