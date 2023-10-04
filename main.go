package main

import (
	"fmt"
	// "math/big"
	// "encoding/hex"
	"trace_ring_sig/curves"
	// "trace_ring_sig/ed25519"
	"trace_ring_sig/point"
	"trace_ring_sig/signature"
	// "filippo.io/edwards25519"
)

func main() {
	curveECC := curves.Secp256k1
	priv_key, pub_key := signature.Gen_keys(curveECC)
	fmt.Println("private key: ", priv_key)
	fmt.Println("public key:  ", curveECC.PointToString(pub_key))
	s := 3
	n := 10
	pub_keys := make([]point.Point, n)
	for i := 0; i < n; i++ {
		if i == s {
			pub_keys[i] = pub_key
		} else {
			_, pub_keys[i] = signature.Gen_keys(curveECC)
			fmt.Println("pub_key ", i, ": ", curveECC.PointToString(pub_keys[i]))
		}
	}
	test_sig := signature.Sign(curveECC, "Hello", pub_keys, s, *priv_key)
	fmt.Println("Signing")
	test := signature.Verify(test_sig)
	fmt.Println("Verify")
	fmt.Println(test)
	test = false
	curveEd := curves.Ed25519
	priv_key, pub_key = signature.Gen_keys(curveEd)
	fmt.Println("private key: ", priv_key)
	fmt.Println("public key:  ", curveEd.PointToString(pub_key))
	for i := 0; i < n; i++ {
		if i == s {
			pub_keys[i] = pub_key
		} else {
			_, pub_keys[i] = signature.Gen_keys(curveEd)
			fmt.Println("pub_key ", i, ": ", curveEd.PointToString(pub_keys[i]))
		}
	}

	test_sig = signature.Sign(curveEd, "Hello", pub_keys, s, *priv_key)
	test = signature.Verify(test_sig)
	fmt.Println("Verify")
	fmt.Println(test)
	fmt.Println("Test link:")
	signature.Link(test_sig)
}
