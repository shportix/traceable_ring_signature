package main

import (
	"fmt"
	"trace_ring_sig/ecc"
	"trace_ring_sig/ed25519"
	"trace_ring_sig/point"
	"trace_ring_sig/signature"
)

func main() {
	curveECC := ecc.Curve
	prive_key, _ := signature.Gen_keys(curveECC)
	n := 5
	pub_keys := make([]point.Point, n)
	for i := 0; i < n; i++ {
		prive_key, pub_keys[i] = signature.Gen_keys(curveECC)
	}
	test_sig := signature.Sign(curveECC, "Hello", pub_keys, 4, *prive_key)
	test := signature.Verify(test_sig)
	fmt.Println(test)
	test = false
	curveEd := ed25519.Curve
	for i := 0; i < n; i++ {
		prive_key, pub_keys[i] = signature.Gen_keys(curveEd)
	}
	test_sig = signature.Sign(curveEd, "Hello", pub_keys, 4, *prive_key)
	test = signature.Verify(test_sig)
	fmt.Println(test)

}
