package main

import (
	"fmt"

	"github.com/shportix/traceable_ring_signature/curves"
	"github.com/shportix/traceable_ring_signature/point"
	"github.com/shportix/traceable_ring_signature/signature"
)

func main() {
	curveSC := curves.Secp256k1
	mess := "gfjkdjlk"
	priv_key, pub_key := signature.Gen_keys(curveSC)
	var (
		ring     []point.Point
		ring_key point.Point
	)
	s := 3
	for i := 0; i < 10; i++ {
		if i == s {
			ring = append(ring, pub_key)
		} else {
			_, ring_key = signature.Gen_keys(curveSC)
			ring = append(ring, ring_key)
		}
	}
	scepcSig := signature.Sign(curveSC, mess, ring, s, *priv_key)
	verif := false
	verif, _ = signature.Verify(scepcSig)
	fmt.Println("Secp256k1:", verif)
	curveED := curves.Ed25519
	priv_key, pub_key = signature.Gen_keys(curveED)
	for i := 0; i < 10; i++ {
		if i != s {
			_, ring_key = signature.Gen_keys(curveED)
			ring[i] = ring_key
		} else {
			ring[i] = pub_key
		}

	}
	sigED := signature.Sign(curveED, mess, ring, s, *priv_key)
	verif, _ = signature.Verify(sigED)
	fmt.Println("Ed25519:", verif)
}
