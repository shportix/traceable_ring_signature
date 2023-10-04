package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"trace_ring_sig/curves"
	"trace_ring_sig/point"
	"trace_ring_sig/signature"
)

func main() {
	curveECC := curves.Secp256k1
	k := 0

	for i := 0; i < 100; i++ {
		verif := true
		message_big, _ := rand.Int(rand.Reader, curveECC.GetOrder())
		message := message_big.String()
		big_n, _ := rand.Int(rand.Reader, big.NewInt(100))
		big_n.Add(big_n, big.NewInt(1))
		n := int(big_n.Uint64())
		s_big, _ := rand.Int(rand.Reader, big_n)
		s := int(s_big.Uint64())
		ring := make([]point.Point, n)
		priv_key, pub_key := signature.Gen_keys(curveECC)
		priv_key, _ = signature.Gen_keys(curveECC)
		for j := 0; j < n; j++ {
			if j == s {
				ring[j] = pub_key
			} else {
				_, ring[j] = signature.Gen_keys(curveECC)
			}
		}
		new_signature := signature.Sign(curveECC, message, ring, s, *priv_key)
		verif = signature.Verify(new_signature)
		if !verif {
			k++
		}

	}
	fmt.Println("k: ", k)
}
