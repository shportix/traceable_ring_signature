package main

import (
	"fmt"
	// "math/big"
	"trace_ring_sig/curves"
	"trace_ring_sig/point"
	"trace_ring_sig/signature"
)

func main() {
	curveED := curves.Ed25519
	k := 0
	for i := 0; i < 100; i++ {
		_, pub_key := signature.Gen_keys(curveED)
		priv_key, _ := signature.Gen_keys(curveED)
		s := 3
		var ring []point.Point
		for j := 0; j < 10; j++ {
			if j == s {
				ring = append(ring, pub_key)
			} else {
				_, p_k := signature.Gen_keys(curveED)
				ring = append(ring, p_k)
			}
		}
		message := "jklfdhgslkfhjlgskfdsbnstpivlwyreontbviw[brepo]69b0-54"
		new_sig := signature.Sign(curveED, message, ring, s, *priv_key)
		verif := signature.Verify(new_sig)
		if !verif {
			k++
		}
	}
	fmt.Println(k)

}
