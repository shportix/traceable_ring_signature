package main

import (
	"fmt"
	// "math/big"
	"trace_ring_sig/curves"
	"trace_ring_sig/point"
	"trace_ring_sig/signature"
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

	// fmt.Println("I:    ", curveEd.PointToString(test_sig.I))

	// I := curveEd.ScalarMult(signature.H_p(pub_key, curveEd), *priv_key)
	// fmt.Println("I:    ", curveEd.PointToString(I))
	// L := curveEd.ScalarMult(curveEd.BasePointGGet(), *test_sig.Q[s])
	// R := curveEd.ScalarMult(signature.H_p(pub_keys[s], curveEd), *test_sig.Q[s])
	// fmt.Println("L:    ", curveEd.PointToString(L))
	// fmt.Println("R:    ", curveEd.PointToString(R))
	// Q_r := curveEd.ScalarMult(curveEd.BasePointGGet(), test_sig.R[s])
	// fmt.Println("Q*r:  ", curveEd.PointToString(Q_r))
	// P_c := curveEd.ScalarMult(test_sig.Pub_keys[s], test_sig.C[s])
	// fmt.Println("P*c:  ", curveEd.PointToString(P_c))
	// L = curveEd.AddPoints(Q_r, P_c)
	// tt := big.NewInt(1)
	// tt.Mul(priv_key, &test_sig.C[s])
	// fmt.Println("c_x:  ", tt)
	// tt.Add(&test_sig.R[s], tt)
	// fmt.Println("r_c_x:", tt)
	// tt.Mod(tt, curveEd.GetOrder())
	// fmt.Println("q    :", tt)
	// fmt.Println("L:    ", curveEd.PointToString(L))
	// p := L.Point()
	// fmt.Println("L_X  :", p.)
	// H_P_r := curveEd.ScalarMult(signature.H_p(test_sig.Pub_keys[s], curveEd), test_sig.R[s])
	// fmt.Println("H_P_r:", curveEd.PointToString(H_P_r))
	// I_c := curveEd.ScalarMult(test_sig.I, test_sig.C[s])
	// fmt.Println("I_c:  ", curveEd.PointToString(I_c))
	// R = curveEd.AddPoints(H_P_r, I_c)
	// fmt.Println("R:    ", curveEd.PointToString(R))
	// fmt.Println("Signing")
	fmt.Println("Verify")
	fmt.Println(test)

}
