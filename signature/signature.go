package signature

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"trace_ring_sig/point"
)

type Curve interface {
	GetOrder() *big.Int
	BasePointGGet() point.Point
	AddECPoints(a, b point.Point) point.Point
	ScalarMult(a point.Point, k big.Int) point.Point
	PointToString(point point.Point) (s string)
}

type TraceRingSignature struct {
	message  string
	curve    Curve
	pub_keys []point.Point
	I        point.Point
	c        []big.Int
	r        []big.Int
}

func SHA256StringToString(message string) (digest string) {
	var dig [32]byte = sha256.Sum256([]byte(message))
	digest = string(dig[:])
	return
}

func H_p(point point.Point, curve Curve) point.Point {
	H_pub_key := new(big.Int)
	H_pub_key.SetString(fmt.Sprintf("%X", SHA256StringToString(curve.PointToString(point))), 16)
	H_pub_key.Mod(H_pub_key, curve.GetOrder())
	new_p := curve.ScalarMult(curve.BasePointGGet(), *H_pub_key)
	return new_p
}

func Gen_keys(curve Curve) (prive_key *big.Int, pub_key point.Point) {
	prive_key, err := rand.Int(rand.Reader, curve.GetOrder())
	if err == nil {
		pub_key = curve.ScalarMult(curve.BasePointGGet(), *prive_key)
		return
	}
	return nil, nil
}

func Sign(curve Curve, message string, pub_keys []point.Point, s int, prive_key big.Int) TraceRingSignature {
	I := curve.ScalarMult(H_p(pub_keys[s], curve), prive_key)
	n := len(pub_keys)
	q := make([]*big.Int, n)
	w := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		q[i], _ = rand.Int(rand.Reader, big.NewInt(1).Sub(curve.GetOrder(), big.NewInt(1)))
		q[i] = big.NewInt(1).Add(q[i], big.NewInt(1))
		w[i], _ = rand.Int(rand.Reader, big.NewInt(1).Sub(curve.GetOrder(), big.NewInt(1)))
		w[i] = big.NewInt(1).Add(w[i], big.NewInt(1))
	}
	L := make([]point.Point, n)
	R := make([]point.Point, n)
	for i := 0; i < n; i++ {
		L[i] = curve.ScalarMult(curve.BasePointGGet(), *q[i])
		R[i] = curve.ScalarMult(H_p(pub_keys[i], curve), *q[i])
		if i != s {
			L[i] = curve.AddECPoints(L[i], curve.ScalarMult(pub_keys[i], *w[i]))
			R[i] = curve.AddECPoints(R[i], curve.ScalarMult(I, *w[i]))
		}
	}
	txt := message
	for i := 0; i < n; i++ {
		txt += curve.PointToString(L[i]) + curve.PointToString(R[i])
	}
	C := new(big.Int)
	C.SetString(fmt.Sprintf("%X", SHA256StringToString(txt)), 16)
	C.Mod(C, curve.GetOrder())
	c := make([]big.Int, n)
	r := make([]big.Int, n)
	sum := big.NewInt(0)
	for i := 0; i < n; i++ {
		if i != s {
			sum.Add(sum, w[i])
			c[i] = *w[i]
			r[i] = *q[i]
		}
	}
	sum = sum.Mod(sum, curve.GetOrder())
	c[s] = *sum.Sub(C, sum)
	c[s] = *c[s].Mod(&c[s], curve.GetOrder())
	r[s] = *big.NewInt(0).Mul(&c[s], &prive_key)
	r[s].Sub(q[s], &r[s])
	r[s].Mod(&r[s], curve.GetOrder())

	signature := TraceRingSignature{
		curve:    curve,
		message:  message,
		pub_keys: pub_keys,
		I:        I,
		c:        c,
		r:        r,
	}
	return signature
}

func Verify(signature TraceRingSignature) bool {
	n := len(signature.pub_keys)
	L := make([]point.Point, n)
	R := make([]point.Point, n)
	sum := big.NewInt(0)
	for i := 0; i < n; i++ {
		sum.Add(sum, &signature.c[i])
		L[i] = signature.curve.AddECPoints(signature.curve.ScalarMult(signature.curve.BasePointGGet(), signature.r[i]), signature.curve.ScalarMult(signature.pub_keys[i], signature.c[i]))
		R[i] = signature.curve.AddECPoints(signature.curve.ScalarMult(H_p(signature.pub_keys[i], signature.curve), signature.r[i]), signature.curve.ScalarMult(signature.I, signature.c[i]))
	}
	txt := signature.message
	for i := 0; i < n; i++ {
		txt += signature.curve.PointToString(L[i]) + signature.curve.PointToString(R[i])
	}
	C := new(big.Int)
	C.SetString(fmt.Sprintf("%X", SHA256StringToString(txt)), 16)
	C.Mod(C, signature.curve.GetOrder())
	sum = sum.Mod(sum, signature.curve.GetOrder())
	return C.Cmp(sum) == 0

}
