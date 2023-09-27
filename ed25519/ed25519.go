package ed25519

import (
	"fmt"
	"math/big"
	"trace_ring_sig/point"

	"filippo.io/edwards25519"
)

var Curve = *new(EdCurve)

type EdCurve struct {
}

type EdPoint struct {
	point edwards25519.Point
}

func (p EdPoint) X() *big.Int {
	return big.NewInt(0)
}

func (p EdPoint) Y() *big.Int {
	return big.NewInt(0)
}

func (p EdPoint) Point() edwards25519.Point {
	return p.point
}

func (c EdCurve) GetOrder() *big.Int {
	buf, _ := big.NewInt(0).SetString("27742317777372353535851937790883648493", 0)
	l := big.NewInt(2)
	l.Exp(l, big.NewInt(252), nil)
	l.Add(l, buf)
	return l
}

func (c EdCurve) BasePointGGet() point.Point {
	ed_point := *edwards25519.NewGeneratorPoint()
	p := EdPoint{ed_point}
	return p
}

func (c EdCurve) AddECPoints(a, b point.Point) point.Point {
	v := new(edwards25519.Point)
	a_p := a.Point()
	b_p := b.Point()
	v.Add(&a_p, &b_p)
	p := EdPoint{*v}
	return p
}

func (c EdCurve) ScalarMult(a point.Point, k big.Int) point.Point {
	v := new(edwards25519.Point)
	k_scal := edwards25519.NewScalar()
	k_bytes := k.Bytes()
	buf := make([]byte, 32)
	if len(k_bytes) < 32 {
		for i := 31; i > len(k_bytes)-1; i-- {
			buf[i] = 0
		}
		for i := 0; i < len(k_bytes); i++ {
			buf[i] = k_bytes[i]
		}
		k_bytes = buf
	}
	for i := 0; i < 32; i++ {
		buf[i] = k_bytes[31-i]
	}
	k_bytes = buf
	k_scal, err := k_scal.SetCanonicalBytes(k_bytes)
	if err != nil {
		fmt.Println(err)
	}
	a_p := a.Point()
	v.ScalarMult(k_scal, &a_p)
	p := EdPoint{*v}
	return p
}

func (c EdCurve) PointToString(point point.Point) (s string) {
	point_p := point.Point()
	point_bytes := point_p.Bytes()
	s = fmt.Sprintf("%X", point_bytes) + " "
	return
}
