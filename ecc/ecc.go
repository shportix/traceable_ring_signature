package ecc

import (
	"fmt"
	"math/big"
	"trace_ring_sig/point"

	"filippo.io/edwards25519"

	"strings"

	"github.com/ubiq/go-ubiq/crypto/secp256k1"
)

var Curve = ECCurve{secp256k1.S256()}

type ECCurve struct {
	Curve *secp256k1.BitCurve
}

type ECPoint struct {
	x *big.Int
	y *big.Int
}

func (p ECPoint) X() *big.Int {
	return p.x
}

func (p ECPoint) Y() *big.Int {
	return p.y
}

func (p ECPoint) Point() edwards25519.Point {
	return *new(edwards25519.Point)
}

func (p ECPoint) SetPoint(point edwards25519.Point) edwards25519.Point {
	return point
}

func (c ECCurve) GetOrder() *big.Int {
	return Curve.Curve.N
}

func (c ECCurve) BasePointGGet() point.Point {
	point := ECPoint{Curve.Curve.Gx, Curve.Curve.Gy}
	return point
}

func (c ECCurve) AddPoints(a, b point.Point) point.Point {
	x, y := Curve.Curve.Add(a.X(), a.Y(), b.X(), b.Y())
	p := ECPoint{x, y}
	return p
}

func (c ECCurve) ScalarMult(a point.Point, k big.Int) point.Point {
	x, y := Curve.Curve.ScalarMult(a.X(), a.Y(), k.Bytes())
	p := ECPoint{x, y}
	return p
}

func (c ECCurve) PointToString(point point.Point) (s string) {
	s = fmt.Sprintf("%X", point.X()) + " " + fmt.Sprintf("%X", point.Y())
	return
}

func (c ECCurve) StringToPoint(s string) (point point.Point) {
	buf := strings.Split(s, " ")
	X, _ := big.NewInt(0).SetString(buf[0], 16)
	Y, _ := big.NewInt(0).SetString(buf[1], 16)
	point = ECPoint{
		x: X,
		y: Y,
	}
	return
}

func (c ECCurve) CurveToString() (s string) {
	s = "secp256k1"
	return
}
