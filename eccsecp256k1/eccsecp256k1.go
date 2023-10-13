package eccsecp256k1

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/shportix/traceable_ring_signature/point"

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

func (c ECCurve) GetOrder() *big.Int {
	return Curve.Curve.N
}

func (c ECCurve) BasePointGGet() point.Point {
	point := ECPoint{Curve.Curve.Gx, Curve.Curve.Gy}
	return point
}

func (c ECCurve) AddPoints(a, b point.Point) point.Point {
	x, y := Curve.Curve.Add(a.X(), a.Y(), b.X(), b.Y())
	return ECPoint{x, y}
}

func (c ECCurve) ScalarMult(a point.Point, k big.Int) point.Point {
	x, y := Curve.Curve.ScalarMult(a.X(), a.Y(), k.Bytes())
	return ECPoint{x, y}
}

func (c ECCurve) PointToString(point point.Point) (s string) {
	return fmt.Sprintf("%X", point.X()) + " " + fmt.Sprintf("%X", point.Y())
}

func (c ECCurve) StringToPoint(s string) (point.Point, error) {
	buf := strings.Split(s, " ")
	var p point.Point
	if len(buf) == 2 {
		X, _ := big.NewInt(0).SetString(buf[0], 16)
		Y, _ := big.NewInt(0).SetString(buf[1], 16)
		p = ECPoint{
			x: X,
			y: Y,
		}
	} else {
		return p, errors.New("Invalid string")
	}
	return p, nil
}

func (c ECCurve) CurveToString() (s string) {
	return "secp256k1"
}
