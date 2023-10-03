package point

import (
	"math/big"

	"filippo.io/edwards25519"
)

type Point interface {
	X() *big.Int
	Y() *big.Int
	Point() edwards25519.Point
	SetPoint(edwards25519.Point) edwards25519.Point
}
