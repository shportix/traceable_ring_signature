package signature

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"strconv"

	"github.com/shportix/traceable_ring_signature/curves"
	"github.com/shportix/traceable_ring_signature/point"
)

type Curve interface {
	GetOrder() *big.Int
	BasePointGGet() point.Point
	AddPoints(a, b point.Point) point.Point
	ScalarMult(a point.Point, k big.Int) point.Point
	PointToString(point point.Point) (s string)
	StringToPoint(string) (point.Point, error)
	CurveToString() string
}

type TraceRingSignature struct {
	Message  string
	Curve    Curve
	Pub_keys []point.Point
	I        point.Point
	C        []big.Int
	R        []big.Int
}

func StringToCurve(s string) (curve Curve) {
	if s == "ed25519" {
		curve = curves.Ed25519
		return
	}
	curve = curves.Secp256k1
	return
}

func WriteToFile(textWriter *bufio.Writer, s string) error {
	_, err := textWriter.WriteString(s + "\n")
	if err != nil {
		return fmt.Errorf("...%w...", err)
	}
	textWriter.Flush()
	return nil
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
			L[i] = curve.AddPoints(L[i], curve.ScalarMult(pub_keys[i], *w[i]))
			R[i] = curve.AddPoints(R[i], curve.ScalarMult(I, *w[i]))
		}
	}
	txt := message
	for i := 0; i < n; i++ {
		txt += curve.PointToString(L[i]) + curve.PointToString(R[i])
	}
	C := new(big.Int)
	C.SetString(fmt.Sprintf("%X", SHA256StringToString(txt)), 16)
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
	c[s] = *sum.Sub(C, sum)
	c[s] = *c[s].Mod(&c[s], curve.GetOrder())
	r[s] = *big.NewInt(0).Mul(&c[s], &prive_key)
	r[s].Sub(q[s], &r[s])
	r[s].Mod(&r[s], curve.GetOrder())
	C.Mod(C, curve.GetOrder())
	signature := TraceRingSignature{
		Curve:    curve,
		Message:  message,
		Pub_keys: pub_keys,
		I:        I,
		C:        c,
		R:        r,
	}
	return signature
}

func Verify(signature TraceRingSignature) (bool, error) {
	n := len(signature.Pub_keys)
	L := make([]point.Point, n)
	R := make([]point.Point, n)
	sum := big.NewInt(0)
	for i := 0; i < n; i++ {
		sum.Add(sum, &signature.C[i])
		L[i] = signature.Curve.AddPoints(signature.Curve.ScalarMult(signature.Curve.BasePointGGet(), signature.R[i]), signature.Curve.ScalarMult(signature.Pub_keys[i], signature.C[i]))
		R[i] = signature.Curve.AddPoints(signature.Curve.ScalarMult(H_p(signature.Pub_keys[i], signature.Curve), signature.R[i]), signature.Curve.ScalarMult(signature.I, signature.C[i]))
	}
	txt := signature.Message
	for i := 0; i < n; i++ {
		txt += signature.Curve.PointToString(L[i]) + signature.Curve.PointToString(R[i])
	}
	C := new(big.Int)
	C.SetString(fmt.Sprintf("%X", SHA256StringToString(txt)), 16)
	C.Mod(C, signature.Curve.GetOrder())
	sum = sum.Mod(sum, signature.Curve.GetOrder())
	res := C.Cmp(sum) == 0
	if res {
		var sigFile *os.File
		// test_secp256k1_link.txt
		file_name := "signatures.txt"
		_, err := os.Stat(file_name)
		if err != nil {
			if os.IsNotExist(err) {
				sigFile, err = os.Create(file_name)
				if err != nil {
					return false, fmt.Errorf("...%w...", err)
				}
				sigFile.Close()
			} else {
				return false, fmt.Errorf("...%w...", err)
			}
		}
		sigFile, err = os.OpenFile(file_name, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return false, fmt.Errorf("...%w...", err)
		}
		defer sigFile.Close()
		textWriter := bufio.NewWriter(sigFile)

		WriteToFile(textWriter, signature.Message)
		WriteToFile(textWriter, signature.Curve.CurveToString())
		n := len(signature.Pub_keys)
		WriteToFile(textWriter, strconv.Itoa(n))
		for i := 0; i < n; i++ {
			WriteToFile(textWriter, signature.Curve.PointToString(signature.Pub_keys[i]))
		}
		WriteToFile(textWriter, signature.Curve.PointToString(signature.I))
		n = len(signature.C)
		WriteToFile(textWriter, strconv.Itoa(n))
		for i := 0; i < n; i++ {
			WriteToFile(textWriter, signature.C[i].String())
		}
		n = len(signature.R)
		WriteToFile(textWriter, strconv.Itoa(n))
		for i := 0; i < n; i++ {
			WriteToFile(textWriter, signature.R[i].String())
		}

	}

	return res, nil

}

func Link(signature TraceRingSignature, check_signayures []TraceRingSignature) (linked_sig []TraceRingSignature) {
	for i := 0; i < len(check_signayures); i++ {
		buf_I := check_signayures[i].Curve.PointToString(check_signayures[i].I)
		if (check_signayures[i].Curve.CurveToString() == signature.Curve.CurveToString()) && (buf_I == signature.Curve.PointToString(signature.I)) {
			linked_sig = append(linked_sig, check_signayures[i])
		}
	}
	return
}
