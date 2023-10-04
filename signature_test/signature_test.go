package signature_test

import (
	"bufio"
	"log"
	"math/big"
	"os"
	"strconv"
	"testing"
	"trace_ring_sig/point"
	"trace_ring_sig/signature"
)

func TestVerify(t *testing.T) {
	testFile, err := os.Open("test_secp256k1_true.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer testFile.Close()
	var (
		test_sigs []signature.TraceRingSignature
		message   string
		curve     signature.Curve
		n         int
		Pub_keys  []point.Point
		I         point.Point
		C         []big.Int
		R         []big.Int
	)
	scanner := bufio.NewScanner(testFile)
	for scanner.Scan() {
		Pub_keys = *new([]point.Point)
		C = *new([]big.Int)
		R = *new([]big.Int)
		message = scanner.Text()
		scanner.Scan()
		curve = signature.StringToCurve(scanner.Text())
		scanner.Scan()
		n, err = strconv.Atoi(scanner.Text())
		if err != nil {
			log.Fatal(err)
		}
		for i := 0; i < n; i++ {
			scanner.Scan()
			Pub_keys = append(Pub_keys, curve.StringToPoint(scanner.Text()))
		}
		scanner.Scan()
		I = curve.StringToPoint(scanner.Text())
		scanner.Scan()
		n, err = strconv.Atoi(scanner.Text())
		if err != nil {
			log.Fatal(err)
		}
		for i := 0; i < n; i++ {
			scanner.Scan()
			c_i, _ := big.NewInt(0).SetString(scanner.Text(), 0)
			C = append(C, *c_i)
		}
		scanner.Scan()
		n, err = strconv.Atoi(scanner.Text())
		if err != nil {
			log.Fatal(err)
		}
		for i := 0; i < n; i++ {
			scanner.Scan()
			r_i, _ := big.NewInt(0).SetString(scanner.Text(), 0)
			R = append(R, *r_i)
		}
		new_sig := signature.TraceRingSignature{
			Message:  message,
			Curve:    curve,
			Pub_keys: Pub_keys,
			I:        I,
			C:        C,
			R:        R,
		}
		test_sigs = append(test_sigs, new_sig)
	}
	k := 0
	verif := false
	for i := 0; i < 100; i++ {
		verif = signature.Verify(test_sigs[i])
		if !verif {
			t.Errorf("all test signature must be valid")
		}
		k++
	}
	if k != 100 {
		t.Errorf("must be 100 valid signatures")
	}

}
