package signature_test

import (
	"bufio"
	"math/big"
	"os"
	"strconv"
	"testing"
	"trace_ring_sig/point"
	"trace_ring_sig/signature"
)

func TestVerify(t *testing.T) {
	testFileTrue, err := os.Open("test_secp256k1_true.txt")
	if err != nil {
		t.Errorf(err.Error())
	}
	defer testFileTrue.Close()
	testFileFalse, err := os.Open("test_secp256k1_false.txt")
	if err != nil {
		t.Errorf("Can`t open file test_secp256k1_false.txt")
	}
	defer testFileFalse.Close()
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
	scanner := bufio.NewScanner(testFileTrue)
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
			t.Errorf(err.Error())
		}
		for i := 0; i < n; i++ {
			scanner.Scan()
			p, _ := curve.StringToPoint(scanner.Text())
			Pub_keys = append(Pub_keys, p)
		}
		scanner.Scan()
		I, _ = curve.StringToPoint(scanner.Text())
		scanner.Scan()
		n, err = strconv.Atoi(scanner.Text())
		if err != nil {
			t.Errorf(err.Error())
		}
		for i := 0; i < n; i++ {
			scanner.Scan()
			c_i, _ := big.NewInt(0).SetString(scanner.Text(), 0)
			C = append(C, *c_i)
		}
		scanner.Scan()
		n, err = strconv.Atoi(scanner.Text())
		if err != nil {
			t.Errorf(err.Error())
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
		verif, _ = signature.Verify(test_sigs[i])
		if !verif {
			t.Errorf("all test signature must be valid")
		}
		k++
	}
	if k != 100 {
		t.Errorf("must be 100 valid signatures")
	}

	scanner = bufio.NewScanner(testFileFalse)
	index := 0
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
			t.Errorf(err.Error())
		}
		for i := 0; i < n; i++ {
			scanner.Scan()
			p, _ := curve.StringToPoint(scanner.Text())
			Pub_keys = append(Pub_keys, p)
		}
		scanner.Scan()
		I, _ = curve.StringToPoint(scanner.Text())
		scanner.Scan()
		n, err = strconv.Atoi(scanner.Text())
		if err != nil {
			t.Errorf(err.Error())
		}
		for i := 0; i < n; i++ {
			scanner.Scan()
			c_i, _ := big.NewInt(0).SetString(scanner.Text(), 0)
			C = append(C, *c_i)
		}
		scanner.Scan()
		n, err = strconv.Atoi(scanner.Text())
		if err != nil {
			t.Errorf(err.Error())
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
		test_sigs[index] = new_sig
		index++
	}
	k = 0
	verif = false
	for i := 0; i < 100; i++ {
		verif, _ = signature.Verify(test_sigs[i])
		if verif {
			t.Errorf("all test signature must be invalid")
		}
		k++
	}
	if k != 100 {
		t.Errorf("must be 100 invalid signatures")
	}

	testFileTrueED, err := os.Open("test_ed25519_true.txt")
	if err != nil {
		t.Errorf(err.Error())
	}
	defer testFileTrueED.Close()
	testFileFalseED, err := os.Open("test_ed25519_false.txt")
	if err != nil {
		t.Errorf(err.Error())
	}
	defer testFileFalseED.Close()
	// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	index = 0
	scanner = bufio.NewScanner(testFileTrueED)
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
			t.Errorf(err.Error())
		}
		for i := 0; i < n; i++ {
			scanner.Scan()
			p, _ := curve.StringToPoint(scanner.Text())
			Pub_keys = append(Pub_keys, p)
		}
		scanner.Scan()
		I, _ = curve.StringToPoint(scanner.Text())
		scanner.Scan()
		n, err = strconv.Atoi(scanner.Text())
		if err != nil {
			t.Errorf(err.Error())
		}
		for i := 0; i < n; i++ {
			scanner.Scan()
			c_i, _ := big.NewInt(0).SetString(scanner.Text(), 0)
			C = append(C, *c_i)
		}
		scanner.Scan()
		n, err = strconv.Atoi(scanner.Text())
		if err != nil {
			t.Errorf(err.Error())
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
		test_sigs[index] = new_sig
		index++
	}
	k = 0
	verif = false
	for i := 0; i < 100; i++ {
		verif, _ = signature.Verify(test_sigs[i])
		if !verif {
			t.Errorf("all test signature must be valid")
		}
		k++
	}
	if k != 100 {
		t.Errorf("must be 100 valid signatures")
	}

	scanner = bufio.NewScanner(testFileFalseED)
	index = 0
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
			t.Errorf(err.Error())
		}
		for i := 0; i < n; i++ {
			scanner.Scan()
			p, _ := curve.StringToPoint(scanner.Text())
			Pub_keys = append(Pub_keys, p)
		}
		scanner.Scan()
		I, _ = curve.StringToPoint(scanner.Text())
		scanner.Scan()
		n, err = strconv.Atoi(scanner.Text())
		if err != nil {
			t.Errorf(err.Error())
		}
		for i := 0; i < n; i++ {
			scanner.Scan()
			c_i, _ := big.NewInt(0).SetString(scanner.Text(), 0)
			C = append(C, *c_i)
		}
		scanner.Scan()
		n, err = strconv.Atoi(scanner.Text())
		if err != nil {
			t.Errorf(err.Error())
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
		test_sigs[index] = new_sig
		index++
	}
	k = 0
	verif = false
	for i := 0; i < 100; i++ {
		verif, _ = signature.Verify(test_sigs[i])
		if verif {
			t.Errorf("all test signature must be invalid")
		}
		k++
	}
	if k != 100 {
		t.Errorf("must be 100 invalid signatures")
	}
}

func TestLink(t *testing.T) {
	var file *os.File
	file_name := "test_link.txt"
	file, err := os.Open(file_name)
	scanner := bufio.NewScanner(file)
	var (
		message  string
		curve    signature.Curve
		n        int
		Pub_keys []point.Point
		I        point.Point
		C        []big.Int
		R        []big.Int
	)
	scanner.Scan()
	message = scanner.Text()
	scanner.Scan()
	curve = signature.StringToCurve(scanner.Text())
	scanner.Scan()
	n, err = strconv.Atoi(scanner.Text())
	if err != nil {
		t.Errorf(err.Error())
	}
	for i := 0; i < n; i++ {
		scanner.Scan()
		p, _ := curve.StringToPoint(scanner.Text())
		Pub_keys = append(Pub_keys, p)
	}
	scanner.Scan()
	I, _ = curve.StringToPoint(scanner.Text())
	scanner.Scan()
	n, err = strconv.Atoi(scanner.Text())
	if err != nil {
		t.Errorf(err.Error())
	}
	for i := 0; i < n; i++ {
		scanner.Scan()
		c_i, _ := big.NewInt(0).SetString(scanner.Text(), 0)
		C = append(C, *c_i)
	}
	scanner.Scan()
	n, err = strconv.Atoi(scanner.Text())
	if err != nil {
		t.Errorf(err.Error())
	}
	for i := 0; i < n; i++ {
		scanner.Scan()
		r_i, _ := big.NewInt(0).SetString(scanner.Text(), 0)
		R = append(R, *r_i)
	}
	linked_sig := signature.TraceRingSignature{
		Message:  message,
		Curve:    curve,
		Pub_keys: Pub_keys,
		I:        I,
		C:        C,
		R:        R,
	}
	var other_sigs []signature.TraceRingSignature
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
			t.Errorf(err.Error())
		}
		for i := 0; i < n; i++ {
			scanner.Scan()
			p, _ := curve.StringToPoint(scanner.Text())
			Pub_keys = append(Pub_keys, p)
		}
		scanner.Scan()
		I, _ = curve.StringToPoint(scanner.Text())
		scanner.Scan()
		n, err = strconv.Atoi(scanner.Text())
		if err != nil {
			t.Errorf(err.Error())
		}
		for i := 0; i < n; i++ {
			scanner.Scan()
			c_i, _ := big.NewInt(0).SetString(scanner.Text(), 0)
			C = append(C, *c_i)
		}
		scanner.Scan()
		n, err = strconv.Atoi(scanner.Text())
		if err != nil {
			t.Errorf(err.Error())
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
		other_sigs = append(other_sigs, new_sig)

	}
	sigs := signature.Link(linked_sig, other_sigs)
	if len(sigs) != 99 {
		t.Errorf("Link function faild")
	}
}
