package signature_test

import (
	"bufio"
	"io"
	"log"
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
		log.Fatal(err)
	}
	defer testFileTrue.Close()
	testFileFalse, err := os.Open("test_secp256k1_false.txt")
	if err != nil {
		log.Fatal(err)
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
		test_sigs[index] = new_sig
		index++
	}
	k = 0
	verif = false
	for i := 0; i < 100; i++ {
		verif = signature.Verify(test_sigs[i])
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
		log.Fatal(err)
	}
	defer testFileTrueED.Close()
	testFileFalseED, err := os.Open("test_ed25519_false.txt")
	if err != nil {
		log.Fatal(err)
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
		test_sigs[index] = new_sig
		index++
	}
	k = 0
	verif = false
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
		test_sigs[index] = new_sig
		index++
	}
	k = 0
	verif = false
	for i := 0; i < 100; i++ {
		verif = signature.Verify(test_sigs[i])
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
	var sigFile, testFile *os.File
	file_name := "signatures.txt"
	_, err := os.Stat(file_name)
	exist := true
	if err != nil {
		if os.IsNotExist(err) {
			exist = false
		} else {
			log.Fatal(err)
		}
	}
	if exist {
		err = os.Remove(file_name)
		if err != nil {
			log.Fatal(err)
		}
	}
	sigFile, err = os.Create(file_name)
	if err != nil {
		log.Fatal(err)
	}
	testFile, err = os.Open("test_link.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer testFile.Close()
	_, err = io.Copy(sigFile, testFile)
	if err != nil {
		log.Fatal(err)
	}
	err = sigFile.Sync()
	if err != nil {
		log.Fatal(err)
	}
	sigFile.Close()
	sigFile, err = os.Open("signatures.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer sigFile.Close()
	scanner := bufio.NewScanner(sigFile)
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
	linked_sig := signature.TraceRingSignature{
		Message:  message,
		Curve:    curve,
		Pub_keys: Pub_keys,
		I:        I,
		C:        C,
		R:        R,
	}
	sigs := signature.Link(linked_sig)
	if len(sigs) != 100 {
		t.Errorf("Link function faild")
	}
}
