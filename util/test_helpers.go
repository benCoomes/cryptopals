package util

import (
	"bufio"
	"os"
	"testing"
)

func AssertEqual[K comparable](t *testing.T, expected K, actual K) {
	if expected != actual {
		t.Errorf("Expected %v, got %v", expected, actual)
	}
}

func AssertSliceEqual[K comparable, S []K](t *testing.T, expected S, actual S) {
	// choosing not to compare capacity, only length
	if len(expected) != len(actual) {
		t.Errorf("Expected %v, got %v", expected, actual)
		return
	}

	for i := 0; i < len(expected); i++ {
		if expected[i] != actual[i] {
			t.Errorf("Expected %v, got %v", expected, actual)
			return
		}
	}
}

func RefuteEqual[K comparable](t *testing.T, a K, b K) {
	if a == b {
		t.Errorf("Expected %v and %v to be unequal", a, b)
	}
}

func RefuteSliceEqual[K comparable, S []K](t *testing.T, a S, b S) {
	if len(a) != len(b) {
		return
	}

	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return
		}
	}

	t.Errorf("Expected %v and %v to be unequal", a, b)
}

func RefuteError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("Error raised: %v", err)
	}
}

func AssertError(t *testing.T, err error) {
	if err == nil {
		t.Error("Expected an error but found nil")
	}
}

func ReadFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lines := make([]string, 0)
	// warning: lines over 64K will be incomplete
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

func ReadFileBytes(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	bytes := make([]byte, 0)
	// warning: lines over 64K will be incomplete
	for scanner.Scan() {
		bytes = append(bytes, scanner.Bytes()...)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return bytes, nil
}
