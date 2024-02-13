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

func AssertNoError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("Error raised: %v", err)
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
