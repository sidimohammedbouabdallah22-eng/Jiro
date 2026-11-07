//go:build !unix && !windows

package main

import "errors"

func processCPU() (float64, error) {
	return 0, errors.New("qualification CPU measurement is unsupported on this OS")
}
