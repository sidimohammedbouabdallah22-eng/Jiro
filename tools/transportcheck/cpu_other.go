//go:build !windows && !linux

package main

import "errors"

func processCPUSeconds() (float64, error) {
	return 0, errors.New("generator CPU measurement is qualified only on Windows and Linux")
}
