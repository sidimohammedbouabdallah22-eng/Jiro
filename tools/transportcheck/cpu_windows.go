package main

import "golang.org/x/sys/windows"

func processCPUSeconds() (float64, error) {
	var created, exited, kernel, user windows.Filetime
	err := windows.GetProcessTimes(windows.CurrentProcess(), &created, &exited, &kernel, &user)
	ticks := uint64(kernel.HighDateTime)<<32 | uint64(kernel.LowDateTime)
	ticks += uint64(user.HighDateTime)<<32 | uint64(user.LowDateTime)
	return float64(ticks) / 1e7, err
}
