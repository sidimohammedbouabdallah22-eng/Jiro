package main

import "os"

func reloadSignals() (<-chan os.Signal, func()) { return nil, func() {} }
