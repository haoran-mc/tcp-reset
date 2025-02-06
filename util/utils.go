package util

import (
	"runtime"
)

func GoroutineID() int {
	return runtime.NumGoroutine()
}
