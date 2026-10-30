package tests

import "runtime/debug"

// raceEnabled reports whether the tests were built with -race (timing checks are skipped then).
var raceEnabled = func() bool {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, s := range bi.Settings {
		if s.Key == "-race" {
			return s.Value == "true"
		}
	}
	return false
}()
