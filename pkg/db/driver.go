package db

import (
	"sort"
	"strings"
	"sync"

	"gorm.io/gorm"
)

// DialectorFunc creates a gorm.Dialector for a given database DSN.
type DialectorFunc func(dsn string) gorm.Dialector

var (
	driverMu sync.RWMutex
	drivers  = make(map[string]DialectorFunc)
)

// RegisterDriver registers a database driver factory function under the specified name.
// Names are case-insensitive. Attempting to register an empty name or nil function panics.
func RegisterDriver(name string, fn DialectorFunc) {
	if fn == nil {
		panic("db: driver factory function cannot be nil")
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		panic("db: driver name cannot be empty")
	}

	driverMu.Lock()
	defer driverMu.Unlock()
	drivers[name] = fn
}

// GetDriver returns the driver factory function registered under the specified name.
func GetDriver(name string) (DialectorFunc, bool) {
	driverMu.RLock()
	defer driverMu.RUnlock()
	fn, ok := drivers[strings.ToLower(strings.TrimSpace(name))]
	return fn, ok
}

// RegisteredDrivers returns a sorted list of all currently registered driver names.
func RegisteredDrivers() []string {
	driverMu.RLock()
	defer driverMu.RUnlock()
	names := make([]string, 0, len(drivers))
	for name := range drivers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
