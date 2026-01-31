package utils

import (
	"sync"
	"time"
)

// Global time synchronization variables
var (
	serverTimeDiff time.Duration
	timeDiffMu     sync.RWMutex
)

// GetServerTimeDiff returns the current time difference between server and local time
func GetServerTimeDiff() time.Duration {
	timeDiffMu.RLock()
	defer timeDiffMu.RUnlock()
	return serverTimeDiff
}

// GetCorrectedTime returns the current time adjusted by server time difference
func GetCorrectedTime() time.Time {
	timeDiffMu.RLock()
	diff := serverTimeDiff
	timeDiffMu.RUnlock()
	return time.Now().UTC().Add(diff)
}

// UpdateTimeDiffFromUnix updates the time difference using a Unix timestamp (seconds)
func UpdateTimeDiffFromUnix(serverUnixTime int64) {
	if serverUnixTime <= 0 {
		return
	}

	serverTime := time.Unix(serverUnixTime, 0).UTC()
	updateTimeDiff(serverTime)
}

// UpdateTimeDiffFromDateHeader extracts server time from HTTP Date header (RFC1123 format)
// Example: "Tue, 27 Jan 2026 13:23:21 GMT"
func UpdateTimeDiffFromDateHeader(dateHeader string) {
	if dateHeader == "" {
		return
	}

	serverTime, err := time.Parse(time.RFC1123, dateHeader)
	if err != nil {
		return
	}

	updateTimeDiff(serverTime)
}

// updateTimeDiff is the internal function to update time diff
func updateTimeDiff(serverTime time.Time) {
	localTime := time.Now().UTC()
	newDiff := serverTime.Sub(localTime)

	timeDiffMu.Lock()
	oldDiff := serverTimeDiff
	serverTimeDiff = newDiff
	timeDiffMu.Unlock()

	if oldDiff != newDiff {
		// fmt.Printf("[TimeSync] Time diff updated: %v -> %v (server: %v, local: %v)\n",
		// 	oldDiff, newDiff, serverTime.Format(time.RFC3339), localTime.Format(time.RFC3339))
	}
}
