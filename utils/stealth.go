package utils

import (
	"math/rand"
	"time"
)

func CalculateDelayWithJitter(baseDelaySeconds int, jitterPercent int) time.Duration {
	if baseDelaySeconds <= 0 {
		return 0
	}

	baseDelay := time.Duration(baseDelaySeconds) * time.Second

	if jitterPercent > 0 && jitterPercent <= 100 {
		jitterAmount := float64(baseDelay.Nanoseconds()) * (float64(jitterPercent) / 100.0)
		randomJitter := (rand.Float64()*2 - 1) * jitterAmount
		finalDelay := time.Duration(float64(baseDelay.Nanoseconds()) + randomJitter)
		if finalDelay < 0 {
			finalDelay = 0
		}
		return finalDelay
	}

	return baseDelay
}

func CalculateStealthDelay(sleepPtr *int, jitterPtr *int) time.Duration {
	if sleepPtr == nil || *sleepPtr <= 0 {
		return 0
	}

	jitterPercent := 0
	if jitterPtr != nil {
		jitterPercent = *jitterPtr
	}

	return CalculateDelayWithJitter(*sleepPtr, jitterPercent)
}
