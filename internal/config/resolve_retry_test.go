package config

import (
	"errors"
	"testing"
	"time"
)

func TestResolveEndpointWithRetry(t *testing.T) {
	origOnce, origBackoff := resolveOnce, resolveEndpointBackoff
	t.Cleanup(func() { resolveOnce, resolveEndpointBackoff = origOnce, origBackoff })
	resolveEndpointBackoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}

	t.Run("succeeds immediately without retrying", func(t *testing.T) {
		calls := 0
		resolveOnce = func(string) (string, error) { calls++; return "1.2.3.4", nil }
		ip, err := resolveEndpointWithRetry("wg.example")
		if err != nil || ip != "1.2.3.4" {
			t.Fatalf("got %q, %v", ip, err)
		}
		if calls != 1 {
			t.Fatalf("expected 1 attempt, got %d", calls)
		}
	})

	t.Run("recovers once DNS comes up (the boot case)", func(t *testing.T) {
		calls := 0
		resolveOnce = func(string) (string, error) {
			calls++
			if calls < 3 {
				return "", errors.New("no such host")
			}
			return "5.6.7.8", nil
		}
		ip, err := resolveEndpointWithRetry("wg.example")
		if err != nil || ip != "5.6.7.8" {
			t.Fatalf("got %q, %v", ip, err)
		}
		if calls != 3 {
			t.Fatalf("expected 3 attempts, got %d", calls)
		}
	})

	t.Run("gives up after the whole schedule", func(t *testing.T) {
		calls := 0
		resolveOnce = func(string) (string, error) { calls++; return "", errors.New("no such host") }
		if _, err := resolveEndpointWithRetry("wg.example"); err == nil {
			t.Fatal("expected an error after exhausting retries")
		}
		if want := len(resolveEndpointBackoff) + 1; calls != want {
			t.Fatalf("expected %d attempts, got %d", want, calls)
		}
	})
}
