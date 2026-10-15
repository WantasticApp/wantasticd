//go:build !linux && !windows && !darwin

package dns

import "context"

func Apply(ctx context.Context, req Request) (Result, error) {
	select {
	case <-ctx.Done():
		return Result{}, ctx.Err()
	default:
	}
	servers := desiredServers(req, nil)
	return Result{
		Skipped: true,
		Method:  "unsupported",
		Reason:  "platform DNS adapter is not implemented yet",
		Servers: servers,
	}, nil
}

func removeTunnel(string) error { return nil }
