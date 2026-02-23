//go:build windows
// +build windows

package runner

import (
	"context"
	"log"

	"golang.org/x/sys/windows/svc"
)

func RunServiceHook(runFunc func(context.Context)) {
	isInteractive, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("failed to determine if interactive session: %v", err)
	}

	if isInteractive {
		runFunc(context.Background())
		return
	}

	err = svc.Run("wantasticd", &wantasticService{runFunc: runFunc})
	if err != nil {
		log.Fatalf("windows service failed: %v", err)
	}
}

type wantasticService struct {
	runFunc func(context.Context)
}

func (m *wantasticService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		m.runFunc(ctx)
		close(done)
	}()

loop:
	for {
		select {
		case <-done:
			break loop
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				cancel()
				<-done
				break loop
			default:
				log.Printf("unexpected control request #%d", c)
			}
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	return
}
