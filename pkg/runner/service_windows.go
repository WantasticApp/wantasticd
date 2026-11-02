//go:build windows
// +build windows

package runner

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// ServiceLogPath is where the service writes its log: a service has no
// console, so without it every startup error is lost.
func ServiceLogPath() string {
	dir := os.Getenv("ProgramData")
	if dir == "" {
		dir = `C:\ProgramData`
	}
	return filepath.Join(dir, "Wantastic", "wantasticd.log")
}

// logToServiceFile sends the log, and stderr (panics, fatal errors), to
// ServiceLogPath. The previous log is kept as .1 once it passes 5 MB.
func logToServiceFile() {
	path := ServiceLogPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	if fi, err := os.Stat(path); err == nil && fi.Size() > 5<<20 {
		os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	log.SetOutput(f)
	os.Stdout, os.Stderr = f, f
	windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, windows.Handle(f.Fd()))
	windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(f.Fd()))
	log.Printf("wantasticd service starting (pid %d)", os.Getpid())
}

func RunServiceHook(runFunc func(context.Context)) {
	// IsWindowsService is true only when the Service Control Manager started
	// this process; commands typed in a console run in the foreground.
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("failed to determine whether running as a Windows service: %v", err)
	}

	if !isService {
		runFunc(context.Background())
		return
	}
	logToServiceFile()

	err = svc.Run("wantasticd", &wantasticService{runFunc: runFunc})
	if err != nil {
		log.Fatalf("windows service failed: %v", err)
	}
}

// serviceStopWait bounds a service stop; the SCM gives up on its own at 30 s.
const serviceStopWait = 25 * time.Second

type wantasticService struct {
	runFunc func(context.Context)
}

func (m *wantasticService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
				// Report the stop at once, then wait a bounded time: the SCM
				// otherwise shows the service RUNNING while it waits, and a
				// component that ignores cancellation would hang it forever.
				changes <- svc.Status{State: svc.StopPending, WaitHint: uint32(serviceStopWait / time.Millisecond)}
				cancel()
				select {
				case <-done:
				case <-time.After(serviceStopWait):
					log.Printf("service stop: the agent did not finish within %s; exiting anyway", serviceStopWait)
				}
				break loop
			default:
				log.Printf("unexpected control request #%d", c)
			}
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	return
}

// detachedProcAttr starts a child without a console, in its own process
// group, so it outlives this process.
func detachedProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
}
