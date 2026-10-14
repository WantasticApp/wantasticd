package runner

import (
	"fmt"
	"io"
	"os/exec"
	"runtime"
)

func copyToClipboard(text string) error {
	if text == "" {
		return nil
	}

	var candidates [][]string
	switch runtime.GOOS {
	case "darwin":
		candidates = [][]string{{"pbcopy"}}
	case "windows":
		candidates = [][]string{{"clip"}}
	default:
		candidates = [][]string{
			{"wl-copy"},
			{"xclip", "-selection", "clipboard"},
			{"xsel", "--clipboard", "--input"},
		}
	}

	var lastErr error
	for _, candidate := range candidates {
		if _, err := exec.LookPath(candidate[0]); err != nil {
			lastErr = err
			continue
		}
		cmd := exec.Command(candidate[0], candidate[1:]...)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			lastErr = err
			continue
		}
		if err := cmd.Start(); err != nil {
			stdin.Close()
			lastErr = err
			continue
		}
		if _, err := io.WriteString(stdin, text); err != nil {
			stdin.Close()
			cmd.Wait()
			lastErr = err
			continue
		}
		if err := stdin.Close(); err != nil {
			cmd.Wait()
			lastErr = err
			continue
		}
		if err := cmd.Wait(); err != nil {
			lastErr = err
			continue
		}
		return nil
	}

	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("no clipboard command available")
}
