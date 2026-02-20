package main

import (
	"fmt"
	"os"
	"os/exec"
)

func main() {
	cmd := exec.Command("iw", "dev")
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("iw dev error: %v\n", err)
	} else {
		fmt.Printf("iw dev output:\n%s\n", string(out))
	}
}
