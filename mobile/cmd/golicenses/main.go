// Command golicenses writes the license of every Go module compiled into the
// Android engine as JSON, for the app's open-source notices.
//
//	go run ./cmd/golicenses -o ../android/app/libs/assets/go-licenses.json
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type module struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	License string `json:"license"`
}

func main() {
	out := flag.String("o", "go-licenses.json", "output file")
	flag.Parse()

	// Every module whose packages the engine links, with its directory;
	// gomobile adds its own bind/seq glue to the library.
	cmd := exec.Command("go", "list", "-deps", "-f", "{{with .Module}}{{.Path}}\t{{.Version}}\t{{.Dir}}{{end}}", ".", "golang.org/x/mobile/bind/seq")
	cmd.Env = append(os.Environ(), "GOOS=android", "GOARCH=arm64", "CGO_ENABLED=1")
	listed, err := cmd.Output()
	if err != nil {
		log.Fatalf("go list: %v", err)
	}
	seen := map[string]bool{}
	var mods []module
	for _, line := range strings.Split(strings.TrimSpace(string(listed)), "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) != 3 || seen[parts[0]] {
			continue
		}
		seen[parts[0]] = true
		path, version, dir := parts[0], parts[1], parts[2]
		if path == "wantastic-agent" || path == "wantastic-agent/mobile" {
			continue // Wantastic's own code
		}
		text, err := licenseText(dir)
		if err != nil {
			log.Fatalf("%s: %v", path, err)
		}
		mods = append(mods, module{Path: path, Version: version, License: text})
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Path < mods[j].Path })

	// The Go runtime and standard library are compiled in too. Their license
	// is embedded: some Go installs (Homebrew) ship without the file.
	goVersion, err := exec.Command("go", "env", "GOVERSION").Output()
	if err != nil {
		log.Fatalf("go env GOVERSION: %v", err)
	}
	mods = append([]module{{Path: "Go (runtime and standard library)", Version: strings.TrimSpace(string(goVersion)), License: goLicense}}, mods...)

	data, err := json.MarshalIndent(mods, "", " ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, append(data, '\n'), 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d modules -> %s\n", len(mods), *out)
}

// licenseText reads a module's license file; a module without one fails the
// build rather than shipping without its notice.
func licenseText(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var parts [][]byte
	for _, e := range entries {
		name := strings.ToUpper(e.Name())
		if e.IsDir() || !(strings.HasPrefix(name, "LICENSE") || strings.HasPrefix(name, "LICENCE") || strings.HasPrefix(name, "COPYING") || name == "NOTICE") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return "", err
		}
		parts = append(parts, bytes.TrimSpace(b))
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("no license file in %s", dir)
	}
	return string(bytes.Join(parts, []byte("\n\n"))), nil
}

// goLicense is the license of the Go project (https://go.dev/LICENSE).
const goLicense = `Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.`
