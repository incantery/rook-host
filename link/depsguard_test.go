package link_test

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// The import-boundary guarantees, enforced by the compiler's own map:
//
//   - projection and edge are stdlib-only (they are the shared
//     vocabulary; anything they pull in, every consumer pulls in)
//   - only bonjour may import the mDNS dependency
//   - nothing imports a future engine/ module (core never imports
//     engine — a compiler guarantee, not a convention)
//   - nothing anywhere pulls storage or workflow runtimes
func TestImportBoundaries(t *testing.T) {
	pkgs := goList(t)

	for _, p := range pkgs {
		short := strings.TrimPrefix(p.ImportPath, "github.com/incantery/rook-host")
		for _, imp := range p.Imports {
			switch {
			case strings.Contains(imp, "brutella/dnssd"):
				if short != "/bonjour" {
					t.Errorf("%s imports dnssd — only bonjour may", short)
				}
			case strings.Contains(imp, "rook-host/engine"):
				t.Errorf("%s imports engine — core never imports engine", short)
			case strings.Contains(imp, "jackc/pgx"),
				strings.Contains(imp, "mongo-driver"),
				strings.Contains(imp, "temporal"),
				strings.Contains(imp, "opentelemetry"):
				t.Errorf("%s imports %s — rook-host core carries no runtime freight", short, imp)
			}
		}

		if short == "/projection" || short == "/edge" {
			for _, dep := range p.Deps {
				if strings.Contains(strings.SplitN(dep, "/", 2)[0], ".") {
					t.Errorf("%s depends on %s — the vocabulary packages are stdlib-only", short, dep)
				}
			}
		}
	}
}

type pkg struct {
	ImportPath string
	Imports    []string
	Deps       []string
}

func goList(t *testing.T) []pkg {
	t.Helper()
	// The module-path pattern works from any cwd inside the module —
	// a ./... here would list only this package's directory.
	out, err := exec.Command("go", "list", "-json=ImportPath,Imports,Deps",
		"github.com/incantery/rook-host/...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	var pkgs []pkg
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var p pkg
		if err := dec.Decode(&p); err != nil {
			t.Fatal(err)
		}
		pkgs = append(pkgs, p)
	}
	if len(pkgs) < 5 {
		t.Fatalf("go list saw only %d packages — pattern broken?", len(pkgs))
	}
	return pkgs
}
