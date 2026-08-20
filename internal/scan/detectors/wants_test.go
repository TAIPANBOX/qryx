package detectors

import "testing"

// Wants decides which files each detector is ever shown. None of these four
// had been run.
//
// This is the same dead-code-that-reads-as-coverage shape as an unregistered
// detector, one level down. A detector's own tests call Detect with content
// they hand it, so they pass whatever Wants says. Narrow Wants by one
// extension and the detector goes on passing every test it has while never
// seeing a single real file of that kind. Nothing is red and the scan is
// quietly blind.
//
// Written as "what must be looked at" and "what must not", because both
// directions cost something: a missed extension is a blind spot, and a
// detector that wants every file is a scan that parses the whole tree with
// every detector.

func TestEachDetectorLooksAtTheFilesItExistsFor(t *testing.T) {
	cases := []struct {
		detector string
		wants    func(string) bool
		yes      []string
		no       []string
	}{
		{
			"certfile", NewCertFile().Wants,
			[]string{"ca.pem", "server.crt", "client.cer", "deep/nested/ca.pem"},
			// .key and .p12 are deliberately not here: this detector parses
			// PEM certificates, and wanting a binary keystore would mean
			// reading a file it cannot make sense of on every scan.
			[]string{"main.go", "notes.txt", "cert.pem.bak", "pem", "Makefile"},
		},
		{
			"goast", NewGoAST().Wants,
			[]string{"main.go", "internal/x/y.go", "a_test.go"},
			[]string{"main.rs", "go.mod", "go.sum", "main.go.tmpl", "README.md"},
		},
		{
			"terraform", NewTerraform().Wants,
			[]string{"main.tf", "modules/vpc/main.tf"},
			// .tfvars carries values, not resource blocks, and .tfstate is
			// generated output that would report findings nobody wrote.
			[]string{"main.tfvars", "terraform.tfstate", "main.tf.json", "main.go"},
		},
		{
			"tlsconfig", NewTLSConfig().Wants,
			// nginx.conf and httpd.conf are here because they end in .conf,
			// which is the ONLY reason they are wanted. Wants had a
			// name-based case for exactly those two names and it could never
			// run, since both already carry the extension. Removed after a
			// mutation renaming them changed nothing any test could see.
			//
			// A server config under a name with no .conf extension is a real
			// shape and is deliberately not covered, here or in the product.
			[]string{"server.go", "tls.conf", "nginx.conf", "etc/httpd.conf"},
			[]string{"main.rs", "nginx.conf.bak", "config.yaml", "httpd"},
		},
	}

	for _, c := range cases {
		t.Run(c.detector, func(t *testing.T) {
			for _, p := range c.yes {
				if !c.wants(p) {
					t.Errorf("%s does not want %q. Its own tests hand it content "+
						"directly, so they would all still pass while it never "+
						"sees a file of this kind in any real scan",
						c.detector, p)
				}
			}
			for _, p := range c.no {
				if c.wants(p) {
					t.Errorf("%s wants %q, which it cannot make sense of. Every "+
						"scan would read this file for nothing",
						c.detector, p)
				}
			}
		})
	}
}

// No detector wants everything. One that did would be handed the whole tree,
// including binaries and vendored trees, on every scan.
func TestNoDetectorWantsEveryFile(t *testing.T) {
	// Not source in any language these detectors read. A vendored .min.js is
	// deliberately NOT here: three detectors read JavaScript and are right to
	// want it, and whether a vendored tree is walked at all is the walker's
	// decision, not a detector's. The first version of this case had it and
	// was wrong about the product rather than the other way round.
	nothingToDoWithCrypto := []string{
		"logo.png", "data.csv", "LICENSE", "build/output.bin",
	}
	for _, d := range Default() {
		for _, p := range nothingToDoWithCrypto {
			if d.Wants(p) {
				t.Errorf("%s wants %q", d.Name(), p)
			}
		}
	}
}
