// Package overlayclient regenerates govpp bindings for the overlay plugin.
//
// Run `go generate ./...` after building+installing the plugin (the
// run-tests.sh harness does this). Output lives in ./overlay and is
// committed to the tree.
package overlayclient

//go:generate binapi-generator --input-file=/usr/share/vpp/api/plugins/overlay.api.json --output-dir=.
