// Package ui holds the embedded ARGUS web console: dependency-free static assets
// (HTML/CSS/JS) served by argus-server. There is deliberately no build step — no
// Node, no bundler — so `make build` alone produces a server that serves the
// console. The browser talks to the admin HTTP API on the same origin.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed static
var files embed.FS

// Assets is the console's static file tree, rooted so "/" maps to index.html.
func Assets() fs.FS {
	sub, err := fs.Sub(files, "static")
	if err != nil {
		// The embed path is a compile-time constant directory; Sub cannot fail.
		panic(err)
	}
	return sub
}
