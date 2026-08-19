// Package extensions is the root for all SCINTX extensions.
//
// Each subdirectory (providers/, policies/) contains extension packages that
// auto-register via init(). The all/ subdirectories are auto-generated
// aggregation packages that import every extension so their init() functions run.
//
// To add a new extension:
//  1. Create a directory under the appropriate kind (e.g. extensions/providers/myprovider/).
//  2. Write a .go file with an init() that calls the relevant Register*Factory.
//  3. Run: go generate ./extensions/...
//  4. The extension is automatically picked up on next build.
//
// See EXTENSIONS.md for the full guide.
package extensions

//go:generate go run ../cmd/gen-extensions
