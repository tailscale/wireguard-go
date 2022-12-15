// Package native provides easy access to native byte order.
//
// Usage: use native.Endian where you need the native binary.ByteOrder.
//
// Please think twice before using this package.
// It can break program portability.
// Native byte order is usually not the right answer.
// This package is a drop-in of github.com/josharian/native, with attribution in
// the file 'license'. This package will likely be replaced by something similar
// in the standard library, see https://github.com/golang/go/issues/57237.
package native
