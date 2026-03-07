package utils

import (
	"unsafe"
)

func Bytes2string(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func UniqueSliceElementsNonEmpty[T ~string](s []T) []T {

	unique := make([]T, 0, len(s))
	seen := make(map[T]bool, len(s))

	for _, e := range s {
		if len(e) > 0 {
			if !seen[e] {
				unique = append(unique, e)
				seen[e] = true
			}
		}
	}

	return unique
}
