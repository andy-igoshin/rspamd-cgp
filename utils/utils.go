package utils

import (
	"strings"
	"unicode"
)

func DiffSlice[T comparable](s1, s2 []T) []T {

	s2m := make(map[T]bool, len(s2))
	for _, v := range s2 {
		s2m[v] = true
	}

	var diff []T
	for _, v := range s1 {
		if _, found := s2m[v]; !found {
			diff = append(diff, v)
		}
	}

	return diff
}

func NoSpace(s string) string {

	var b strings.Builder
	b.Grow(len(s))

	for _, c := range s {
		if !unicode.IsSpace(c) {
			b.WriteRune(c)
		}
	}

	return b.String()
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
