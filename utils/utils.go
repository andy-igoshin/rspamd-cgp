package utils

func UniqueSliceElementsNonEmpty[T ~string](inputSlice []T) []T {

	uniqueSlice := make([]T, 0, len(inputSlice))
	seen := make(map[T]bool, len(inputSlice))

	for _, element := range inputSlice {
		if len(element) != 0 {
			if !seen[element] {
				uniqueSlice = append(uniqueSlice, element)
				seen[element] = true
			}
		}
	}

	return uniqueSlice
}
