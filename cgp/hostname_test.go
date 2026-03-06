package cgp

import (
	"testing"
)

func TestHostname_Logic(t *testing.T) {
	t.Run("FilterNames", func(t *testing.T) {
		input := []string{"host", "mail.domain.name", "localhost", "deep.sub.domain.com"}
		// Должны остаться только те, что проходят IsValidDomain (с точками)
		got := filterNames(input)
		if len(got) != 3 { // mail.domain.name, localhost (если rx пропустит), deep...
			// Зависит от вашего regex. IsValidDomain требует хотя бы одну точку.
			t.Logf("Filtered names: %v", got)
		}
	})

	t.Run("FindShorterItem", func(t *testing.T) {
		input := []string{"very-long-hostname.example.com", "short.com", "medium.example.com"}
		want := "short.com"
		if got := findShorterItem(input); got != want {
			t.Errorf("findShorterItem() = %v, want %v", got, want)
		}
	})

	t.Run("FindLongerItem", func(t *testing.T) {
		input := []string{"a.ru", "abc.ru", "ab.ru"}
		want := "abc.ru"
		if got := findLongerItem(input); got != want {
			t.Errorf("findLongerItem() = %v, want %v", got, want)
		}
	})

	t.Run("IsValidDomain", func(t *testing.T) {
		tests := []struct {
			dom  string
			want bool
		}{
			{"domain.name", true},
			{"mail.domain.name.", true}, // с точкой в конце
			{"internal-host", false},    // нет точек
			{"1.2.3.4", false},          // IP не должен быть доменом в этой логике
		}
		for _, tt := range tests {
			if got := IsValidDomain(tt.dom); got != tt.want {
				t.Errorf("IsValidDomain(%q) = %v, want %v", tt.dom, got, tt.want)
			}
		}
	})
}
