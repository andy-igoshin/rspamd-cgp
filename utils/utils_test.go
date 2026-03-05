package utils

import (
	"testing"
)

func TestBytes2string(t *testing.T) {
	t.Run("Valid conversion", func(t *testing.T) {
		input := []byte("hello world")
		got := Bytes2string(input)
		if got != "hello world" {
			t.Errorf("Expected 'hello world', got %q", got)
		}
	})

	t.Run("Empty slice", func(t *testing.T) {
		if got := Bytes2string([]byte{}); got != "" {
			t.Errorf("Expected empty string, got %q", got)
		}
		if got := Bytes2string(nil); got != "" {
			t.Errorf("Expected empty string for nil, got %q", got)
		}
	})
}

func TestUniqueSliceElementsNonEmpty(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "Duplicates and empty strings",
			input: []string{"a", "b", "", "a", "c", "b", " "},
			want:  []string{"a", "b", "c", " "}, // Пробел не пустая строка
		},
		{
			name:  "All empty",
			input: []string{"", "", ""},
			want:  []string{},
		},
		{
			name:  "Already unique",
			input: []string{"one", "two"},
			want:  []string{"one", "two"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := UniqueSliceElementsNonEmpty(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("Length mismatch: got %d, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("At index %d: got %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestDiffSlice(t *testing.T) {
	s1 := []string{"a", "b", "c", "d"}
	s2 := []string{"b", "d"}
	want := []string{"a", "c"}

	got := DiffSlice(s1, s2)
	if len(got) != len(want) {
		t.Fatalf("Length mismatch: got %d, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("At index %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestNoSpace(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"  hello  world  ", "helloworld"},
		{"\t\n a \r", "a"},
		{"", ""},
	}

	for _, tt := range tests {
		if got := NoSpace(tt.input); got != tt.want {
			t.Errorf("NoSpace(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
