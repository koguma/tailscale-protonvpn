package vpn

import (
	"slices"
	"testing"
)

func TestInterleave(t *testing.T) {
	in := []string{"1.1.1.1", "1.1.1.2", "1.1.1.3", "2.2.2.1", "3.3.3.1", "3.3.3.2"}
	got := interleave(in)
	want := []string{"1.1.1.1", "2.2.2.1", "3.3.3.1", "1.1.1.2", "3.3.3.2", "1.1.1.3"}
	if !slices.Equal(got, want) {
		t.Fatalf("interleave = %v, want %v", got, want)
	}
}
