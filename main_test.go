package main

import "testing"

func TestParseAdditionalDomains(t *testing.T) {
	data := []byte("server=/example.com/\n0.0.0.0 ads.example.org\n||tracker.example.net^\nfull:full.example.io\n")
	got := parseAdditionalDomains(data)
	want := []string{"ads.example.org", "example.com", "full.example.io", "tracker.example.net"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
