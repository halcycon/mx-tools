package checks

import "testing"

func TestParseSpfTerms(t *testing.T) {
	terms := parseSpfTerms("v=spf1 include:_spf.google.com ip4:1.2.3.4/24 a mx ~all")
	if len(terms) != 5 {
		t.Fatalf("len=%d", len(terms))
	}
	if terms[0].mech != "include" || terms[0].arg != "_spf.google.com" {
		t.Fatalf("%+v", terms[0])
	}
	if terms[4].qual != "~" || terms[4].mech != "all" {
		t.Fatalf("%+v", terms[4])
	}
}

func TestParseQueryFlattenAlias(t *testing.T) {
	q, err := ParseQuery("flatten:example.com")
	if err != nil {
		t.Fatal(err)
	}
	if q.Tool != "spf-flat" || q.Target != "example.com" {
		t.Fatalf("%+v", q)
	}
	q, err = ParseQuery("spf-flat:example.com")
	if err != nil {
		t.Fatal(err)
	}
	if q.Tool != "spf-flat" {
		t.Fatalf("%+v", q)
	}
}
