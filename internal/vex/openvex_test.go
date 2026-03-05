package vex

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewDocument(t *testing.T) {
	doc := NewDocument("urn:test:vex:1", "test-author")

	if doc.Context != OpenVEXContext {
		t.Errorf("expected context %s, got %s", OpenVEXContext, doc.Context)
	}
	if doc.ID != "urn:test:vex:1" {
		t.Errorf("expected ID urn:test:vex:1, got %s", doc.ID)
	}
	if doc.Author != "test-author" {
		t.Errorf("expected author test-author, got %s", doc.Author)
	}
	if doc.Timestamp == "" {
		t.Error("expected timestamp")
	}
	if len(doc.Statements) != 0 {
		t.Error("expected empty statements")
	}
}

func TestAddStatement(t *testing.T) {
	doc := NewDocument("urn:test:vex:1", "test")

	// Valid under_investigation
	err := doc.AddStatement(VEXStatement{
		Vulnerability: VulnerabilityRef{ID: "CVE-2024-1234"},
		Products:      []ProductRef{{ID: "pkg:npm/test@1.0.0"}},
		Status:        StatusUnderInvestigation,
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Valid not_affected with justification
	err = doc.AddStatement(VEXStatement{
		Vulnerability: VulnerabilityRef{ID: "CVE-2024-5678"},
		Products:      []ProductRef{{ID: "pkg:npm/test@1.0.0"}},
		Status:        StatusNotAffected,
		Justification: "component_not_present",
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Invalid: not_affected without justification
	err = doc.AddStatement(VEXStatement{
		Vulnerability: VulnerabilityRef{ID: "CVE-2024-9999"},
		Products:      []ProductRef{{ID: "pkg:npm/test@1.0.0"}},
		Status:        StatusNotAffected,
	})
	if err == nil {
		t.Error("expected error for not_affected without justification")
	}

	// Invalid: no products
	err = doc.AddStatement(VEXStatement{
		Vulnerability: VulnerabilityRef{ID: "CVE-2024-0000"},
		Status:        StatusAffected,
	})
	if err == nil {
		t.Error("expected error for missing products")
	}

	// Invalid: bad status
	err = doc.AddStatement(VEXStatement{
		Vulnerability: VulnerabilityRef{ID: "CVE-2024-1111"},
		Products:      []ProductRef{{ID: "pkg:npm/test@1.0.0"}},
		Status:        "invalid_status",
	})
	if err == nil {
		t.Error("expected error for invalid status")
	}

	if len(doc.Statements) != 2 {
		t.Errorf("expected 2 statements, got %d", len(doc.Statements))
	}
}

func TestWriteAndReadDocument(t *testing.T) {
	doc := NewDocument("urn:test:vex:1", "test")
	_ = doc.AddStatement(VEXStatement{
		Vulnerability: VulnerabilityRef{ID: "CVE-2024-1234"},
		Products:      []ProductRef{{ID: "pkg:npm/test@1.0.0"}},
		Status:        StatusFixed,
	})

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "vex.json")

	if err := WriteDocument(doc, path); err != nil {
		t.Fatal(err)
	}

	loaded, err := ReadDocument(path)
	if err != nil {
		t.Fatal(err)
	}

	if loaded.ID != doc.ID {
		t.Errorf("expected ID %s, got %s", doc.ID, loaded.ID)
	}
	if len(loaded.Statements) != 1 {
		t.Errorf("expected 1 statement, got %d", len(loaded.Statements))
	}

	// Clean up
	os.Remove(path)
}

func TestAllJustifications(t *testing.T) {
	for _, j := range ValidJustifications {
		doc := NewDocument("urn:test", "test")
		err := doc.AddStatement(VEXStatement{
			Vulnerability: VulnerabilityRef{ID: "CVE-2024-0001"},
			Products:      []ProductRef{{ID: "pkg:npm/test@1.0.0"}},
			Status:        StatusNotAffected,
			Justification: j,
		})
		if err != nil {
			t.Errorf("justification %q should be valid, got error: %v", j, err)
		}
	}
}
