package vex

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

const (
	OpenVEXContext = "https://openvex.dev/ns/v0.2.0"

	StatusNotAffected       = "not_affected"
	StatusAffected          = "affected"
	StatusFixed             = "fixed"
	StatusUnderInvestigation = "under_investigation"
)

// Valid justifications for not_affected status.
var ValidJustifications = []string{
	"component_not_present",
	"vulnerable_code_not_present",
	"vulnerable_code_not_in_execute_path",
	"vulnerable_code_cannot_be_controlled_by_adversary",
	"inline_mitigations_already_exist",
}

// OpenVEXDocument is an OpenVEX v0.2 document.
type OpenVEXDocument struct {
	Context    string         `json:"@context"`
	ID         string         `json:"@id"`
	Author     string         `json:"author"`
	Timestamp  string         `json:"timestamp"`
	Version    int            `json:"version"`
	Statements []VEXStatement `json:"statements"`
}

// VEXStatement is a single VEX statement.
type VEXStatement struct {
	Vulnerability   VulnerabilityRef `json:"vulnerability"`
	Products        []ProductRef     `json:"products"`
	Status          string           `json:"status"`
	Justification   string           `json:"justification,omitempty"`
	ImpactStatement string           `json:"impact_statement,omitempty"`
	Timestamp       string           `json:"timestamp"`
}

// VulnerabilityRef identifies a vulnerability.
type VulnerabilityRef struct {
	ID string `json:"@id"`
}

// ProductRef identifies a product and optional subcomponents.
type ProductRef struct {
	ID            string   `json:"@id"`
	Subcomponents []string `json:"subcomponents,omitempty"`
}

// NewDocument creates a new OpenVEX document.
func NewDocument(id, author string) *OpenVEXDocument {
	return &OpenVEXDocument{
		Context:    OpenVEXContext,
		ID:         id,
		Author:     author,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Version:    1,
		Statements: []VEXStatement{},
	}
}

// AddStatement adds a VEX statement to the document.
func (d *OpenVEXDocument) AddStatement(stmt VEXStatement) error {
	if err := validateStatement(stmt); err != nil {
		return err
	}
	if stmt.Timestamp == "" {
		stmt.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	d.Statements = append(d.Statements, stmt)
	return nil
}

func validateStatement(stmt VEXStatement) error {
	if stmt.Vulnerability.ID == "" {
		return fmt.Errorf("vulnerability ID is required")
	}
	if len(stmt.Products) == 0 {
		return fmt.Errorf("at least one product is required")
	}

	switch stmt.Status {
	case StatusNotAffected:
		if stmt.Justification == "" {
			return fmt.Errorf("justification is required when status is not_affected")
		}
		valid := false
		for _, j := range ValidJustifications {
			if j == stmt.Justification {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid justification %q; valid values: %v", stmt.Justification, ValidJustifications)
		}
	case StatusAffected, StatusFixed, StatusUnderInvestigation:
		// OK
	default:
		return fmt.Errorf("invalid status %q; valid values: not_affected, affected, fixed, under_investigation", stmt.Status)
	}

	return nil
}

// WriteDocument serializes an OpenVEX document to a file.
func WriteDocument(doc *OpenVEXDocument, path string) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling VEX document: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// ReadDocument reads an OpenVEX document from a file.
func ReadDocument(path string) (*OpenVEXDocument, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading VEX document: %w", err)
	}
	var doc OpenVEXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing VEX document: %w", err)
	}
	return &doc, nil
}
