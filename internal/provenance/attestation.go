package provenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

const (
	// PredicateTypeSLSAProvenance is the SLSA v1 provenance predicate type.
	PredicateTypeSLSAProvenance = "https://slsa.dev/provenance/v1"

	// BuildTypeForgeseal is the forgeseal build type.
	BuildTypeForgeseal = "https://forgeseal.dev/build/v1"

	// StatementType is the in-toto statement type.
	StatementType = "https://in-toto.io/Statement/v1"
)

// AttestOptions configures attestation generation.
type AttestOptions struct {
	SubjectPath   string
	SubjectDigest string // sha256:hex
	Repository    string
	Commit        string
	Sign          bool
}

// Statement is an in-toto v1 attestation statement.
type Statement struct {
	Type          string        `json:"_type"`
	Subject       []Subject     `json:"subject"`
	PredicateType string        `json:"predicateType"`
	Predicate     interface{}   `json:"predicate"`
}

// Subject is the artifact being attested.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// SLSAProvenance is the SLSA v1 provenance predicate.
type SLSAProvenance struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

// BuildDefinition describes what was built and how.
type BuildDefinition struct {
	BuildType            string               `json:"buildType"`
	ExternalParameters   map[string]string     `json:"externalParameters"`
	ResolvedDependencies []ResourceDescriptor  `json:"resolvedDependencies,omitempty"`
}

// ResourceDescriptor is a reference to a build input.
type ResourceDescriptor struct {
	URI    string            `json:"uri,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
	Name   string            `json:"name,omitempty"`
}

// RunDetails describes the build execution.
type RunDetails struct {
	Builder  Builder        `json:"builder"`
	Metadata BuildMetadata  `json:"metadata"`
}

// Builder identifies the build system.
type Builder struct {
	ID string `json:"id"`
}

// BuildMetadata holds build timestamps and identifiers.
type BuildMetadata struct {
	InvocationID string `json:"invocationId,omitempty"`
	StartedOn    string `json:"startedOn,omitempty"`
	FinishedOn   string `json:"finishedOn,omitempty"`
}

// BuildAttestation creates a SLSA v1 provenance attestation.
func BuildAttestation(ctx context.Context, opts AttestOptions) (*Statement, error) {
	// Determine subject digest
	digest := opts.SubjectDigest
	subjectName := opts.SubjectPath
	if digest == "" && opts.SubjectPath != "" {
		d, err := hashFile(opts.SubjectPath)
		if err != nil {
			return nil, fmt.Errorf("hashing subject: %w", err)
		}
		digest = "sha256:" + d
	}

	if digest == "" {
		return nil, fmt.Errorf("subject digest is required; provide --subject or --subject-digest")
	}

	// Parse digest
	digestMap := make(map[string]string)
	if len(digest) > 7 && digest[:7] == "sha256:" {
		digestMap["sha256"] = digest[7:]
	} else {
		digestMap["sha256"] = digest
	}

	// Detect CI environment or use manual values
	var ciEnv *CIEnvironment
	detected, err := DetectCI()
	if err == nil {
		ciEnv = detected
	}

	// Build external parameters
	extParams := make(map[string]string)
	repo := opts.Repository
	commit := opts.Commit

	if ciEnv != nil {
		if repo == "" {
			repo = ciEnv.Repository
		}
		if commit == "" {
			commit = ciEnv.Commit
		}
		extParams["workflow"] = ciEnv.Workflow
		extParams["ref"] = ciEnv.Ref
	}

	if repo != "" {
		extParams["source"] = repo
	}
	if commit != "" {
		extParams["commit"] = commit
	}

	// Build resolved dependencies
	var resolvedDeps []ResourceDescriptor
	if repo != "" {
		dep := ResourceDescriptor{
			URI: repo,
		}
		if commit != "" {
			dep.Digest = map[string]string{"sha1": commit}
		}
		resolvedDeps = append(resolvedDeps, dep)
	}

	// Build metadata
	now := time.Now().UTC().Format(time.RFC3339)
	builderID := "https://forgeseal.dev/cli"
	invocationID := ""

	if ciEnv != nil {
		builderID = ciEnv.BuilderID
		invocationID = ciEnv.RunURL
	}

	stmt := &Statement{
		Type: StatementType,
		Subject: []Subject{
			{
				Name:   subjectName,
				Digest: digestMap,
			},
		},
		PredicateType: PredicateTypeSLSAProvenance,
		Predicate: SLSAProvenance{
			BuildDefinition: BuildDefinition{
				BuildType:            BuildTypeForgeseal,
				ExternalParameters:   extParams,
				ResolvedDependencies: resolvedDeps,
			},
			RunDetails: RunDetails{
				Builder: Builder{ID: builderID},
				Metadata: BuildMetadata{
					InvocationID: invocationID,
					StartedOn:    now,
					FinishedOn:   now,
				},
			},
		},
	}

	return stmt, nil
}

// MarshalAttestation serializes an attestation to JSON.
func MarshalAttestation(stmt *Statement) ([]byte, error) {
	return json.MarshalIndent(stmt, "", "  ")
}

func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}
