# Claude Code Prompt: forgeseal Multi-Ecosystem Extension

## Context

You are extending **forgeseal** (github.com/sns45/forgeseal), a Go-based supply chain security CLI that generates CycloneDX SBOMs, Sigstore signatures, SLSA provenance, and VEX documents. It currently supports JS/TS (6 lockfile formats) and Python (4 lockfile formats).

You are adding support for **Go (`go.mod`/`go.sum`)**, **Rust (`Cargo.lock`)**, and **Java/Gradle (`gradle.lockfile`)** — 3 new parsers, 3 new PURL types, and updates to the SBOM generator, component mapper, and test suite.

**Read `requirements.md` first** — it is the authoritative spec for this task.

---

## Instructions

Use `write-plan` followed by `execute-plan` to implement this in phases. The plan should have these phases:

### Phase 1: Go Module Support

**Plan name**: `forgeseal-gomod`

1. Add `TypeGoMod LockfileType = "gomod"` to `internal/lockfile/model.go`

2. Create `internal/lockfile/gomod.go`:
   - `GoModParser` struct implementing `Parser` interface
   - `Filenames()` returns `["go.mod"]`
   - `Parse()` reads `go.mod` from the reader, then attempts to read `go.sum` from the same directory by implementing `FileParser` interface instead (use `ParseFile` to get the directory path)
   - Parse `require` blocks (both parenthesized and single-line), handling `// indirect` comments
   - Parse `replace` directives and apply them to the dependency list
   - Parse `go.sum` for `h1:` integrity hashes (use the non-`/go.mod` entries)
   - Skip workspace members / the module itself

3. Create test fixture `testdata/lockfiles/gomod/go.mod` with:
   - `module example.com/myproject`
   - `go 1.22`
   - A `require` block with ~8–10 deps including indirect ones
   - At least one `replace` directive (e.g., `replace golang.org/x/old => golang.org/x/new v0.5.0`)
   - At least one `/v2` major version module
   - **Use real-world module paths** (github.com/gorilla/mux, golang.org/x/sys, etc.) with plausible versions

4. Create matching `testdata/lockfiles/gomod/go.sum` with `h1:` hashes for each module

5. Create `internal/lockfile/gomod_test.go`:
   - `TestGoModParser`: parse fixture, verify package count, names, versions, replace resolution, hash extraction
   - `TestGoModParserReplace`: verify replace directives are resolved correctly
   - `TestParseGoModLine`: unit test for line parsing helper

6. Add `BuildGolangPURL(name, version string) string` to `internal/sbom/purl.go`:
   - Use `packageurl.NewPackageURL("golang", namespace, name, version, nil, "")`
   - Split module path on last `/` for namespace vs name
   - Add test cases to `purl_test.go`

7. Update `internal/sbom/cyclonedx.go` `mapComponent()`:
   - For `"golang"` ecosystem: external ref URL = `https://pkg.go.dev/<module>`
   - Hash parsing for `h1:<base64>` format → `cdx.HashAlgoSHA256`

8. Update `internal/sbom/generator.go`:
   - Add `TypeGoMod` case to `ecosystemFromLockfileType()` returning `"golang"`
   - Add `readGoModInfo()` to extract module name from `go.mod`
   - Wire into `Generate()` metadata chain

9. Update `internal/sbom/purl.go` `BuildPURL()` dispatcher:
   - Add `case "golang": return BuildGolangPURL(name, version)`

10. Register `&GoModParser{}` in `internal/lockfile/parser.go` registry (after Python parsers)

11. Run `go test ./internal/lockfile/ -run TestGoMod` and `go test ./internal/sbom/ -run TestSnapshots/gomod -update` to generate the snapshot

12. Run `go test ./...` to verify nothing is broken

### Phase 2: Rust/Cargo Support

**Plan name**: `forgeseal-cargo`

1. Add `TypeCargoLock LockfileType = "cargo"` to `internal/lockfile/model.go`

2. Create `internal/lockfile/cargo.go`:
   - `CargoParser` struct implementing `Parser`
   - `Filenames()` returns `["Cargo.lock"]`
   - Parse TOML using `pelletier/go-toml/v2` with map-based decoding (same pattern as `uv.go`)
   - Extract `[[package]]` array entries: `name`, `version`, `source`, `checksum`, `dependencies`
   - Skip packages without `source` field (workspace members)
   - Parse dependency strings: `"name"`, `"name version"`, `"name version (source)"`
   - Store `checksum` as `sha256:<hex>` in `Package.Integrity`

3. Create test fixture `testdata/lockfiles/cargo/Cargo.lock` with:
   - `version = 3` header
   - A workspace root package (no `source`)
   - ~8–10 registry packages with checksums
   - At least one package with multiple versions
   - Dependency strings in various formats
   - **Use real crate names** (serde, tokio, rand, etc.)

4. Create `internal/lockfile/cargo_test.go`:
   - `TestCargoParser`: parse fixture, verify count, names, versions, checksums, workspace root skipping
   - `TestParseCargoDepString`: unit test for dependency string parsing

5. Add `BuildCargoPURL(name, version string) string` to `internal/sbom/purl.go`:
   - `packageurl.NewPackageURL("cargo", "", name, version, nil, "")`
   - Add test cases

6. Update `mapComponent()` for `"cargo"`: external ref URL = `https://crates.io/crates/<n>`

7. Update `ecosystemFromLockfileType()`: `TypeCargoLock → "cargo"`

8. Update `BuildPURL()` dispatcher: `case "cargo": return BuildCargoPURL(name, version)`

9. Add `readCargoTomlInfo()` to extract `[package].name` and `[package].version` from `Cargo.toml` if present

10. Register `&CargoParser{}` in parser registry

11. Generate snapshot and run full test suite

### Phase 3: Java/Gradle Support

**Plan name**: `forgeseal-gradle`

1. Add `TypeGradleLock LockfileType = "gradle"` to `internal/lockfile/model.go`

2. Create `internal/lockfile/gradle.go`:
   - `GradleParser` struct implementing `Parser`
   - `Filenames()` returns `["gradle.lockfile"]`
   - Line-oriented parsing: skip `#` comments and blank lines
   - Parse `<group>:<artifact>:<version>=<configurations>` format
   - Store `Package.Name` as `"group:artifact"` (colon-joined for PURL splitting later)
   - Dev detection: if configurations CSV contains ONLY `test*` prefixed configs, mark `Dev = true`

3. Create test fixture `testdata/lockfiles/gradle/gradle.lockfile` with:
   - Standard header comment
   - ~8–10 dependencies across various configurations
   - At least 2 test-only dependencies
   - **Use real Maven coordinates** (org.springframework:spring-core, com.google.guava:guava, etc.)

4. Create `internal/lockfile/gradle_test.go`:
   - `TestGradleParser`: parse fixture, verify count, names (group:artifact format), versions, dev detection
   - `TestGradleDevDetection`: verify configuration-based dev classification

5. Add `BuildMavenPURL(name, version string) string` to `internal/sbom/purl.go`:
   - Split `name` on `:` → `group` (namespace) and `artifact` (name)
   - `packageurl.NewPackageURL("maven", group, artifact, version, nil, "")`
   - Add test cases

6. Update `mapComponent()` for `"maven"`:
   - External ref URL = `https://central.sonatype.com/artifact/<group>/<artifact>`
   - Use `artifact` portion as display name in `comp.Name`

7. Update `ecosystemFromLockfileType()`: `TypeGradleLock → "maven"`

8. Update `BuildPURL()` dispatcher: `case "maven": return BuildMavenPURL(name, version)`

9. Register `&GradleParser{}` in parser registry

10. Generate snapshot and run full test suite

### Phase 4: Integration & Polish

**Plan name**: `forgeseal-integration`

1. Update `Detect()` error message in `parser.go` to include `go.mod, Cargo.lock, gradle.lockfile`

2. Update `internal/sbom/generator_test.go`:
   - Add `TestGeneratorGenerateGo` with Go lockfile result
   - Add `TestGeneratorGenerateRust` with Cargo lockfile result
   - Add `TestGeneratorGenerateGradle` with Gradle lockfile result
   - Verify PURL prefixes (`pkg:golang/`, `pkg:cargo/`, `pkg:maven/`)

3. Update `ecosystemFromLockfileType` test in `generator_test.go` to cover all new types

4. Run `go test -race -count=1 ./...` — everything must pass

5. Update `README.md`:
   - Add Go, Rust, Gradle rows to Supported Lockfiles table
   - Update description and feature summary
   - Add Go/Rust/Gradle quick start examples
   - Update Architecture section with new parser count
   - Update PURL construction docs

6. Update `action.yml` description to mention Go, Rust, Java

7. Update `.goreleaser.yaml` brew description

8. Update `rootCmd.Long` and `rootCmd.Short` in `internal/cli/root.go`

9. Final `go test -race -count=1 ./...` — confirm green

---

## Key Patterns to Follow

These are the patterns already established in the codebase. Follow them exactly:

### Parser Interface
```go
type XxxParser struct{}
func (p *XxxParser) Type() LockfileType { return TypeXxx }
func (p *XxxParser) Filenames() []string { return []string{"filename"} }
func (p *XxxParser) Parse(ctx context.Context, r io.Reader) (*LockfileResult, error) { ... }
```

### TOML Parsing (for Cargo.lock)
Use map-based decoding like `uv.go` and `pdm.go`:
```go
var raw map[string]any
if err := toml.Unmarshal(data, &raw); err != nil { ... }
packageList, ok := raw["package"].([]any)
```

### PURL Construction
```go
func BuildXxxPURL(name, version string) string {
    purl := packageurl.NewPackageURL("type", namespace, name, version, nil, "")
    return purl.ToString()
}
```

### Test Structure
```go
func TestXxxParser(t *testing.T) {
    f, err := os.Open("../../testdata/lockfiles/xxx/filename")
    // ... parse, verify Type, verify package count
    found := make(map[string]Package)
    for _, pkg := range result.Packages { found[pkg.Name] = pkg }
    // ... assert specific packages by name, version, integrity, deps, dev flag
}
```

### Snapshot Tests
New testdata directories are auto-discovered by `discoverSnapshotCases()` in `snapshot_test.go`. Just create the fixture and run with `-update`.

---

## Critical Constraints

1. **ZERO new `go.mod` dependencies** — `pelletier/go-toml/v2` is already available for Cargo.lock. Go.mod and gradle.lockfile need only string parsing.

2. **Never shell out** to `go`, `cargo`, or `gradle`. Parse lockfiles only.

3. **Test fixtures must be vendored** in `testdata/`. No network fetches during tests.

4. **Preserve backward compatibility** — existing JS/TS and Python tests must continue passing unchanged.

5. **Maintain detection priority** — JS/TS > Python > Go > Rust > Java. A project won't have multiple ecosystems, but the priority exists for mixed-project edge cases.

6. **GoModParser needs FileParser interface** — because it reads `go.sum` from the same directory as `go.mod`. Implement `ParseFile(ctx, path)` which reads `go.mod` from the reader AND reads `go.sum` by deriving the directory from the path. The `Parse(ctx, reader)` method should work without hashes (for streaming/testing).

---

## Verification Checklist

After each phase, verify:
- [ ] `go build ./...` succeeds
- [ ] `go vet ./...` is clean
- [ ] `go test -race -count=1 ./...` passes (ALL tests, not just new ones)
- [ ] Snapshot test generates valid CycloneDX JSON
- [ ] PURLs match the spec format exactly
- [ ] No new entries in `go.mod` / `go.sum` (no new dependencies)

After Phase 4 (final):
- [ ] Full test suite passes
- [ ] `forgeseal sbom --dir testdata/lockfiles/gomod` produces valid SBOM
- [ ] `forgeseal sbom --dir testdata/lockfiles/cargo` produces valid SBOM
- [ ] `forgeseal sbom --dir testdata/lockfiles/gradle` produces valid SBOM
- [ ] README is updated
- [ ] `go test -race -count=1 ./...` is green

---

## Execution

Run each phase sequentially:

```
write-plan forgeseal-gomod
execute-plan forgeseal-gomod

write-plan forgeseal-cargo
execute-plan forgeseal-cargo

write-plan forgeseal-gradle
execute-plan forgeseal-gradle

write-plan forgeseal-integration
execute-plan forgeseal-integration
```

Each phase is self-contained: implement, test, verify green. If a phase fails tests, fix before moving to the next.
