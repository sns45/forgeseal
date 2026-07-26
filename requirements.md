# forgeseal Multi-Ecosystem Extension: Go, Rust, Java/Gradle

## Overview

Extend forgeseal's lockfile parsing and SBOM generation from JS/TS + Python to Go, Rust, and Java/Gradle. The existing architecture — `Parser` interface, `LockfileResult` model, `BuildPURL()` dispatch, `ecosystemFromLockfileType()`, and `mapComponent()` — is designed for this. No new `go.mod` dependencies are required.

## Scope

### In Scope

- **Go**: Parse `go.mod` (the lockfile in Go's MVS model) + `go.sum` (integrity hashes)
- **Rust**: Parse `Cargo.lock` (TOML, already have `pelletier/go-toml/v2`)
- **Java/Gradle**: Parse `gradle.lockfile` (line-oriented text)
- PURL construction for `pkg:golang/`, `pkg:cargo/`, `pkg:maven/` types
- Ecosystem detection and priority ordering in the parser registry
- CycloneDX component mapping with correct external references
- VEX triage via OSV.dev (already ecosystem-agnostic via PURL)
- Snapshot tests for each new ecosystem
- Update `Detect()` error message and README

### Out of Scope

- Maven `pom.xml` parsing (deferred — requires XML property interpolation, parent POM inheritance, transitive resolution; a separate phase)
- Invoking `go`, `cargo`, or `gradle` CLIs (lockfile-only, no build tool dependency)
- Workspace/multi-module resolution beyond what the lockfile provides
- New `go.mod` dependencies

---

## Phase 1: Go Module Support

### 1.1 Model Changes

Add to `internal/lockfile/model.go`:

```go
TypeGoMod LockfileType = "gomod"
```

### 1.2 Parser: `internal/lockfile/gomod.go`

**File**: `GoModParser` implementing `Parser` interface.

**Detection**: Filenames `go.mod` (the parser reads both `go.mod` and `go.sum` from the same directory).

**Parsing `go.mod`**:
- Line-oriented format with directives: `module`, `go`, `require`, `replace`, `exclude`, `retract`
- `require` block (parenthesized or single-line): extract `module@version` pairs
- Track `// indirect` comment to set a metadata flag (not `Dev`, but could be stored as a property — for now, all Go deps are non-dev since Go has no dev dependency concept)
- Resolve `replace` directives: if `replace old => new`, the SBOM should use the replacement module path and version. Both single-line and block forms.
- Skip `exclude` and `retract` directives
- Handle major version suffixes (`/v2`, `/v3`) — these are part of the module path and must appear in PURLs

**Parsing `go.sum`** (for integrity hashes):
- Located in same directory as `go.mod`
- Format: `<module> <version>[/go.mod] <hash>` per line
- Each module has two entries: one for the module zip (`v1.2.3`) and one for the `go.mod` file (`v1.2.3/go.mod`)
- Use the module zip hash (without `/go.mod` suffix) as `Package.Integrity`
- Hash format is `h1:<base64>` (SHA-256 of the module zip); store as-is

**Edge cases**:
- `replace` with local path (`replace foo => ../local`) — skip the replacement (no version available), keep original
- `replace` with no version on old side (`replace foo => bar v1.2.3`) — apply to all versions
- Pseudo-versions like `v0.0.0-20240101000000-abcdef123456` — parse as normal versions

### 1.3 PURL Construction

Add `BuildGolangPURL(name, version string) string` to `internal/sbom/purl.go`:

```
pkg:golang/<module-path>@<version>
```

- The full module path (e.g., `github.com/gorilla/mux`) becomes the PURL name
- Namespace and name are split on the last `/` segment: namespace=`github.com/gorilla`, name=`mux`
- Actually, per the purl spec for golang: the `type` is `golang`, the `namespace` is everything except the last path segment, `name` is the last segment
- Version includes the `v` prefix as-is (e.g., `v1.8.0`)
- Module paths must be lowercased per purl spec (Go module paths are case-sensitive but purl requires lowercase)

**Examples**:
| Module | PURL |
|--------|------|
| `github.com/gorilla/mux` v1.8.0 | `pkg:golang/github.com/gorilla/mux@v1.8.0` |
| `golang.org/x/sys` v0.29.0 | `pkg:golang/golang.org/x/sys@v0.29.0` |
| `github.com/foo/bar/v2` v2.1.0 | `pkg:golang/github.com/foo/bar/v2@v2.1.0` |

### 1.4 CycloneDX Mapping

In `mapComponent()`, for ecosystem `"golang"`:
- External reference URL: `https://pkg.go.dev/<module-path>`
- Hashes: `h1:` prefix maps to SHA-256 (`cdx.HashAlgoSHA256`)

### 1.5 Project Metadata

Add `readGoModInfo(dir string) *ProjectInfo` to `internal/sbom/generator.go`:
- Parse `module` directive from `go.mod` for the project name
- Go has no project version in `go.mod` — use `"0.0.0"` as default

### 1.6 Test Data

Create `testdata/lockfiles/gomod/`:
- `go.mod`: Module with ~10 dependencies including scoped/indirect/replace directives
- `go.sum`: Matching integrity hashes
- Include a `replace` directive to test resolution
- Include a `/v2` major version suffix module

Snapshot: `testdata/snapshots/gomod.sbom.json`

---

## Phase 2: Rust/Cargo Support

### 2.1 Model Changes

Add to `internal/lockfile/model.go`:

```go
TypeCargoLock LockfileType = "cargo"
```

### 2.2 Parser: `internal/lockfile/cargo.go`

**File**: `CargoParser` implementing `Parser` interface.

**Detection**: Filenames `Cargo.lock`.

**Parsing `Cargo.lock`**:
- TOML file with a flat `[[package]]` array
- Each package has: `name` (string), `version` (string), `source` (optional string), `checksum` (optional string), `dependencies` (optional array of strings)
- Use `pelletier/go-toml/v2` (already in `go.mod`) for parsing
- Use map-based decoding (`map[string]any`) to tolerate unknown/future fields, same pattern as `uv.go` and `pdm.go`

**Package extraction**:
- Skip the first `[[package]]` entry if its `name` matches the workspace root (has no `source` field — registry packages always have `source = "registry+https://github.com/rust-lang/crates.io-index"`)
- `checksum` field is a bare SHA-256 hex string — store as `Package.Integrity` with `sha256:` prefix for consistency
- `dependencies` are strings in format `"name"` or `"name version"` or `"name version (source)"` — extract name (and optionally version) for `DependencyRef`
- Cargo has no dev dependency concept in `Cargo.lock` — all resolved deps are included regardless of `[dev-dependencies]` in `Cargo.toml`. Set `Dev = false` for all.

**Edge cases**:
- Workspace projects: single `Cargo.lock` at workspace root, multiple `[[package]]` entries without `source` (all are workspace members) — skip all packages without a `source` field
- Multiple versions of the same crate: each gets its own `[[package]]` entry with a different version — include all
- `source` field may be a git URL (`git+https://...#commit`) or a path — only include packages with registry source or no source filtering (include all, let PURL handle it)

### 2.3 PURL Construction

Add `BuildCargoPURL(name, version string) string` to `internal/sbom/purl.go`:

```
pkg:cargo/<name>@<version>
```

- No namespace (flat package namespace)
- Name used as-is (crate names are lowercase by convention, but preserve original case)

**Examples**:
| Crate | PURL |
|-------|------|
| `serde` 1.0.124 | `pkg:cargo/serde@1.0.124` |
| `tokio` 1.36.0 | `pkg:cargo/tokio@1.36.0` |

### 2.4 CycloneDX Mapping

In `mapComponent()`, for ecosystem `"cargo"`:
- External reference URL: `https://crates.io/crates/<name>`
- Hashes: `sha256:` hex string maps to `cdx.HashAlgoSHA256`

### 2.5 Test Data

Create `testdata/lockfiles/cargo/`:
- `Cargo.lock`: ~10 packages including a workspace root (no source), multiple versions of a crate, and git-sourced dependency
- Include version 3 format (`version = 3` at top)

Snapshot: `testdata/snapshots/cargo.sbom.json`

---

## Phase 3: Java/Gradle Support

### 3.1 Model Changes

Add to `internal/lockfile/model.go`:

```go
TypeGradleLock LockfileType = "gradle"
```

### 3.2 Parser: `internal/lockfile/gradle.go`

**File**: `GradleParser` implementing `Parser` interface.

**Detection**: Filenames `gradle.lockfile`.

**Parsing `gradle.lockfile`**:
- Plain text, one dependency per line
- Format: `<group>:<artifact>:<version>=<configurations>`
- Lines starting with `#` are comments (header comment `# This is a Gradle generated file`)
- Lines containing `empty=` at the end mark empty configurations — skip these
- The `=<configurations>` suffix lists which Gradle configurations include this dep (e.g., `compileClasspath,runtimeClasspath`)
- Extract `group`, `artifact`, `version` from the `<group>:<artifact>:<version>` portion

**Dev detection**:
- If configurations list contains ONLY test-related configs (`testCompileClasspath`, `testRuntimeClasspath`, `testImplementation`, etc.) and no production configs (`compileClasspath`, `runtimeClasspath`, `implementation`, etc.), mark as `Dev = true`
- Production configs: any config NOT starting with `test` (case-insensitive)

**Edge cases**:
- `gradle.lockfile` is opt-in (`dependencyLocking` must be enabled in `build.gradle`) — detection will simply not find the file if not present
- Multi-project builds may have per-project lockfiles — for now, only detect `gradle.lockfile` in the scanned directory root
- Lines may have platform-specific configurations like `compileClasspath,runtimeClasspath` — treat the whole CSV as the configurations list

### 3.3 PURL Construction

Add `BuildMavenPURL(group, artifact, version string) string` to `internal/sbom/purl.go`:

```
pkg:maven/<groupId>/<artifactId>@<version>
```

- `groupId` becomes the namespace
- `artifactId` becomes the name

**Examples**:
| Dependency | PURL |
|-----------|------|
| `org.apache.logging.log4j:log4j-core:2.14.1` | `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1` |
| `com.google.guava:guava:32.1.3-jre` | `pkg:maven/com.google.guava/guava@32.1.3-jre` |

Note: The `BuildPURL()` dispatcher needs a new path since Gradle packages are identified by `group:artifact:version` (3-part), not just `name:version`. The `Package.Name` field will store `group:artifact` (colon-separated) for Gradle, and `BuildPURL()` will split on `:` for the maven ecosystem.

### 3.4 CycloneDX Mapping

In `mapComponent()`, for ecosystem `"maven"`:
- External reference URL: `https://central.sonatype.com/artifact/<group>/<artifact>`
- Component name: use `artifact` portion only for display, with `group` as a property or in the PURL namespace
- No integrity hashes available from `gradle.lockfile` (Gradle lockfiles don't include checksums)

### 3.5 Test Data

Create `testdata/lockfiles/gradle/`:
- `gradle.lockfile`: ~10 dependencies including test-only deps, various configurations

Snapshot: `testdata/snapshots/gradle.sbom.json`

---

## Phase 4: Integration

### 4.1 Parser Registry Update

In `internal/lockfile/parser.go`, add to `registry` slice in `init()`:

```go
// Go (after Python, before end)
&GoModParser{},
// Rust
&CargoParser{},
// Java/Gradle
&GradleParser{},
```

**Detection priority** (updated):
```
bun.lockb > bun.lock > pnpm-lock.yaml > yarn.lock > package-lock.json >
uv.lock > poetry.lock > pdm.lock > requirements.txt >
go.mod > Cargo.lock > gradle.lockfile
```

JS/TS > Python > Go > Rust > Java. In practice, a project will only have one ecosystem's lockfiles.

### 4.2 Ecosystem Mapping

Update `ecosystemFromLockfileType()` in `internal/sbom/generator.go`:

```go
case lockfile.TypeGoMod:
    return "golang"
case lockfile.TypeCargoLock:
    return "cargo"
case lockfile.TypeGradleLock:
    return "maven"
```

### 4.3 PURL Dispatcher

Update `BuildPURL()` in `internal/sbom/purl.go`:

```go
func BuildPURL(name, version, ecosystem string) string {
    switch ecosystem {
    case "pypi":
        return BuildPyPIPURL(name, version)
    case "golang":
        return BuildGolangPURL(name, version)
    case "cargo":
        return BuildCargoPURL(name, version)
    case "maven":
        return BuildMavenPURL(name, version)  // name is "group:artifact"
    default:
        return BuildNPMPURL(name, version)
    }
}
```

### 4.4 Component Mapping

Update `mapComponent()` in `internal/sbom/cyclonedx.go` to handle new ecosystems:

- **golang**: external ref → `https://pkg.go.dev/...`, hash parsing for `h1:` format
- **cargo**: external ref → `https://crates.io/crates/...`, hash parsing for `sha256:` hex
- **maven**: external ref → `https://central.sonatype.com/artifact/...`, parse `group:artifact` for display name

### 4.5 Project Info Reader

Update `Generate()` in `internal/sbom/generator.go` to try:
1. `pyproject.toml` (Python)
2. `package.json` (JS/TS)
3. `go.mod` (Go — extract `module` directive)
4. `Cargo.toml` (Rust — extract `[package].name` and `[package].version`)
5. `settings.gradle` / `build.gradle` (Java — extract `rootProject.name`)

### 4.6 Config and VEX Updates

- `vex.osv_ecosystem` in `.forgeseal.yaml.example`: document that this is auto-detected from lockfile type and rarely needs manual setting
- OSV.dev queries already use PURLs, so no code changes needed for VEX triage — it's automatically ecosystem-agnostic

### 4.7 Error Messages

Update the `Detect()` error message to include new lockfile names:

```
no lockfile found in %s; supported: bun.lockb, bun.lock, pnpm-lock.yaml, yarn.lock,
package-lock.json, uv.lock, poetry.lock, pdm.lock, requirements.txt, go.mod,
Cargo.lock, gradle.lockfile
```

### 4.8 CLI and README

- Update `rootCmd.Long` to mention Go, Rust, and Java
- Update `action.yml` description
- Update `.goreleaser.yaml` brew description
- Update `README.md`: add Go/Rust/Gradle to supported lockfiles table, add examples, update architecture section

---

## Test Matrix

| Test File | What It Tests |
|-----------|---------------|
| `internal/lockfile/gomod_test.go` | `go.mod` + `go.sum` parsing, replace resolution, indirect detection, major version suffixes |
| `internal/lockfile/cargo_test.go` | `Cargo.lock` parsing, workspace root skipping, multi-version crates, dependency string parsing |
| `internal/lockfile/gradle_test.go` | `gradle.lockfile` parsing, dev detection via configurations, comment skipping |
| `internal/sbom/purl_test.go` | Add cases for `pkg:golang/`, `pkg:cargo/`, `pkg:maven/` PURLs |
| `internal/sbom/generator_test.go` | Add `TestGeneratorGenerateGo`, `TestGeneratorGenerateRust`, `TestGeneratorGenerateGradle` |
| `internal/sbom/snapshot_test.go` | Snapshot tests auto-discover new `testdata/lockfiles/` directories |

---

## Implementation Constraints

1. **Zero new `go.mod` dependencies** — Go modules uses line-oriented text (no library needed), Cargo.lock uses TOML (`pelletier/go-toml/v2` already present), Gradle uses plain text (no library needed)
2. **Follow existing patterns** — map-based TOML decoding (like `uv.go`, `pdm.go`), `Parser` interface with `Parse(ctx, io.Reader)`, `Type()`, `Filenames()`
3. **Lockfile-only** — never invoke `go`, `cargo`, or `gradle` commands. If the lockfile doesn't exist, forgeseal reports an error.
4. **Test fixtures in `testdata/`** — vendor fixture files directly; no network-dependent test setup
5. **Snapshot testing** — golden file pattern with `-update` flag, same as existing `TestSnapshots`

---

## Estimated Effort

| Phase | Effort | Files Created | Files Modified |
|-------|--------|---------------|----------------|
| Go | 1–2 days | `gomod.go`, `gomod_test.go`, testdata, snapshot | `model.go`, `parser.go`, `purl.go`, `cyclonedx.go`, `generator.go` |
| Rust | 1 day | `cargo.go`, `cargo_test.go`, testdata, snapshot | `model.go`, `parser.go`, `purl.go`, `cyclonedx.go`, `generator.go` |
| Gradle | 1 day | `gradle.go`, `gradle_test.go`, testdata, snapshot | `model.go`, `parser.go`, `purl.go`, `cyclonedx.go`, `generator.go` |
| Integration | 0.5 days | — | `parser.go`, `generator.go`, `purl_test.go`, `generator_test.go`, README, action.yml |
| **Total** | **3.5–4.5 days** | **9 new files** | **~8 modified files** |
