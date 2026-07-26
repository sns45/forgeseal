# forgeseal Python Ecosystem Support — Implementation Plan

## Summary

Extend forgeseal to parse Python lockfiles (requirements.txt, poetry.lock, pdm.lock, uv.lock) and generate CycloneDX SBOMs with PyPI PURLs. The signing, attestation, VEX triage, and pipeline commands already work ecosystem-agnostically — only the lockfile parsing layer and PURL/registry mapping need changes.

**No tool in existence combines all five capabilities for Python. pdm.lock parsing does not exist in ANY tool (Syft, Trivy, cdxgen, cyclonedx-python — none). uv.lock support is nascent. This is genuine whitespace.**

## Architecture Constraints

- **Zero new dependencies.** `github.com/pelletier/go-toml/v2` is already an indirect dep via Viper. Use it for TOML parsing (poetry.lock, pdm.lock, uv.lock). requirements.txt is line-based — parse with bufio.
- **Follow existing patterns exactly.** Each parser implements `Parser` interface from `internal/lockfile/parser.go`. Registration in `registry` with detection priority. Test files in `testdata/lockfiles/<format>/`.
- **PyPI PURL format:** `pkg:pypi/package-name@version` (names normalized to lowercase, underscores→hyphens per PEP 503).
- **OSV ecosystem:** PyPI (the existing VEX triage uses PURLs, so `pkg:pypi/...` PURLs will query OSV correctly with zero changes to the VEX code).
- **Project metadata:** Read from `pyproject.toml` (name, version) when no `package.json` found.

## Detection Priority

Python lockfiles are detected AFTER JS/TS lockfiles (JS takes precedence in mixed projects):

```
bun.lockb > bun.lock > pnpm-lock.yaml > yarn.lock > package-lock.json >
uv.lock > poetry.lock > pdm.lock > requirements.txt
```

Rationale: uv.lock is most precise (full dependency graph + hashes), poetry.lock next (full graph), pdm.lock next (full graph), requirements.txt last (flat, no graph).

## Files to Create

### 1. `internal/lockfile/requirements_txt.go`

Parser for `requirements.txt` (pip freeze output format).

**Format rules:**

- One package per line: `package==version`
- Lines starting with `#` are comments
- Lines starting with `-r`, `-c`, `-e`, `--` are directives (skip)
- Lines with `\` continuation (join with next line)
- Extras: `package[extra]==version` → strip extras for name
- Hashes: `--hash=sha256:abc` after version spec → capture as integrity
- Environment markers: `; python_version >= "3.8"` after version → ignore
- Blank lines skipped
- Version specifiers: only `==` gives exact version. `>=`, `~=`, `!=` etc. → record the specifier but mark version as constraint, not pinned. For SBOM purposes, only `==` pinned versions produce components.

**Struct:**

```go
type RequirementsTxtParser struct{}
func (p *RequirementsTxtParser) Type() LockfileType      { return TypeRequirementsTxt }
func (p *RequirementsTxtParser) Filenames() []string      { return []string{"requirements.txt"} }
func (p *RequirementsTxtParser) Parse(ctx, r) (*LockfileResult, error) { ... }
```

### 2. `internal/lockfile/poetry.go`

Parser for `poetry.lock` (TOML format).

**Structure (TOML):**

```toml
[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."
optional = false
python-versions = ">=3.8"

[package.dependencies]
charset-normalizer = ">=2,<4"
idna = ">=2.5,<4"

[package.extras]
socks = ["PySocks (>=1.5.6,!=1.5.7)"]

[[package.files]]
file = "requests-2.31.0-py3-none-any.whl"
hash = "sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003eb"

[metadata]
lock-version = "2.0"
python-versions = "^3.10"
content-hash = "abc123..."
```

**Parse logic:**

- Decode top-level `[[package]]` array
- For each package: extract name, version, optional flag
- Extract `[package.dependencies]` as DependencyRef list
- Extract first hash from `[[package.files]]` array for integrity
- Detect dev deps: poetry.lock doesn't mark dev directly in the lock file — all packages are included. The `optional` field is NOT the same as dev. For simplicity, include all packages (user controls via `--include-dev` at the SBOM level if they want filtering, but poetry.lock doesn't reliably distinguish).

**Struct:**

```go
type PoetryParser struct{}
func (p *PoetryParser) Type() LockfileType { return TypePoetry }
func (p *PoetryParser) Filenames() []string { return []string{"poetry.lock"} }
```

### 3. `internal/lockfile/pdm.go`

Parser for `pdm.lock` (TOML format). **This is the most differentiated parser — no other tool supports it.**

**Structure (TOML):**

```toml
[[metadata.targets]]
requires_python = ">=3.10"

[metadata.files]
"requests 2.31.0" = [
    {file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:58cd..."},
]

[[package]]
name = "requests"
version = "2.31.0"
requires_python = ">=3.8"
summary = "Python HTTP for Humans."

[package.dependencies]
charset-normalizer = ">=2,<4"
idna = ">=2.5,<4"

[[package]]
name = "pytest"
version = "8.1.0"
groups = ["dev"]
```

**Parse logic:**

- Decode `[[package]]` array
- Extract name, version, summary
- Extract dependencies from `[package.dependencies]` (inline table or separate section — pdm.lock uses a flat dependencies list on the package)
- Dev detection: pdm.lock includes a `groups` field. If `groups` contains `"dev"`, mark as dev.
- Hashes: found in `[metadata.files]` keyed by `"name version"` string

### 4. `internal/lockfile/uv.go`

Parser for `uv.lock` (TOML format).

**Structure (TOML):**

```toml
version = 1
requires-python = ">=3.12"

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }

[package.dependencies]
charset-normalizer = [
    { name = "charset-normalizer", specifier = ">=2,<4" },
]

[[package.wheels]]
url = "https://files.pythonhosted.org/..."
hash = "sha256:58cd..."
size = 62574

[[package]]
name = "my-project"
version = "0.1.0"
source = { virtual = "." }

[package.dev-dependencies]
group = [
    { name = "pytest" },
]
```

**Parse logic:**

- Decode `[[package]]` array
- Skip packages with `source.virtual` or `source.editable` (these are the project itself)
- Extract name, version from each package
- Extract dependencies from nested `[package.dependencies]` — each value is an array of objects with `name` and optional `specifier`
- Dev detection: packages listed under `[package.dev-dependencies]` on other packages
- Hashes: from `[[package.wheels]]` or `[[package.sdist]]` entries

### 5. `internal/lockfile/model.go` — Add new types

```go
const (
    // ... existing types ...
    TypeRequirementsTxt LockfileType = "requirements-txt"
    TypePoetry          LockfileType = "poetry"
    TypePDM             LockfileType = "pdm"
    TypeUV              LockfileType = "uv"
)
```

### 6. `internal/lockfile/parser.go` — Update registry

Add Python parsers to `registry` after all JS parsers:

```go
func init() {
    registry = []Parser{
        // JS/TS (higher priority)
        &BunBinaryParser{},
        &BunTextParser{},
        &PNPMParser{},
        &YarnBerryParser{},
        &YarnClassicParser{},
        &NPMParser{},
        // Python (lower priority)
        &UVParser{},
        &PoetryParser{},
        &PDMParser{},
        &RequirementsTxtParser{},
    }
}
```

Update `Detect()` error message to include Python lockfiles.

### 7. `internal/sbom/purl.go` — Ecosystem-aware PURL

The current `BuildPURL` always uses `"npm"` type. Refactor:

```go
// BuildPURL constructs a Package URL. Ecosystem is "npm" or "pypi".
func BuildPURL(name, version, ecosystem string) string {
    if ecosystem == "pypi" {
        return BuildPyPIPURL(name, version)
    }
    return BuildNPMPURL(name, version)
}

func BuildPyPIPURL(name, version string) string {
    // Normalize per PEP 503: lowercase, replace underscores/dots with hyphens
    normalized := normalizePyPIName(name)
    purl := packageurl.NewPackageURL("pypi", "", normalized, version, nil, "")
    return purl.ToString()
}

func normalizePyPIName(name string) string {
    // PEP 503: lowercase, consecutive [-_.] runs → single hyphen
    name = strings.ToLower(name)
    name = strings.ReplaceAll(name, "_", "-")
    name = strings.ReplaceAll(name, ".", "-")
    // Collapse consecutive hyphens
    for strings.Contains(name, "--") {
        name = strings.ReplaceAll(name, "--", "-")
    }
    return name
}
```

### 8. `internal/sbom/cyclonedx.go` — Ecosystem-aware component mapping

Update `mapComponent` to accept ecosystem parameter:

```go
func mapComponent(pkg lockfile.Package, ecosystem string) cdx.Component {
    purl := BuildPURL(pkg.Name, pkg.Version, ecosystem)
    // ...
    // External reference URL based on ecosystem
    var registryURL string
    if ecosystem == "pypi" {
        registryURL = "https://pypi.org/project/" + normalizePyPIName(pkg.Name) + "/"
    } else {
        registryURL = "https://www.npmjs.com/package/" + pkg.Name
    }
    // ...
}
```

### 9. `internal/sbom/generator.go` — Detect ecosystem + read pyproject.toml

```go
func ecosystemFromLockfileType(lt lockfile.LockfileType) string {
    switch lt {
    case lockfile.TypeRequirementsTxt, lockfile.TypePoetry, lockfile.TypePDM, lockfile.TypeUV:
        return "pypi"
    default:
        return "npm"
    }
}
```

Add `readPyProjectInfo(dir string) *ProjectInfo` to read `[project]` table from `pyproject.toml` for name/version.

Update `Generate()` to try `pyproject.toml` when `package.json` not found.

### 10. Test Data Files

Create minimal but realistic lockfiles:

```
testdata/lockfiles/requirements-txt/requirements.txt
testdata/lockfiles/poetry/poetry.lock
testdata/lockfiles/pdm/pdm.lock
testdata/lockfiles/uv/uv.lock
```

Each should contain at least: `requests` (with deps), `flask` or similar (with deps), and one dev-only package where the format supports it. Include at least one package with integrity hashes.

### 11. Test Files

```
internal/lockfile/requirements_txt_test.go
internal/lockfile/poetry_test.go
internal/lockfile/pdm_test.go
internal/lockfile/uv_test.go
internal/sbom/purl_test.go  (extend with PyPI test cases)
```

Follow existing test patterns exactly — open testdata file, parse, verify known packages by name, check version, check integrity, check dev flag.

### 12. Example Python Project

```
examples/flask-app/
    pyproject.toml
    uv.lock          (or poetry.lock — pick uv since it's trendiest)
    app.py
```

Minimal Flask or FastAPI app for E2E dogfooding. Update CI workflow to also run:

```yaml
- name: E2E pipeline (examples/flask-app)
  run: |
    ./bin/forgeseal pipeline \
      --dir ./examples/flask-app \
      --output-dir ./e2e-output-python \
      --sign=false \
      --attest=false \
      --vex-triage
```

### 13. README Updates

Add to supported lockfiles table:

| Package Manager | File               | Parser                                          |
| --------------- | ------------------ | ----------------------------------------------- |
| pip             | `requirements.txt` | Pinned (`==`) dependencies with optional hashes |
| Poetry          | `poetry.lock`      | TOML v2 format with full dependency graph       |
| PDM             | `pdm.lock`         | TOML format with groups-based dev detection     |
| uv              | `uv.lock`          | TOML format (Astral uv v0.1+)                   |

Update detection priority documentation.

## Implementation Order

1. **model.go** — Add 4 new `LockfileType` constants
2. **requirements_txt.go** + test — Simplest parser, line-based
3. **poetry.go** + test — TOML, most common Python lockfile
4. **pdm.go** + test — TOML, unique differentiator
5. **uv.go** + test — TOML, trending format
6. **parser.go** — Register all 4, update Detect()
7. **purl.go** — Add PyPI PURL + normalization, extend tests
8. **cyclonedx.go** — Ecosystem-aware component mapping
9. **generator.go** — Ecosystem detection + pyproject.toml reading
10. **Test data** — Create all 4 lockfile fixtures
11. **Example project** — flask-app with uv.lock
12. **E2E** — Verify `forgeseal pipeline --dir examples/flask-app` works
13. **README** — Update docs

## Key Design Decisions

1. **requirements.txt**: Only `==` pinned versions produce SBOM components. Other specifiers are too ambiguous for supply chain attestation.
2. **poetry.lock dev detection**: Not reliably distinguishable in the lock file itself. Include all packages; let `--include-dev` control filtering at SBOM generation.
3. **pdm.lock dev detection**: Use `groups` field — if it contains `"dev"`, mark as dev dependency.
4. **uv.lock**: Skip virtual/editable source packages (the project itself). Extract hashes from wheels/sdist entries.
5. **PURL normalization**: Follow PEP 503 strictly — lowercase, underscores/dots→hyphens. This is critical for OSV.dev lookups to work correctly.
6. **Ecosystem parameter threading**: The `LockfileResult.Type` already tells us which ecosystem. Thread through to PURL construction and component mapping. No new fields needed on `Package` struct.
