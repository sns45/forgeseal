# forgeseal

Supply chain security for JavaScript and TypeScript projects. Generates CycloneDX SBOMs from lockfiles, signs them with Sigstore (keyless), produces SLSA provenance attestations, and manages VEX vulnerability documents.

Built for EU Cyber Resilience Act (CRA) compliance. forgeseal's own releases are attested by forgeseal.

## Features

| Capability | Description |
|---|---|
| **SBOM Generation** | CycloneDX v1.4/v1.5/v1.6 from any JS/TS lockfile (JSON and XML output) |
| **Sigstore Signing** | Keyless signing via Fulcio + Rekor transparency log (OIDC identity) |
| **SLSA Provenance** | In-toto attestations with SLSA v1 provenance predicate |
| **VEX Management** | OpenVEX v0.2 document CRUD, automated triage via OSV.dev |
| **Verification** | Validate signatures, bundles, and attestation integrity |
| **Pipeline** | Single command: SBOM, sign, attest, triage |

## Supported Lockfiles

| Package Manager | File | Parser |
|---|---|---|
| npm | `package-lock.json` | v2 and v3 schemas |
| Yarn Classic | `yarn.lock` | v1 text format (state machine) |
| Yarn Berry | `yarn.lock` | v2/v3/v4 YAML (auto-detected via `__metadata:` header) |
| pnpm | `pnpm-lock.yaml` | v6 and v9 schemas |
| Bun | `bun.lock` | JSONC text format (Bun v1.2+) |
| Bun (binary) | `bun.lockb` | Shells out to `bun` CLI; prefers `bun.lock` when both exist |

Detection priority: `bun.lockb` > `bun.lock` > `pnpm-lock.yaml` > `yarn.lock` > `package-lock.json`. Yarn v1 vs Berry is determined by content inspection.

**Note on Yarn Berry hashes:** Yarn Berry uses a proprietary checksum format that is not compatible with standard SRI hashes or CycloneDX hash algorithms. Components from Yarn Berry lockfiles will be included in the SBOM without integrity hashes. This is a format limitation, not a forgeseal bug.

## Installation

```bash
# Homebrew (macOS / Linux)
brew install sns45/tap/forgeseal

# Quick install (latest release)
curl -sSL https://raw.githubusercontent.com/sns45/forgeseal/main/scripts/install.sh | sh

# Go
go install github.com/sn45/forgeseal/cmd/forgeseal@latest

# Docker
docker run --rm -v $(pwd):/src ghcr.io/sns45/forgeseal pipeline --dir /src

# From source
git clone https://github.com/sns45/forgeseal.git && cd forgeseal && make build
```

Requires Go 1.23+ for building from source.

## Quick Start

```bash
# Generate an SBOM from the current directory
forgeseal sbom --dir .

# Full pipeline: SBOM + sign + attest + VEX triage
forgeseal pipeline --dir . --output-dir ./forgeseal-output --vex-triage

# Sign an existing artifact
forgeseal sign --artifact sbom.cdx.json

# Verify a signed artifact
forgeseal verify --artifact sbom.cdx.json --bundle sbom.cdx.json.sigstore.json
```

## Commands

### `forgeseal sbom`

Generate a CycloneDX SBOM from a lockfile.

```bash
forgeseal sbom --dir ./my-project
forgeseal sbom --lockfile ./package-lock.json --output-format xml
forgeseal sbom --include-dev --spec-version 1.6 -o sbom.json
```

| Flag | Default | Description |
|---|---|---|
| `--dir` | `.` | Project directory to scan |
| `--lockfile` | (auto-detect) | Explicit lockfile path |
| `--spec-version` | `1.5` | CycloneDX spec version: `1.4`, `1.5`, `1.6` |
| `--output-format` | `json` | Output format: `json` or `xml` |
| `--include-dev` | `false` | Include devDependencies |
| `--no-deps` | `false` | Only direct dependencies |

Output includes: metadata (timestamp, tool info, root component), components with PURLs and integrity hashes, and a dependency graph.

### `forgeseal sign`

Sign an artifact with Sigstore keyless signing.

```bash
forgeseal sign --artifact sbom.cdx.json
forgeseal sign --artifact sbom.cdx.json --identity-token $OIDC_TOKEN
```

| Flag | Default | Description |
|---|---|---|
| `--artifact` | (required) | Path to the artifact to sign |
| `--identity-token` | (auto) | Explicit OIDC token; auto-detected in GitHub Actions |
| `--fulcio-url` | `https://fulcio.sigstore.dev` | Fulcio CA instance |
| `--rekor-url` | `https://rekor.sigstore.dev` | Rekor transparency log |
| `--bundle` | `<artifact>.sigstore.json` | Output path for the Sigstore bundle |

The signing flow: obtain OIDC token, generate ephemeral ECDSA P-256 keypair, sign the artifact, and produce a `.sigstore.json` bundle. In GitHub Actions, the OIDC token is obtained automatically when the workflow has `permissions: id-token: write`.

### `forgeseal attest`

Generate a SLSA v1 provenance attestation as an in-toto statement.

```bash
forgeseal attest --subject sbom.cdx.json
forgeseal attest --subject sbom.cdx.json --sign --repo https://github.com/org/repo --commit abc123
```

| Flag | Default | Description |
|---|---|---|
| `--subject` | | Path to the artifact being attested |
| `--subject-digest` | | Explicit `sha256:...` digest |
| `--repo` | (auto in CI) | Source repository URI |
| `--commit` | (auto in CI) | Source commit SHA |
| `--sign` | `true` | Sign the attestation with Sigstore DSSE |

CI environment variables (`GITHUB_REPOSITORY`, `GITHUB_SHA`, etc.) are automatically detected.

### `forgeseal vex`

Manage Vulnerability Exploitability eXchange (VEX) documents.

```bash
# Create an empty VEX document
forgeseal vex create -o vex.json

# Add a statement
forgeseal vex add --vex vex.json --cve CVE-2024-1234 \
  --product "pkg:npm/my-app@1.0.0" \
  --status not_affected \
  --justification vulnerable_code_not_present

# List statements
forgeseal vex list --vex vex.json

# Automated triage: scan SBOM against OSV.dev
forgeseal vex triage --sbom sbom.cdx.json -o vex.json
forgeseal vex triage --sbom sbom.cdx.json --format cyclonedx -o sbom-with-vex.json
```

**VEX statuses:** `not_affected`, `affected`, `fixed`, `under_investigation`

**Justifications** (for `not_affected`): `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_cannot_be_controlled_by_adversary`, `vulnerable_code_not_in_execute_path`, `inline_mitigations_already_exist`

The `triage` subcommand queries the [OSV.dev](https://osv.dev) batch API, batching PURLs in groups of 1000, and generates `under_investigation` stubs for each discovered vulnerability.

### `forgeseal verify`

Verify Sigstore bundles and attestations.

```bash
forgeseal verify --artifact sbom.cdx.json --bundle sbom.cdx.json.sigstore.json
forgeseal verify --attestation sbom.cdx.json.intoto.jsonl
```

| Flag | Default | Description |
|---|---|---|
| `--artifact` | | Path to the artifact |
| `--bundle` | | Path to `.sigstore.json` bundle |
| `--attestation` | | Path to SLSA attestation |
| `--expected-issuer` | | Expected OIDC issuer for identity verification |
| `--expected-identity` | | Expected signer identity (regex) |

### `forgeseal pipeline`

Run the full security pipeline in one command.

```bash
forgeseal pipeline --dir . --output-dir ./forgeseal-output
forgeseal pipeline --dir . --vex-triage --identity-token $TOKEN
```

| Flag | Default | Description |
|---|---|---|
| `--dir` | `.` | Project directory |
| `--output-dir` | `./forgeseal-output` | Directory for all generated artifacts |
| `--lockfile` | (auto-detect) | Explicit lockfile path |
| `--sign` | `true` | Sign artifacts with Sigstore |
| `--attest` | `true` | Generate SLSA provenance |
| `--vex-triage` | `false` | Run VEX triage against OSV.dev |
| `--include-dev` | `false` | Include devDependencies |
| `--identity-token` | (auto) | Explicit OIDC token |

**Pipeline steps:**
1. Parse lockfile, generate CycloneDX SBOM (`sbom.cdx.json`)
2. Sign SBOM (`sbom.cdx.json.sigstore.json`)
3. Generate SLSA provenance attestation (`sbom.cdx.json.intoto.jsonl`), optionally sign it
4. Query OSV.dev and generate VEX document (`vex.json`)

## GitHub Action

```yaml
name: Supply Chain Security
on: [push]

permissions:
  id-token: write  # Required for Sigstore keyless signing
  contents: read

jobs:
  forgeseal:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: sn45/forgeseal@v1
        with:
          command: pipeline
          dir: '.'
          output-dir: './forgeseal-output'
          sign: 'true'
          attest: 'true'
          vex-triage: 'true'

      - uses: actions/upload-artifact@v4
        with:
          name: supply-chain-artifacts
          path: ./forgeseal-output/
```

The action runs in a Docker container and automatically obtains OIDC tokens from the GitHub Actions runtime.

## Configuration

forgeseal reads `.forgeseal.yaml` from the project directory or home directory. All settings can be overridden via flags or environment variables (prefixed `FORGESEAL_`).

```yaml
sbom:
  spec_version: "1.5"
  format: json
  include_dev: false

sign:
  fulcio_url: https://fulcio.sigstore.dev
  rekor_url: https://rekor.sigstore.dev

attest:
  auto_sign: true

vex:
  format: openvex
  osv_ecosystem: npm
```

Environment variable mapping: `FORGESEAL_SBOM_SPEC_VERSION`, `FORGESEAL_SIGN_FULCIO_URL`, etc.

## Architecture

```
cmd/forgeseal/          Entrypoint
internal/
  cli/                  Cobra commands (sbom, sign, attest, vex, verify, pipeline)
  config/               Viper configuration loading
  lockfile/             6 parsers + auto-detection + domain types
  sbom/                 CycloneDX BOM generation, PURL construction, dependency mapping
  signing/              Sigstore signer interface, bundle serialization
  provenance/           SLSA v1 attestation builder, CI environment detection
  vex/                  OpenVEX CRUD, OSV.dev client, CycloneDX VEX embedding
  verify/               Bundle and attestation verification
```

### Key Design Decisions

**Parser interface.** Each lockfile format implements `Parser` with `Parse(ctx, io.Reader)`, `Type()`, and `Filenames()`. Binary formats (bun.lockb) additionally implement `FileParser` with `ParseFile(ctx, path)`. Detection iterates a priority ordered registry and uses content inspection for yarn v1 vs Berry disambiguation.

**PURL construction.** Package URLs follow the PURL spec: scoped packages like `@babel/core@7.24.0` become `pkg:npm/babel/core@7.24.0` (the `@` prefix is stripped from the namespace per spec).

**Signing abstraction.** The `Signer` interface provides `SignBlob` (raw content) and `SignDSSE` (in-toto envelope). The current implementation generates ephemeral ECDSA P-256 signatures. Full Sigstore integration (Fulcio certificate issuance + Rekor log recording) can be added by depending on `sigstore-go` without changing the interface.

**VEX triage.** PURLs extracted from the SBOM are batched in groups of 1000 and sent to the OSV.dev `/v1/querybatch` endpoint. Results are mapped to `under_investigation` VEX stubs for manual review.

## Output Artifacts

| File | Content |
|---|---|
| `sbom.cdx.json` | CycloneDX SBOM (JSON) |
| `sbom.cdx.json.sigstore.json` | Sigstore bundle for the SBOM |
| `sbom.cdx.json.intoto.jsonl` | SLSA v1 provenance attestation |
| `sbom.cdx.json.intoto.jsonl.sigstore.json` | Sigstore bundle for the attestation |
| `vex.json` | OpenVEX document with vulnerability triage results |

## Development

```bash
make build       # Build to ./bin/forgeseal
make test        # Run tests with race detection
make lint        # Run golangci-lint
make install     # Install to $GOPATH/bin
make clean       # Remove build artifacts
```

Cross-platform releases (Linux, macOS, Windows; amd64 + arm64) are handled by GoReleaser.

## License

Apache 2.0
