package lockfile

// LockfileType identifies the package manager lockfile format.
type LockfileType string

const (
	TypeNPM         LockfileType = "npm"
	TypeYarnClassic LockfileType = "yarn-classic"
	TypeYarnBerry   LockfileType = "yarn-berry"
	TypePNPM        LockfileType = "pnpm"
	TypeBunText     LockfileType = "bun-text"
	TypeBunBinary   LockfileType = "bun-binary"
)

// Package represents a resolved dependency from a lockfile.
type Package struct {
	Name         string
	Version      string
	Integrity    string // SRI hash (e.g., "sha512-...")
	Resolved     string // download URL
	Dependencies []DependencyRef
	Dev          bool
	Optional     bool
	Peer         bool
}

// DependencyRef is a reference from one package to another.
type DependencyRef struct {
	Name    string
	Version string // version constraint or resolved version
}

// LockfileResult holds the parsed output of a lockfile.
type LockfileResult struct {
	Type     LockfileType
	Packages []Package
}
