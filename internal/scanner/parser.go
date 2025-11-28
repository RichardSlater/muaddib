package scanner

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Package represents a package with name and version
type Package struct {
	Name    string
	Version string
	IsDev   bool
	Source  string // "direct" or "transitive"
}

// PackageJSON represents the structure of a package.json file
type PackageJSON struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

// PackageLockJSON represents the structure of a package-lock.json file (v2/v3)
type PackageLockJSON struct {
	Name            string                      `json:"name"`
	Version         string                      `json:"version"`
	LockfileVersion int                         `json:"lockfileVersion"`
	Packages        map[string]PackageLockEntry `json:"packages"`     // v2/v3 format
	Dependencies    map[string]LegacyLockEntry  `json:"dependencies"` // v1 format
}

// PackageLockEntry represents an entry in the packages map (v2/v3)
type PackageLockEntry struct {
	Version      string            `json:"version"`
	Resolved     string            `json:"resolved"`
	Dev          bool              `json:"dev"`
	Optional     bool              `json:"optional"`
	Dependencies map[string]string `json:"dependencies"`
}

// LegacyLockEntry represents an entry in the v1 dependencies map
type LegacyLockEntry struct {
	Version      string                     `json:"version"`
	Dev          bool                       `json:"dev"`
	Optional     bool                       `json:"optional"`
	Requires     map[string]string          `json:"requires"`
	Dependencies map[string]LegacyLockEntry `json:"dependencies"`
}

// ParsePackageJSON parses a package.json file and extracts all dependencies
func ParsePackageJSON(content string, includeDev bool) ([]*Package, error) {
	var pkg PackageJSON
	if err := json.Unmarshal([]byte(content), &pkg); err != nil {
		return nil, fmt.Errorf("failed to parse package.json: %w", err)
	}

	var packages []*Package

	// Production dependencies
	for name, version := range pkg.Dependencies {
		packages = append(packages, &Package{
			Name:    name,
			Version: cleanVersion(version),
			IsDev:   false,
			Source:  "direct",
		})
	}

	// Dev dependencies
	if includeDev {
		for name, version := range pkg.DevDependencies {
			packages = append(packages, &Package{
				Name:    name,
				Version: cleanVersion(version),
				IsDev:   true,
				Source:  "direct",
			})
		}
	}

	// Optional dependencies
	for name, version := range pkg.OptionalDependencies {
		packages = append(packages, &Package{
			Name:    name,
			Version: cleanVersion(version),
			IsDev:   false,
			Source:  "direct",
		})
	}

	// Peer dependencies
	for name, version := range pkg.PeerDependencies {
		packages = append(packages, &Package{
			Name:    name,
			Version: cleanVersion(version),
			IsDev:   false,
			Source:  "direct",
		})
	}

	return packages, nil
}

// ParsePackageLock parses a package-lock.json file and extracts all dependencies including transitive
func ParsePackageLock(content string, includeDev bool) ([]*Package, error) {
	var lock PackageLockJSON
	if err := json.Unmarshal([]byte(content), &lock); err != nil {
		return nil, fmt.Errorf("failed to parse package-lock.json: %w", err)
	}

	seen := make(map[string]bool)
	var packages []*Package

	// v2/v3 format uses "packages" field
	if len(lock.Packages) > 0 {
		for pkgPath, entry := range lock.Packages {
			// Skip the root package (empty path or ".")
			if pkgPath == "" || pkgPath == "." {
				continue
			}

			// Skip dev dependencies if not included
			if entry.Dev && !includeDev {
				continue
			}

			name := extractPackageName(pkgPath)
			if name == "" {
				continue
			}

			key := name + "@" + entry.Version
			if seen[key] {
				continue
			}
			seen[key] = true

			packages = append(packages, &Package{
				Name:    name,
				Version: entry.Version,
				IsDev:   entry.Dev,
				Source:  "transitive",
			})
		}
	}

	// v1 format uses "dependencies" field
	if len(lock.Dependencies) > 0 {
		parseLegacyDeps(lock.Dependencies, "", includeDev, seen, &packages)
	}

	return packages, nil
}

// parseLegacyDeps recursively parses v1 format dependencies
func parseLegacyDeps(deps map[string]LegacyLockEntry, prefix string, includeDev bool, seen map[string]bool, packages *[]*Package) {
	for name, entry := range deps {
		// Skip dev dependencies if not included
		if entry.Dev && !includeDev {
			continue
		}

		key := name + "@" + entry.Version
		if seen[key] {
			continue
		}
		seen[key] = true

		*packages = append(*packages, &Package{
			Name:    name,
			Version: entry.Version,
			IsDev:   entry.Dev,
			Source:  "transitive",
		})

		// Recurse into nested dependencies
		if len(entry.Dependencies) > 0 {
			parseLegacyDeps(entry.Dependencies, name+"/", includeDev, seen, packages)
		}
	}
}

// extractPackageName extracts the package name from a package path
// e.g., "node_modules/lodash" -> "lodash"
// e.g., "node_modules/@types/node" -> "@types/node"
// e.g., "node_modules/foo/node_modules/bar" -> "bar"
func extractPackageName(pkgPath string) string {
	// Remove "node_modules/" prefix
	path := strings.TrimPrefix(pkgPath, "node_modules/")

	// Handle nested node_modules (use the last package in the chain)
	parts := strings.Split(path, "/node_modules/")
	lastPart := parts[len(parts)-1]

	// Handle scoped packages (@org/package)
	if strings.HasPrefix(lastPart, "@") {
		// Scoped package: take @scope/name
		segments := strings.SplitN(lastPart, "/", 3)
		if len(segments) >= 2 {
			return segments[0] + "/" + segments[1]
		}
	}

	// Regular package: take first segment
	segments := strings.SplitN(lastPart, "/", 2)
	return segments[0]
}

// cleanVersion removes semver range operators to get a cleaner version
func cleanVersion(version string) string {
	// Remove common prefixes
	version = strings.TrimPrefix(version, "^")
	version = strings.TrimPrefix(version, "~")
	version = strings.TrimPrefix(version, ">=")
	version = strings.TrimPrefix(version, ">")
	version = strings.TrimPrefix(version, "<=")
	version = strings.TrimPrefix(version, "<")
	version = strings.TrimPrefix(version, "=")
	version = strings.TrimSpace(version)

	// Handle ranges like "1.0.0 - 2.0.0", take the first version
	if idx := strings.Index(version, " "); idx > 0 {
		version = version[:idx]
	}

	return version
}
