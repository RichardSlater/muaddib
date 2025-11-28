package vuln

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

const (
	// DataDogIOCURL is the primary IOC source from DataDog
	DataDogIOCURL = "https://raw.githubusercontent.com/DataDog/indicators-of-compromise/refs/heads/main/shai-hulud-2.0/consolidated_iocs.csv"
	// WizIOCURL is the secondary IOC source from Wiz (uses npm version specification format)
	WizIOCURL = "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv"
	// DefaultIOCURL is kept for backward compatibility
	DefaultIOCURL = DataDogIOCURL
)

// WarningFunc is called when a non-fatal warning occurs during parsing
type WarningFunc func(message string)

// defaultWarningFunc is used when no warning function is provided
var defaultWarningFunc WarningFunc = func(message string) {
	// Default: silent, warnings are ignored
}

// currentWarningFunc holds the active warning callback
var currentWarningFunc = defaultWarningFunc

// SetWarningFunc sets the function to call when warnings occur
// Returns the previous warning function
func SetWarningFunc(fn WarningFunc) WarningFunc {
	prev := currentWarningFunc
	if fn == nil {
		currentWarningFunc = defaultWarningFunc
	} else {
		currentWarningFunc = fn
	}
	return prev
}

// warn calls the current warning function
func warn(format string, args ...interface{}) {
	currentWarningFunc(fmt.Sprintf(format, args...))
}

// VulnEntry represents a vulnerable package entry
type VulnEntry struct {
	PackageName     string
	PackageVersion  string // Single version (after splitting comma-separated list)
	OriginalVersion string // Original version string from CSV (may be comma-separated)
}

// VulnDB holds the vulnerability database as a lookup map
type VulnDB struct {
	// Key: "package_name@version" for exact matches
	entries map[string]*VulnEntry
	// Index by package name for listing
	byName map[string][]*VulnEntry
	// Total entries count (before dedup)
	totalEntries int
}

// NewVulnDB creates a new vulnerability database
func NewVulnDB() *VulnDB {
	return &VulnDB{
		entries: make(map[string]*VulnEntry),
		byName:  make(map[string][]*VulnEntry),
	}
}

// LoadFromURL fetches and parses a CSV vulnerability database from a URL
func LoadFromURL(url string) (*VulnDB, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch vulnerability database: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch vulnerability database: HTTP %d", resp.StatusCode)
	}

	return parseCSV(resp.Body)
}

// LoadFromFile loads and parses a CSV vulnerability database from a local file
func LoadFromFile(path string) (*VulnDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open vulnerability file: %w", err)
	}
	defer f.Close()

	return parseCSV(f)
}

// ParseCSVForTest is a test helper that parses CSV from a reader
// Exported for use in tests
func ParseCSVForTest(r io.Reader) (*VulnDB, error) {
	return parseCSV(r)
}

// parseCSV parses a CSV file looking for package_name and package_version columns
// Handles comma-separated version lists like "6.10.1, 6.8.2, 6.8.3"
// If column headers are not recognized, falls back to positional parsing (first=name, second=version)
func parseCSV(r io.Reader) (*VulnDB, error) {
	db := NewVulnDB()
	reader := csv.NewReader(r)

	// Read header
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV header: %w", err)
	}

	if len(header) < 2 {
		return nil, fmt.Errorf("CSV must have at least 2 columns (package name and version)")
	}

	// Find column indices by trying to match known column names
	nameIdx := -1
	versionIdx := -1
	for i, col := range header {
		colLower := strings.ToLower(strings.TrimSpace(col))
		// Support various column naming conventions:
		// - DataDog format: package_name, package_versions
		// - Wiz format: Package, Version
		// - Generic: name, version
		if colLower == "package_name" || colLower == "packagename" || colLower == "name" || colLower == "package" {
			nameIdx = i
		}
		if colLower == "package_versions" || colLower == "package_version" || colLower == "packageversion" || colLower == "version" || colLower == "versions" {
			versionIdx = i
		}
	}

	// Fall back to positional parsing if headers not recognized
	usedFallback := false
	if nameIdx == -1 {
		nameIdx = 0
		usedFallback = true
	}
	if versionIdx == -1 {
		versionIdx = 1
		usedFallback = true
	}

	// Read a few records to provide sample data for warning
	var allRecords [][]string
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Skip malformed lines
			continue
		}
		allRecords = append(allRecords, record)
	}

	// Issue warning with sample data if we used fallback
	if usedFallback && len(allRecords) > 0 {
		sampleCount := 3
		if len(allRecords) < sampleCount {
			sampleCount = len(allRecords)
		}

		var samples []string
		for i := 0; i < sampleCount; i++ {
			rec := allRecords[i]
			if len(rec) > 1 {
				samples = append(samples, fmt.Sprintf("  %s @ %s", rec[nameIdx], rec[versionIdx]))
			}
		}

		warn("CSV headers not recognized (found: %v). Assuming column 1 = package name, column 2 = version. Sample data:\n%s",
			header, strings.Join(samples, "\n"))
	}

	// Process all records
	for _, record := range allRecords {
		if nameIdx >= len(record) {
			continue
		}

		packageName := strings.TrimSpace(record[nameIdx])
		if packageName == "" {
			continue
		}

		// Get version field
		versionField := ""
		if versionIdx >= 0 && versionIdx < len(record) {
			versionField = strings.TrimSpace(record[versionIdx])
		}

		if versionField == "" {
			// Skip entries without version - we require both name AND version
			continue
		}

		// Handle comma-separated versions like "6.10.1, 6.8.2, 6.8.3, 6.9.1"
		versions := parseVersionList(versionField)

		for _, version := range versions {
			entry := &VulnEntry{
				PackageName:     packageName,
				PackageVersion:  version,
				OriginalVersion: versionField,
			}
			db.Add(entry)
		}
	}

	return db, nil
}

// parseVersionList splits a comma-separated version string into individual versions
// e.g., "6.10.1, 6.8.2, 6.8.3" -> ["6.10.1", "6.8.2", "6.8.3"]
func parseVersionList(versionField string) []string {
	// Check if this looks like an npm version specification (contains "= ")
	if strings.Contains(versionField, "= ") || strings.HasPrefix(versionField, "=") {
		return parseNpmVersionSpec(versionField)
	}

	var versions []string

	// Split by comma
	parts := strings.Split(versionField, ",")
	for _, part := range parts {
		version := strings.TrimSpace(part)
		if version != "" {
			versions = append(versions, version)
		}
	}

	// If no valid versions found, return the original as-is
	if len(versions) == 0 && versionField != "" {
		versions = append(versions, versionField)
	}

	return versions
}

// parseNpmVersionSpec parses npm version specification format used by Wiz IOC list
// e.g., "= 1.0.0 || = 2.0.0" -> ["1.0.0", "2.0.0"]
// e.g., "= 1.0.0" -> ["1.0.0"]
// This handles the exact version match format: = X.Y.Z
func parseNpmVersionSpec(versionSpec string) []string {
	var versions []string

	// Split by "||" (the OR operator in npm semver)
	parts := strings.Split(versionSpec, "||")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Remove the leading "=" or "= " prefix
		if strings.HasPrefix(part, "=") {
			part = strings.TrimPrefix(part, "=")
			part = strings.TrimSpace(part)
		}

		if part != "" {
			versions = append(versions, part)
		}
	}

	return versions
}

// Add adds a vulnerability entry to the database
func (db *VulnDB) Add(entry *VulnEntry) {
	db.totalEntries++

	// Create key with name@version
	key := entry.PackageName + "@" + entry.PackageVersion

	// Only add if not already present (dedup)
	if _, exists := db.entries[key]; !exists {
		db.entries[key] = entry
		db.byName[entry.PackageName] = append(db.byName[entry.PackageName], entry)
	}
}

// Check checks if a package name and version are vulnerable
// Returns the matching VulnEntry if found, nil otherwise
// BOTH package name AND version must match for a positive result
func (db *VulnDB) Check(name, version string) *VulnEntry {
	if name == "" || version == "" {
		return nil
	}

	// Look for exact match of name@version
	key := name + "@" + version
	if entry, ok := db.entries[key]; ok {
		return entry
	}

	return nil
}

// GetVulnerableVersions returns all known vulnerable versions for a package name
func (db *VulnDB) GetVulnerableVersions(name string) []string {
	entries, ok := db.byName[name]
	if !ok {
		return nil
	}

	versions := make([]string, 0, len(entries))
	for _, entry := range entries {
		versions = append(versions, entry.PackageVersion)
	}
	return versions
}

// Size returns the number of unique package@version entries in the database
func (db *VulnDB) Size() int {
	return len(db.entries)
}

// UniquePackages returns the number of unique package names
func (db *VulnDB) UniquePackages() int {
	return len(db.byName)
}

// TotalEntries returns the total number of entries processed (before dedup)
func (db *VulnDB) TotalEntries() int {
	return db.totalEntries
}

// Merge adds all entries from another VulnDB into this one
// Duplicates (same package@version) are automatically deduplicated
func (db *VulnDB) Merge(other *VulnDB) {
	if other == nil {
		return
	}

	for _, entry := range other.entries {
		db.Add(entry)
	}
}

// LoadFromMultipleURLs fetches and merges CSV vulnerability databases from multiple URLs
// Errors from individual URLs are collected but don't stop the overall process
// Returns an error only if ALL sources fail to load
func LoadFromMultipleURLs(urls []string) (*VulnDB, error) {
	if len(urls) == 0 {
		return nil, fmt.Errorf("no URLs provided")
	}

	db := NewVulnDB()
	var errors []string
	successCount := 0

	for _, url := range urls {
		sourceDB, err := LoadFromURL(url)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", url, err))
			continue
		}
		db.Merge(sourceDB)
		successCount++
	}

	if successCount == 0 {
		return nil, fmt.Errorf("failed to load any IOC sources: %s", strings.Join(errors, "; "))
	}

	return db, nil
}

// DefaultIOCURLs returns the list of default IOC sources (DataDog and Wiz)
func DefaultIOCURLs() []string {
	return []string{DataDogIOCURL, WizIOCURL}
}
