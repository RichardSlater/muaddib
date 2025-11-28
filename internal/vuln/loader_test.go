package vuln

import (
	"strings"
	"testing"
)

// Test package names that are clearly fake and won't match real packages
const (
	testPkgVulnerable1  = "test-muaddib-vulnerable-pkg-1"
	testPkgVulnerable2  = "test-muaddib-vulnerable-pkg-2"
	testPkgSafe         = "test-muaddib-safe-pkg"
	testPkgScoped       = "@test-muaddib/vulnerable-scoped"
	testPkgMultiVersion = "test-muaddib-multi-version"
)

func TestParseCSV_BasicFunctionality(t *testing.T) {
	csv := `package_name,package_versions,sources
test-muaddib-vulnerable-pkg-1,1.0.0,"test"
test-muaddib-vulnerable-pkg-2,2.0.0,"test"`

	db, err := parseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("parseCSV failed: %v", err)
	}

	if db.Size() != 2 {
		t.Errorf("expected 2 entries, got %d", db.Size())
	}

	if db.UniquePackages() != 2 {
		t.Errorf("expected 2 unique packages, got %d", db.UniquePackages())
	}
}

func TestParseCSV_CommaSeparatedVersions(t *testing.T) {
	csv := `package_name,package_versions,sources
test-muaddib-multi-version,"1.0.0, 1.0.1, 1.0.2","test"`

	db, err := parseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("parseCSV failed: %v", err)
	}

	// Should expand into 3 separate entries
	if db.Size() != 3 {
		t.Errorf("expected 3 entries after splitting versions, got %d", db.Size())
	}

	// But only 1 unique package
	if db.UniquePackages() != 1 {
		t.Errorf("expected 1 unique package, got %d", db.UniquePackages())
	}

	// All versions should be detectable
	versions := []string{"1.0.0", "1.0.1", "1.0.2"}
	for _, v := range versions {
		if db.Check(testPkgMultiVersion, v) == nil {
			t.Errorf("expected version %s to be vulnerable", v)
		}
	}
}

func TestParseCSV_ScopedPackages(t *testing.T) {
	csv := `package_name,package_versions,sources
@test-muaddib/vulnerable-scoped,1.0.0,"test"`

	db, err := parseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("parseCSV failed: %v", err)
	}

	if db.Check(testPkgScoped, "1.0.0") == nil {
		t.Error("expected scoped package to be detected as vulnerable")
	}
}

func TestParseCSV_SkipsEntriesWithoutVersion(t *testing.T) {
	csv := `package_name,package_versions,sources
test-muaddib-vulnerable-pkg-1,,"test"
test-muaddib-vulnerable-pkg-2,2.0.0,"test"`

	db, err := parseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("parseCSV failed: %v", err)
	}

	// Only the entry with a version should be loaded
	if db.Size() != 1 {
		t.Errorf("expected 1 entry (skipping empty version), got %d", db.Size())
	}
}

func TestParseCSV_FallbackToPositionalColumns(t *testing.T) {
	// When headers are not recognized, should fall back to positional parsing
	// Column 1 = package name, Column 2 = version
	csv := `wrong_column,also_wrong,sources
test-muaddib-fallback-pkg,1.0.0,"test"`

	// Capture warnings
	var warnings []string
	oldWarnFunc := SetWarningFunc(func(msg string) {
		warnings = append(warnings, msg)
	})
	defer SetWarningFunc(oldWarnFunc)

	db, err := parseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("parseCSV should not fail with unrecognized headers: %v", err)
	}

	// Should have parsed using fallback
	if db.Size() != 1 {
		t.Errorf("expected 1 entry from fallback parsing, got %d", db.Size())
	}

	// Should have issued a warning
	if len(warnings) == 0 {
		t.Error("expected a warning about unrecognized headers")
	}

	// Check that the package was parsed correctly
	if db.Check("test-muaddib-fallback-pkg", "1.0.0") == nil {
		t.Error("expected fallback package to be detected")
	}
}

func TestParseCSV_PartialFallback(t *testing.T) {
	// When only one header is recognized, should use recognized + fallback for other
	csv := `package_name,wrong_version_col,sources
test-muaddib-partial-pkg,2.0.0,"test"`

	// Capture warnings
	var warnings []string
	oldWarnFunc := SetWarningFunc(func(msg string) {
		warnings = append(warnings, msg)
	})
	defer SetWarningFunc(oldWarnFunc)

	db, err := parseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("parseCSV should not fail with partial header match: %v", err)
	}

	// Should have parsed the package_name correctly
	if db.Size() != 1 {
		t.Errorf("expected 1 entry, got %d", db.Size())
	}

	// Should have issued a warning about the version column
	if len(warnings) == 0 {
		t.Error("expected a warning about unrecognized version column")
	}

	// Check that the package was parsed correctly using fallback for version (column 1)
	if db.Check("test-muaddib-partial-pkg", "2.0.0") == nil {
		t.Error("expected package to be detected with version from fallback column")
	}
}

func TestParseCSV_TooFewColumns(t *testing.T) {
	// CSV with only one column should fail
	csv := `single_column
test-pkg`

	_, err := parseCSV(strings.NewReader(csv))
	if err == nil {
		t.Error("expected error for CSV with less than 2 columns")
	}
}

func TestParseCSV_AlternativeColumnNames(t *testing.T) {
	testCases := []struct {
		name   string
		header string
		data   string // data row
	}{
		{"package_name and package_versions", "package_name,package_versions,sources", "test-muaddib-vulnerable-pkg-1,1.0.0,test"},
		{"name and versions", "name,versions,sources", "test-muaddib-vulnerable-pkg-1,1.0.0,test"},
		{"packagename and packageversion", "packagename,packageversion,sources", "test-muaddib-vulnerable-pkg-1,1.0.0,test"},
		{"name and version", "name,version,sources", "test-muaddib-vulnerable-pkg-1,1.0.0,test"},
		{"Package and Version (Wiz format)", "Package,Version", "test-muaddib-vulnerable-pkg-1,= 1.0.0"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			csv := tc.header + "\n" + tc.data
			db, err := parseCSV(strings.NewReader(csv))
			if err != nil {
				t.Fatalf("parseCSV failed for header %q: %v", tc.header, err)
			}
			if db.Size() != 1 {
				t.Errorf("expected 1 entry, got %d", db.Size())
			}
		})
	}
}

func TestCheck_RequiresBothNameAndVersion(t *testing.T) {
	csv := `package_name,package_versions,sources
test-muaddib-vulnerable-pkg-1,1.0.0,"test"`

	db, err := parseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("parseCSV failed: %v", err)
	}

	// Exact match should work
	if db.Check(testPkgVulnerable1, "1.0.0") == nil {
		t.Error("expected exact match to detect vulnerability")
	}

	// Wrong version should NOT match
	if db.Check(testPkgVulnerable1, "2.0.0") != nil {
		t.Error("wrong version should not match")
	}

	// Wrong name should NOT match
	if db.Check(testPkgSafe, "1.0.0") != nil {
		t.Error("wrong package name should not match")
	}

	// Empty name should NOT match
	if db.Check("", "1.0.0") != nil {
		t.Error("empty name should not match")
	}

	// Empty version should NOT match
	if db.Check(testPkgVulnerable1, "") != nil {
		t.Error("empty version should not match")
	}
}

func TestCheck_ExactVersionMatch(t *testing.T) {
	csv := `package_name,package_versions,sources
test-muaddib-vulnerable-pkg-1,1.0.0,"test"`

	db, err := parseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("parseCSV failed: %v", err)
	}

	testCases := []struct {
		version    string
		shouldFind bool
	}{
		{"1.0.0", true},    // exact match
		{"1.0.1", false},   // different patch
		{"1.0", false},     // missing patch
		{"1.0.0.0", false}, // extra component
		{"v1.0.0", false},  // v prefix
		{" 1.0.0", false},  // leading space
		{"1.0.0 ", false},  // trailing space
	}

	for _, tc := range testCases {
		t.Run(tc.version, func(t *testing.T) {
			result := db.Check(testPkgVulnerable1, tc.version)
			if tc.shouldFind && result == nil {
				t.Errorf("version %q should have been found", tc.version)
			}
			if !tc.shouldFind && result != nil {
				t.Errorf("version %q should NOT have been found", tc.version)
			}
		})
	}
}

func TestGetVulnerableVersions(t *testing.T) {
	csv := `package_name,package_versions,sources
test-muaddib-multi-version,"1.0.0, 2.0.0, 3.0.0","test"`

	db, err := parseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("parseCSV failed: %v", err)
	}

	versions := db.GetVulnerableVersions(testPkgMultiVersion)
	if len(versions) != 3 {
		t.Errorf("expected 3 vulnerable versions, got %d", len(versions))
	}

	// Non-existent package should return nil
	versions = db.GetVulnerableVersions(testPkgSafe)
	if versions != nil {
		t.Error("expected nil for non-existent package")
	}
}

func TestParseVersionList(t *testing.T) {
	testCases := []struct {
		input    string
		expected []string
	}{
		{"1.0.0", []string{"1.0.0"}},
		{"1.0.0, 1.0.1", []string{"1.0.0", "1.0.1"}},
		{"1.0.0, 1.0.1, 1.0.2", []string{"1.0.0", "1.0.1", "1.0.2"}},
		{"1.0.0,1.0.1", []string{"1.0.0", "1.0.1"}},     // no spaces
		{" 1.0.0 , 1.0.1 ", []string{"1.0.0", "1.0.1"}}, // extra spaces
		{"1.0.0, , 1.0.1", []string{"1.0.0", "1.0.1"}},  // empty middle
		{"", []string{}}, // empty string
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := parseVersionList(tc.input)
			if len(result) != len(tc.expected) {
				t.Errorf("expected %d versions, got %d: %v", len(tc.expected), len(result), result)
				return
			}
			for i, v := range result {
				if v != tc.expected[i] {
					t.Errorf("version[%d]: expected %q, got %q", i, tc.expected[i], v)
				}
			}
		})
	}
}

func TestVulnDB_Deduplication(t *testing.T) {
	csv := `package_name,package_versions,sources
test-muaddib-vulnerable-pkg-1,1.0.0,"test"
test-muaddib-vulnerable-pkg-1,1.0.0,"test2"`

	db, err := parseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("parseCSV failed: %v", err)
	}

	// Should deduplicate same package@version
	if db.Size() != 1 {
		t.Errorf("expected 1 entry after dedup, got %d", db.Size())
	}

	// But TotalEntries should count both
	if db.TotalEntries() != 2 {
		t.Errorf("expected 2 total entries, got %d", db.TotalEntries())
	}
}

func TestVulnEntry_OriginalVersion(t *testing.T) {
	csv := `package_name,package_versions,sources
test-muaddib-multi-version,"1.0.0, 1.0.1, 1.0.2","test"`

	db, err := parseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("parseCSV failed: %v", err)
	}

	entry := db.Check(testPkgMultiVersion, "1.0.1")
	if entry == nil {
		t.Fatal("expected to find entry")
	}

	// OriginalVersion should contain the full comma-separated list
	if entry.OriginalVersion != "1.0.0, 1.0.1, 1.0.2" {
		t.Errorf("expected original version %q, got %q", "1.0.0, 1.0.1, 1.0.2", entry.OriginalVersion)
	}

	// PackageVersion should be the individual version
	if entry.PackageVersion != "1.0.1" {
		t.Errorf("expected package version %q, got %q", "1.0.1", entry.PackageVersion)
	}
}

func TestParseNpmVersionSpec(t *testing.T) {
	testCases := []struct {
		input    string
		expected []string
	}{
		// Single version
		{"= 1.0.0", []string{"1.0.0"}},
		{"=1.0.0", []string{"1.0.0"}},
		// Multiple versions with ||
		{"= 1.0.0 || = 2.0.0", []string{"1.0.0", "2.0.0"}},
		{"= 1.0.0 || = 2.0.0 || = 3.0.0", []string{"1.0.0", "2.0.0", "3.0.0"}},
		// Variations in spacing
		{"=1.0.0||=2.0.0", []string{"1.0.0", "2.0.0"}},
		{"= 1.0.0||= 2.0.0", []string{"1.0.0", "2.0.0"}},
		// Extra spaces
		{"  = 1.0.0  ||  = 2.0.0  ", []string{"1.0.0", "2.0.0"}},
		// Empty string
		{"", []string{}},
		// Only equals sign
		{"=", []string{}},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := parseNpmVersionSpec(tc.input)
			if len(result) != len(tc.expected) {
				t.Errorf("expected %d versions, got %d: %v", len(tc.expected), len(result), result)
				return
			}
			for i, v := range result {
				if v != tc.expected[i] {
					t.Errorf("version[%d]: expected %q, got %q", i, tc.expected[i], v)
				}
			}
		})
	}
}

func TestParseCSV_WizFormat(t *testing.T) {
	// Test CSV in Wiz format (Package,Version with npm spec format)
	csv := `Package,Version
test-muaddib-wiz-pkg-1,= 1.0.0
test-muaddib-wiz-pkg-2,= 1.0.0 || = 2.0.0
@test-muaddib/wiz-scoped,= 3.0.0`

	db, err := parseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("parseCSV failed: %v", err)
	}

	// Should have 4 entries total (1 + 2 + 1)
	if db.Size() != 4 {
		t.Errorf("expected 4 entries, got %d", db.Size())
	}

	// Verify specific entries
	if db.Check("test-muaddib-wiz-pkg-1", "1.0.0") == nil {
		t.Error("expected test-muaddib-wiz-pkg-1@1.0.0 to be vulnerable")
	}

	if db.Check("test-muaddib-wiz-pkg-2", "1.0.0") == nil {
		t.Error("expected test-muaddib-wiz-pkg-2@1.0.0 to be vulnerable")
	}

	if db.Check("test-muaddib-wiz-pkg-2", "2.0.0") == nil {
		t.Error("expected test-muaddib-wiz-pkg-2@2.0.0 to be vulnerable")
	}

	if db.Check("@test-muaddib/wiz-scoped", "3.0.0") == nil {
		t.Error("expected @test-muaddib/wiz-scoped@3.0.0 to be vulnerable")
	}
}

func TestVulnDB_Merge(t *testing.T) {
	csv1 := `package_name,package_versions,sources
test-muaddib-merge-pkg-1,1.0.0,"datadog"
test-muaddib-merge-pkg-2,2.0.0,"datadog"`

	csv2 := `Package,Version
test-muaddib-merge-pkg-3,= 3.0.0
test-muaddib-merge-pkg-1,= 1.0.0`

	db1, err := parseCSV(strings.NewReader(csv1))
	if err != nil {
		t.Fatalf("parseCSV for db1 failed: %v", err)
	}

	db2, err := parseCSV(strings.NewReader(csv2))
	if err != nil {
		t.Fatalf("parseCSV for db2 failed: %v", err)
	}

	// Merge db2 into db1
	db1.Merge(db2)

	// Should have 3 unique entries (pkg-1 is duplicated)
	if db1.Size() != 3 {
		t.Errorf("expected 3 unique entries after merge, got %d", db1.Size())
	}

	// Should have 3 unique packages
	if db1.UniquePackages() != 3 {
		t.Errorf("expected 3 unique packages, got %d", db1.UniquePackages())
	}

	// Verify all packages are present
	if db1.Check("test-muaddib-merge-pkg-1", "1.0.0") == nil {
		t.Error("expected merge-pkg-1@1.0.0 to be present")
	}
	if db1.Check("test-muaddib-merge-pkg-2", "2.0.0") == nil {
		t.Error("expected merge-pkg-2@2.0.0 to be present")
	}
	if db1.Check("test-muaddib-merge-pkg-3", "3.0.0") == nil {
		t.Error("expected merge-pkg-3@3.0.0 to be present")
	}
}

func TestVulnDB_MergeNil(t *testing.T) {
	csv := `package_name,package_versions,sources
test-muaddib-merge-nil,1.0.0,"test"`

	db, err := parseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("parseCSV failed: %v", err)
	}

	sizeBefore := db.Size()

	// Merging nil should be safe
	db.Merge(nil)

	if db.Size() != sizeBefore {
		t.Errorf("size changed after merging nil: was %d, now %d", sizeBefore, db.Size())
	}
}

func TestDefaultIOCURLs(t *testing.T) {
	urls := DefaultIOCURLs()

	if len(urls) != 2 {
		t.Errorf("expected 2 default URLs, got %d", len(urls))
	}

	// Check that both URLs are present
	hasDataDog := false
	hasWiz := false
	for _, url := range urls {
		if url == DataDogIOCURL {
			hasDataDog = true
		}
		if url == WizIOCURL {
			hasWiz = true
		}
	}

	if !hasDataDog {
		t.Error("DataDog IOC URL not found in default URLs")
	}
	if !hasWiz {
		t.Error("Wiz IOC URL not found in default URLs")
	}
}
