package scanner

import (
	"testing"
)

func TestParsePackageJSON_Dependencies(t *testing.T) {
	content := `{
		"name": "test-project",
		"version": "1.0.0",
		"dependencies": {
			"test-muaddib-pkg-a": "1.0.0",
			"test-muaddib-pkg-b": "^2.0.0"
		}
	}`

	packages, err := ParsePackageJSON(content, false)
	if err != nil {
		t.Fatalf("ParsePackageJSON failed: %v", err)
	}

	if len(packages) != 2 {
		t.Errorf("expected 2 packages, got %d", len(packages))
	}

	// Check that versions are cleaned
	for _, pkg := range packages {
		if pkg.Name == "test-muaddib-pkg-b" && pkg.Version != "2.0.0" {
			t.Errorf("expected version 2.0.0 after cleaning ^, got %s", pkg.Version)
		}
	}
}

func TestParsePackageJSON_DevDependencies(t *testing.T) {
	content := `{
		"name": "test-project",
		"version": "1.0.0",
		"dependencies": {
			"test-muaddib-prod": "1.0.0"
		},
		"devDependencies": {
			"test-muaddib-dev": "2.0.0"
		}
	}`

	// Without dev dependencies
	packages, err := ParsePackageJSON(content, false)
	if err != nil {
		t.Fatalf("ParsePackageJSON failed: %v", err)
	}

	if len(packages) != 1 {
		t.Errorf("expected 1 package without dev deps, got %d", len(packages))
	}

	// With dev dependencies
	packages, err = ParsePackageJSON(content, true)
	if err != nil {
		t.Fatalf("ParsePackageJSON failed: %v", err)
	}

	if len(packages) != 2 {
		t.Errorf("expected 2 packages with dev deps, got %d", len(packages))
	}

	// Check that dev dependencies are marked correctly
	for _, pkg := range packages {
		if pkg.Name == "test-muaddib-dev" && !pkg.IsDev {
			t.Error("dev dependency should be marked as IsDev")
		}
		if pkg.Name == "test-muaddib-prod" && pkg.IsDev {
			t.Error("prod dependency should not be marked as IsDev")
		}
	}
}

func TestParsePackageJSON_OptionalAndPeerDependencies(t *testing.T) {
	content := `{
		"name": "test-project",
		"version": "1.0.0",
		"optionalDependencies": {
			"test-muaddib-optional": "1.0.0"
		},
		"peerDependencies": {
			"test-muaddib-peer": "2.0.0"
		}
	}`

	packages, err := ParsePackageJSON(content, false)
	if err != nil {
		t.Fatalf("ParsePackageJSON failed: %v", err)
	}

	if len(packages) != 2 {
		t.Errorf("expected 2 packages, got %d", len(packages))
	}
}

func TestParsePackageJSON_ScopedPackages(t *testing.T) {
	content := `{
		"name": "test-project",
		"version": "1.0.0",
		"dependencies": {
			"@test-muaddib/scoped-pkg": "1.0.0",
			"@test-muaddib/another-scoped": "^2.0.0"
		}
	}`

	packages, err := ParsePackageJSON(content, false)
	if err != nil {
		t.Fatalf("ParsePackageJSON failed: %v", err)
	}

	if len(packages) != 2 {
		t.Errorf("expected 2 packages, got %d", len(packages))
	}

	for _, pkg := range packages {
		if pkg.Name != "@test-muaddib/scoped-pkg" && pkg.Name != "@test-muaddib/another-scoped" {
			t.Errorf("unexpected package name: %s", pkg.Name)
		}
	}
}

func TestParsePackageJSON_InvalidJSON(t *testing.T) {
	content := `{ invalid json }`

	_, err := ParsePackageJSON(content, false)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParsePackageJSON_EmptyDependencies(t *testing.T) {
	content := `{
		"name": "test-project",
		"version": "1.0.0"
	}`

	packages, err := ParsePackageJSON(content, true)
	if err != nil {
		t.Fatalf("ParsePackageJSON failed: %v", err)
	}

	if len(packages) != 0 {
		t.Errorf("expected 0 packages, got %d", len(packages))
	}
}

func TestParsePackageLock_V2Format(t *testing.T) {
	content := `{
		"name": "test-project",
		"version": "1.0.0",
		"lockfileVersion": 2,
		"packages": {
			"": {
				"name": "test-project",
				"version": "1.0.0"
			},
			"node_modules/test-muaddib-pkg-a": {
				"version": "1.0.0",
				"resolved": "https://registry.npmjs.org/test-muaddib-pkg-a/-/test-muaddib-pkg-a-1.0.0.tgz"
			},
			"node_modules/test-muaddib-pkg-b": {
				"version": "2.0.0",
				"resolved": "https://registry.npmjs.org/test-muaddib-pkg-b/-/test-muaddib-pkg-b-2.0.0.tgz"
			}
		}
	}`

	packages, err := ParsePackageLock(content, false)
	if err != nil {
		t.Fatalf("ParsePackageLock failed: %v", err)
	}

	// Should have 2 packages (excluding root)
	if len(packages) != 2 {
		t.Errorf("expected 2 packages, got %d", len(packages))
	}

	// Check package extraction
	found := make(map[string]string)
	for _, pkg := range packages {
		found[pkg.Name] = pkg.Version
	}

	if found["test-muaddib-pkg-a"] != "1.0.0" {
		t.Errorf("expected test-muaddib-pkg-a@1.0.0, got %s", found["test-muaddib-pkg-a"])
	}
	if found["test-muaddib-pkg-b"] != "2.0.0" {
		t.Errorf("expected test-muaddib-pkg-b@2.0.0, got %s", found["test-muaddib-pkg-b"])
	}
}

func TestParsePackageLock_V3Format(t *testing.T) {
	content := `{
		"name": "test-project",
		"version": "1.0.0",
		"lockfileVersion": 3,
		"packages": {
			"": {
				"name": "test-project",
				"version": "1.0.0"
			},
			"node_modules/test-muaddib-pkg": {
				"version": "3.0.0"
			}
		}
	}`

	packages, err := ParsePackageLock(content, false)
	if err != nil {
		t.Fatalf("ParsePackageLock failed: %v", err)
	}

	if len(packages) != 1 {
		t.Errorf("expected 1 package, got %d", len(packages))
	}

	if packages[0].Version != "3.0.0" {
		t.Errorf("expected version 3.0.0, got %s", packages[0].Version)
	}
}

func TestParsePackageLock_ScopedPackages(t *testing.T) {
	content := `{
		"name": "test-project",
		"version": "1.0.0",
		"lockfileVersion": 2,
		"packages": {
			"node_modules/@test-muaddib/scoped": {
				"version": "1.0.0"
			}
		}
	}`

	packages, err := ParsePackageLock(content, false)
	if err != nil {
		t.Fatalf("ParsePackageLock failed: %v", err)
	}

	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}

	if packages[0].Name != "@test-muaddib/scoped" {
		t.Errorf("expected @test-muaddib/scoped, got %s", packages[0].Name)
	}
}

func TestParsePackageLock_NestedNodeModules(t *testing.T) {
	content := `{
		"name": "test-project",
		"version": "1.0.0",
		"lockfileVersion": 2,
		"packages": {
			"node_modules/test-muaddib-parent": {
				"version": "1.0.0"
			},
			"node_modules/test-muaddib-parent/node_modules/test-muaddib-child": {
				"version": "2.0.0"
			}
		}
	}`

	packages, err := ParsePackageLock(content, false)
	if err != nil {
		t.Fatalf("ParsePackageLock failed: %v", err)
	}

	if len(packages) != 2 {
		t.Errorf("expected 2 packages, got %d", len(packages))
	}

	// Find the nested package
	found := false
	for _, pkg := range packages {
		if pkg.Name == "test-muaddib-child" && pkg.Version == "2.0.0" {
			found = true
			break
		}
	}
	if !found {
		t.Error("nested package test-muaddib-child@2.0.0 not found")
	}
}

func TestParsePackageLock_DevDependencies(t *testing.T) {
	content := `{
		"name": "test-project",
		"version": "1.0.0",
		"lockfileVersion": 2,
		"packages": {
			"node_modules/test-muaddib-prod": {
				"version": "1.0.0"
			},
			"node_modules/test-muaddib-dev": {
				"version": "2.0.0",
				"dev": true
			}
		}
	}`

	// Without dev dependencies
	packages, err := ParsePackageLock(content, false)
	if err != nil {
		t.Fatalf("ParsePackageLock failed: %v", err)
	}

	if len(packages) != 1 {
		t.Errorf("expected 1 package without dev deps, got %d", len(packages))
	}

	// With dev dependencies
	packages, err = ParsePackageLock(content, true)
	if err != nil {
		t.Fatalf("ParsePackageLock failed: %v", err)
	}

	if len(packages) != 2 {
		t.Errorf("expected 2 packages with dev deps, got %d", len(packages))
	}
}

func TestParsePackageLock_V1Format(t *testing.T) {
	content := `{
		"name": "test-project",
		"version": "1.0.0",
		"lockfileVersion": 1,
		"dependencies": {
			"test-muaddib-pkg-a": {
				"version": "1.0.0",
				"resolved": "https://registry.npmjs.org/test-muaddib-pkg-a/-/test-muaddib-pkg-a-1.0.0.tgz"
			},
			"test-muaddib-pkg-b": {
				"version": "2.0.0",
				"requires": {
					"test-muaddib-pkg-c": "3.0.0"
				},
				"dependencies": {
					"test-muaddib-pkg-c": {
						"version": "3.0.0"
					}
				}
			}
		}
	}`

	packages, err := ParsePackageLock(content, false)
	if err != nil {
		t.Fatalf("ParsePackageLock failed: %v", err)
	}

	// Should have 3 packages (a, b, and nested c)
	if len(packages) != 3 {
		t.Errorf("expected 3 packages, got %d", len(packages))
	}

	found := make(map[string]string)
	for _, pkg := range packages {
		found[pkg.Name] = pkg.Version
	}

	if found["test-muaddib-pkg-a"] != "1.0.0" {
		t.Errorf("expected pkg-a@1.0.0")
	}
	if found["test-muaddib-pkg-b"] != "2.0.0" {
		t.Errorf("expected pkg-b@2.0.0")
	}
	if found["test-muaddib-pkg-c"] != "3.0.0" {
		t.Errorf("expected pkg-c@3.0.0")
	}
}

func TestParsePackageLock_InvalidJSON(t *testing.T) {
	content := `{ invalid json }`

	_, err := ParsePackageLock(content, false)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParsePackageLock_Deduplication(t *testing.T) {
	// Same package appearing in multiple places should be deduplicated
	content := `{
		"name": "test-project",
		"version": "1.0.0",
		"lockfileVersion": 2,
		"packages": {
			"node_modules/test-muaddib-pkg": {
				"version": "1.0.0"
			},
			"node_modules/other/node_modules/test-muaddib-pkg": {
				"version": "1.0.0"
			}
		}
	}`

	packages, err := ParsePackageLock(content, false)
	if err != nil {
		t.Fatalf("ParsePackageLock failed: %v", err)
	}

	// Should deduplicate same name@version
	if len(packages) != 1 {
		t.Errorf("expected 1 package after dedup, got %d", len(packages))
	}
}

func TestCleanVersion(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"1.0.0", "1.0.0"},
		{"^1.0.0", "1.0.0"},
		{"~1.0.0", "1.0.0"},
		{">=1.0.0", "1.0.0"},
		{">1.0.0", "1.0.0"},
		{"<=1.0.0", "1.0.0"},
		{"<1.0.0", "1.0.0"},
		{"=1.0.0", "1.0.0"},
		{"1.0.0 - 2.0.0", "1.0.0"},
		{" 1.0.0 ", "1.0.0"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := cleanVersion(tc.input)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestExtractPackageName(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"node_modules/lodash", "lodash"},
		{"node_modules/@types/node", "@types/node"},
		{"node_modules/foo/node_modules/bar", "bar"},
		{"node_modules/@scope/pkg/node_modules/nested", "nested"},
		{"node_modules/@scope/pkg/node_modules/@other/nested", "@other/nested"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := extractPackageName(tc.input)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}
