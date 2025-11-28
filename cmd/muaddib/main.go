package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/rslater/muaddib/internal/github"
	"github.com/rslater/muaddib/internal/reporter"
	"github.com/rslater/muaddib/internal/scanner"
	"github.com/rslater/muaddib/internal/vuln"
)

var (
	org       string
	user      string
	vulnCSV   string
	rateLimit float64
	skipDev   bool
	verbose   bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "muaddib",
		Short: "NPM vulnerability scanner for GitHub repositories",
		Long: `Muaddib scans GitHub organization or user repositories for vulnerable npm packages.

It fetches package.json and package-lock.json files from all repositories,
extracts all dependencies (including transitive), and checks them against
a vulnerability database (IOC list).

Environment Variables:
  GITHUB_TOKEN    Required. GitHub Personal Access Token for API access.

Example:
  export GITHUB_TOKEN=ghp_xxxxxxxxxxxx
  muaddib --org mycompany
  muaddib --user johndoe --vuln-csv ./my-iocs.csv`,
		RunE: run,
	}

	rootCmd.Flags().StringVar(&org, "org", "", "GitHub organization to scan")
	rootCmd.Flags().StringVar(&user, "user", "", "GitHub user to scan")
	rootCmd.Flags().StringVar(&vulnCSV, "vuln-csv", "", "Path or URL to vulnerability CSV (default: DataDog IOC list)")
	rootCmd.Flags().Float64Var(&rateLimit, "rate-limit", 1.0, "API requests per second (lower is safer)")
	rootCmd.Flags().BoolVar(&skipDev, "skip-dev", false, "Skip devDependencies")
	rootCmd.Flags().BoolVar(&verbose, "verbose", false, "Enable verbose output")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	rep := reporter.NewTerminalReporter(reporter.WithVerbose(verbose))
	rep.PrintBanner()

	// Validate flags
	if org == "" && user == "" {
		return fmt.Errorf("either --org or --user must be specified")
	}
	if org != "" && user != "" {
		return fmt.Errorf("--org and --user are mutually exclusive")
	}

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		rep.ReportInfo("\n⚠️  Interrupt received, shutting down gracefully...")
		cancel()
	}()

	// Load vulnerability database
	rep.ReportInfo("📥 Loading vulnerability database...")

	// Set up warning handler for CSV parsing
	vuln.SetWarningFunc(func(msg string) {
		rep.ReportWarning("⚠️  %s", msg)
	})

	var db *vuln.VulnDB
	var err error

	if vulnCSV != "" {
		// Custom source provided - load single source
		vulnSource := vulnCSV
		rep.ReportInfo("   Using custom source: %s", vulnSource)

		if strings.HasPrefix(vulnSource, "http://") || strings.HasPrefix(vulnSource, "https://") {
			db, err = vuln.LoadFromURL(vulnSource)
		} else {
			db, err = vuln.LoadFromFile(vulnSource)
		}
	} else {
		// No custom source - load both default sources (DataDog and Wiz)
		rep.ReportInfo("   Using default sources: DataDog + Wiz IOC lists")
		db, err = vuln.LoadFromMultipleURLs(vuln.DefaultIOCURLs())
	}

	if err != nil {
		return fmt.Errorf("failed to load vulnerability database: %w", err)
	}

	rep.ReportSuccess("Loaded %d IOC entries (%d unique packages, %d vulnerable versions)", db.TotalEntries(), db.UniquePackages(), db.Size())

	// Create GitHub client
	progressCb := func(msg string) {
		if verbose {
			rep.ReportProgress(msg)
		}
	}

	ghClient, err := github.NewClientFromEnv(
		github.WithRateLimit(rateLimit),
		github.WithProgressCallback(progressCb),
	)
	if err != nil {
		return err
	}

	rep.ReportInfo("🔗 Connected to GitHub API (rate limit: %.1f req/sec)", rateLimit)

	// List repositories
	var repos []*github.Repository
	if org != "" {
		rep.ReportInfo("📦 Fetching repositories for organization: %s", org)
		repos, err = ghClient.ListOrgRepos(ctx, org)
	} else {
		rep.ReportInfo("📦 Fetching repositories for user: %s", user)
		repos, err = ghClient.ListUserRepos(ctx, user)
	}

	if err != nil {
		return fmt.Errorf("failed to list repositories: %w", err)
	}

	if len(repos) == 0 {
		rep.ReportInfo("No repositories found")
		return nil
	}

	rep.ReportSuccess("Found %d repositories", len(repos))

	// Check for malicious migration repositories
	rep.ReportInfo("🔍 Checking for malicious migration repositories...")
	var orgResult scanner.OrgScanResult
	for _, repo := range repos {
		if github.IsMaliciousMigrationRepo(repo) {
			orgResult.MaliciousRepos = append(orgResult.MaliciousRepos, &scanner.MaliciousRepo{
				RepoName:    repo.FullName,
				Description: repo.Description,
			})
			rep.ReportMaliciousRepo(repo.FullName, repo.Description)
		}
	}
	if len(orgResult.MaliciousRepos) == 0 {
		rep.ReportSuccess("No malicious migration repositories found")
	}

	// Create scanner
	scan := scanner.NewScanner(db, !skipDev)

	// Scan each repository
	var results []*scanner.RepoScanResult
	for i, repo := range repos {
		// Check for cancellation
		select {
		case <-ctx.Done():
			rep.ReportInfo("Scan interrupted, showing partial results...")
			goto summary
		default:
		}

		// Skip archived repositories
		if repo.Archived {
			rep.ReportInfo("🔍 [%d/%d] Scanning %s...", i+1, len(repos), repo.FullName)
			rep.ReportProgress("   ⏭️  Skipping archived repository")
			continue
		}

		// Print repo header before scanning in verbose mode
		if verbose {
			rep.ReportRepoStart(repo.FullName)
		}
		rep.ReportInfo("🔍 [%d/%d] Scanning %s...", i+1, len(repos), repo.FullName)

		// Find package files
		files, err := ghClient.FindPackageFiles(ctx, repo)
		if err != nil {
			results = append(results, &scanner.RepoScanResult{
				RepoName: repo.FullName,
				Error:    err,
			})
			continue
		}

		// Find malicious workflows
		workflows, err := ghClient.FindMaliciousWorkflows(ctx, repo)
		if err != nil {
			// Log error but continue scanning
			if verbose {
				rep.ReportProgress(fmt.Sprintf("   ⚠️  Failed to check workflows: %v", err))
			}
		}

		// Find malicious branches
		if verbose {
			rep.ReportProgress(fmt.Sprintf("🌿 Checking %s for malicious branches...", repo.FullName))
		}
		maliciousBranches, err := ghClient.FindMaliciousBranches(ctx, repo)
		if err != nil {
			// Log error but continue scanning
			if verbose {
				rep.ReportProgress(fmt.Sprintf("   ⚠️  Failed to check branches: %v", err))
			}
		} else if verbose && len(maliciousBranches) == 0 {
			rep.ReportProgress("   ✓ No malicious branches found")
		}

		// Scan files
		result := scan.ScanFiles(files)

		// Check workflows for malicious patterns
		if len(workflows) > 0 {
			result.MaliciousWorkflows = scan.CheckWorkflows(workflows)
		}

		// Add malicious branches to result
		for _, branch := range maliciousBranches {
			result.MaliciousBranches = append(result.MaliciousBranches, &scanner.MaliciousBranch{
				RepoName:   branch.RepoName,
				BranchName: branch.Name,
			})
		}

		results = append(results, result)

		// Report per-repo if verbose or any issues found
		hasIssues := len(result.VulnerablePackages) > 0 ||
			len(result.MaliciousWorkflows) > 0 ||
			len(result.MaliciousScripts) > 0 ||
			len(result.MaliciousBranches) > 0
		if hasIssues && !verbose {
			// Print header only if not in verbose mode (verbose already printed it)
			rep.ReportRepoStart(repo.FullName)
		}
		if verbose || hasIssues {
			rep.ReportRepoResult(result)
		}
	}

summary:
	// Print summary
	rep.ReportSummary(results, &orgResult, db.Size())
	rep.ReportInfo("📊 Total API requests made: %d", ghClient.GetRequestsMade())

	// Exit with error code if vulnerabilities or malicious workflows found
	for _, result := range results {
		if len(result.VulnerablePackages) > 0 || len(result.MaliciousWorkflows) > 0 {
			return nil // Return nil but could return error to indicate vulns found
		}
	}

	return nil
}
