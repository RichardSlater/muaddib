package reporter

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/rslater/muaddib/internal/scanner"
)

// TerminalReporter outputs scan results to the terminal with colors and emoji
type TerminalReporter struct {
	out          io.Writer
	verbose      bool
	headerColor  *color.Color
	errorColor   *color.Color
	warnColor    *color.Color
	successColor *color.Color
	infoColor    *color.Color
	dimColor     *color.Color
}

// ReporterOption configures the TerminalReporter
type ReporterOption func(*TerminalReporter)

// WithOutput sets the output writer
func WithOutput(w io.Writer) ReporterOption {
	return func(r *TerminalReporter) {
		r.out = w
	}
}

// WithVerbose enables verbose output
func WithVerbose(v bool) ReporterOption {
	return func(r *TerminalReporter) {
		r.verbose = v
	}
}

// NewTerminalReporter creates a new terminal reporter
func NewTerminalReporter(opts ...ReporterOption) *TerminalReporter {
	r := &TerminalReporter{
		out:          os.Stdout,
		headerColor:  color.New(color.FgMagenta, color.Bold),
		errorColor:   color.New(color.FgRed, color.Bold),
		warnColor:    color.New(color.FgYellow),
		successColor: color.New(color.FgGreen),
		infoColor:    color.New(color.FgWhite),
		dimColor:     color.New(color.FgHiBlack),
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

// ReportProgress reports a progress message
func (r *TerminalReporter) ReportProgress(message string) {
	r.dimColor.Fprintf(r.out, "%s\n", message)
}

// ReportRepoStart reports the start of scanning a repository
func (r *TerminalReporter) ReportRepoStart(repoName string) {
	r.headerColor.Fprintf(r.out, "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	r.headerColor.Fprintf(r.out, "📁 Repository: %s\n", repoName)
	r.headerColor.Fprintf(r.out, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
}

// ReportRepoResult reports the results for a single repository
func (r *TerminalReporter) ReportRepoResult(result *scanner.RepoScanResult) {
	if result.Error != nil {
		r.errorColor.Fprintf(r.out, "❌ Error scanning repository: %v\n", result.Error)
		return
	}

	// If no files scanned and no malicious branches, nothing to report
	// (progress callback already reported "no package files found")
	if result.FilesScanned == 0 && len(result.MaliciousBranches) == 0 {
		return
	}

	if result.FilesScanned > 0 {
		r.infoColor.Fprintf(r.out, "📦 Scanned %d files, found %d unique packages\n",
			result.FilesScanned, result.TotalPackages)
	}

	if len(result.VulnerablePackages) == 0 && len(result.MaliciousWorkflows) == 0 &&
		len(result.MaliciousScripts) == 0 && len(result.MaliciousBranches) == 0 {
		r.successColor.Fprintf(r.out, "✅ No vulnerable packages or malicious patterns detected\n")
		return
	}

	vulnCount := len(result.VulnerablePackages) + len(result.MaliciousWorkflows) +
		len(result.MaliciousScripts) + len(result.MaliciousBranches)
	r.errorColor.Fprintf(r.out, "🔴 Found %d issue(s):\n\n", vulnCount)

	// Report malicious branches
	if len(result.MaliciousBranches) > 0 {
		r.errorColor.Fprintf(r.out, "  🌿 Malicious Branch Detected:\n")
		for _, mb := range result.MaliciousBranches {
			r.errorColor.Fprintf(r.out, "     🔴 Branch: %s\n", mb.BranchName)
		}
		fmt.Fprintln(r.out)
	}

	// Report malicious workflows
	if len(result.MaliciousWorkflows) > 0 {
		r.errorColor.Fprintf(r.out, "  🐛 Malicious Workflow Detected:\n")
		for _, mw := range result.MaliciousWorkflows {
			r.errorColor.Fprintf(r.out, "     🔴 %s\n", mw.FilePath)
			r.dimColor.Fprintf(r.out, "        Pattern: %s\n", mw.Pattern)
		}
		fmt.Fprintln(r.out)
	}

	// Report malicious scripts
	if len(result.MaliciousScripts) > 0 {
		r.errorColor.Fprintf(r.out, "  💉 Malicious Script Detected:\n")
		for _, ms := range result.MaliciousScripts {
			r.errorColor.Fprintf(r.out, "     🔴 %s\n", ms.FilePath)
			r.dimColor.Fprintf(r.out, "        Script: %s → %s\n", ms.ScriptName, ms.Command)
			r.dimColor.Fprintf(r.out, "        Pattern: %s\n", ms.Pattern)
		}
		fmt.Fprintln(r.out)
	}

	// Group by file
	byFile := make(map[string][]*scanner.VulnerablePackage)
	for _, vp := range result.VulnerablePackages {
		byFile[vp.FilePath] = append(byFile[vp.FilePath], vp)
	}

	for filePath, vulns := range byFile {
		r.warnColor.Fprintf(r.out, "  📄 %s:\n", filePath)
		for _, vp := range vulns {
			devMarker := ""
			if vp.Package.IsDev {
				devMarker = r.dimColor.Sprint(" (dev)")
			}
			sourceMarker := ""
			if vp.Package.Source == "transitive" {
				sourceMarker = r.dimColor.Sprint(" [transitive]")
			}

			r.errorColor.Fprintf(r.out, "     🔴 %s@%s%s%s\n",
				vp.Package.Name,
				vp.Package.Version,
				devMarker,
				sourceMarker)

			// Show IOC entry details if version differs
			if vp.VulnEntry.PackageVersion != "" && vp.VulnEntry.PackageVersion != vp.Package.Version {
				r.dimColor.Fprintf(r.out, "        ⚠️  IOC version: %s\n", vp.VulnEntry.PackageVersion)
			}
		}
		fmt.Fprintln(r.out)
	}
}

// ReportMaliciousRepo reports a detected malicious migration repository
func (r *TerminalReporter) ReportMaliciousRepo(repoName, description string) {
	r.errorColor.Fprintf(r.out, "🚨 MALICIOUS MIGRATION REPO DETECTED: %s\n", repoName)
	r.dimColor.Fprintf(r.out, "   Description: %s\n", description)
	r.dimColor.Fprintf(r.out, "   This repo was likely created by the Shai-Hulud worm and may contain exposed secrets!\n\n")
}

// ReportSummary reports the overall scan summary
func (r *TerminalReporter) ReportSummary(results []*scanner.RepoScanResult, orgResult *scanner.OrgScanResult, vulnDBSize int) {
	fmt.Fprintln(r.out)
	r.headerColor.Fprintf(r.out, "══════════════════════════════════════════════════════════════\n")
	r.headerColor.Fprintf(r.out, "                        SCAN SUMMARY\n")
	r.headerColor.Fprintf(r.out, "══════════════════════════════════════════════════════════════\n\n")

	totalRepos := len(results)
	totalPackages := 0
	totalVulnerable := 0
	totalMaliciousWorkflows := 0
	totalMaliciousScripts := 0
	totalMaliciousBranches := 0
	totalMaliciousRepos := 0
	reposWithVulns := 0
	errorCount := 0

	if orgResult != nil {
		totalMaliciousRepos = len(orgResult.MaliciousRepos)
	}

	for _, result := range results {
		if result.Error != nil {
			errorCount++
			continue
		}
		totalPackages += result.TotalPackages
		hasIssues := len(result.VulnerablePackages) > 0 ||
			len(result.MaliciousWorkflows) > 0 ||
			len(result.MaliciousScripts) > 0 ||
			len(result.MaliciousBranches) > 0
		if hasIssues {
			totalVulnerable += len(result.VulnerablePackages)
			totalMaliciousWorkflows += len(result.MaliciousWorkflows)
			totalMaliciousScripts += len(result.MaliciousScripts)
			totalMaliciousBranches += len(result.MaliciousBranches)
			reposWithVulns++
		}
	}

	r.infoColor.Fprintf(r.out, "📊 Repositories scanned:     %d\n", totalRepos)
	r.infoColor.Fprintf(r.out, "📦 Total packages checked:   %d\n", totalPackages)
	r.infoColor.Fprintf(r.out, "🔍 IOC database entries:     %d\n", vulnDBSize)
	fmt.Fprintln(r.out)

	hasAnyIssues := totalVulnerable > 0 || totalMaliciousWorkflows > 0 ||
		totalMaliciousScripts > 0 || totalMaliciousBranches > 0 || totalMaliciousRepos > 0

	if hasAnyIssues {
		if totalMaliciousRepos > 0 {
			r.errorColor.Fprintf(r.out, "🚨 Migration repos found:     %d (CRITICAL - secrets may be exposed!)\n", totalMaliciousRepos)
		}
		if totalMaliciousBranches > 0 {
			r.errorColor.Fprintf(r.out, "🌿 Malicious branches found:  %d\n", totalMaliciousBranches)
		}
		if totalVulnerable > 0 {
			r.errorColor.Fprintf(r.out, "🔴 Vulnerable packages found: %d\n", totalVulnerable)
		}
		if totalMaliciousWorkflows > 0 {
			r.errorColor.Fprintf(r.out, "🐛 Malicious workflows found: %d\n", totalMaliciousWorkflows)
		}
		if totalMaliciousScripts > 0 {
			r.errorColor.Fprintf(r.out, "💉 Malicious scripts found:   %d\n", totalMaliciousScripts)
		}
		r.errorColor.Fprintf(r.out, "⚠️  Affected repositories:    %d\n", reposWithVulns+totalMaliciousRepos)
	} else {
		r.successColor.Fprintf(r.out, "✅ No vulnerable packages or malicious patterns detected!\n")
	}

	if errorCount > 0 {
		r.warnColor.Fprintf(r.out, "⚠️  Repositories with errors: %d\n", errorCount)
	}

	fmt.Fprintln(r.out)

	// List malicious migration repos first (most critical)
	if totalMaliciousRepos > 0 {
		r.errorColor.Fprintf(r.out, "🚨 CRITICAL - Malicious migration repositories:\n")
		for _, repo := range orgResult.MaliciousRepos {
			r.errorColor.Fprintf(r.out, "  🚨 %s\n", repo.RepoName)
		}
		fmt.Fprintln(r.out)
	}

	// List affected repositories
	if reposWithVulns > 0 {
		r.warnColor.Fprintf(r.out, "Affected repositories:\n")
		for _, result := range results {
			hasIssues := len(result.VulnerablePackages) > 0 ||
				len(result.MaliciousWorkflows) > 0 ||
				len(result.MaliciousScripts) > 0 ||
				len(result.MaliciousBranches) > 0
			if hasIssues {
				parts := []string{}
				if len(result.MaliciousBranches) > 0 {
					parts = append(parts, fmt.Sprintf("%d malicious branch", len(result.MaliciousBranches)))
				}
				if len(result.VulnerablePackages) > 0 {
					parts = append(parts, fmt.Sprintf("%d vulnerable", len(result.VulnerablePackages)))
				}
				if len(result.MaliciousWorkflows) > 0 {
					parts = append(parts, fmt.Sprintf("%d malicious workflow", len(result.MaliciousWorkflows)))
				}
				if len(result.MaliciousScripts) > 0 {
					parts = append(parts, fmt.Sprintf("%d malicious script", len(result.MaliciousScripts)))
				}
				r.errorColor.Fprintf(r.out, "  🔴 %s (%s)\n",
					result.RepoName, strings.Join(parts, ", "))
			}
		}
		fmt.Fprintln(r.out)
	}

	r.headerColor.Fprintf(r.out, "══════════════════════════════════════════════════════════════\n")
}

// ReportError reports an error
func (r *TerminalReporter) ReportError(format string, args ...interface{}) {
	r.errorColor.Fprintf(r.out, "❌ "+format+"\n", args...)
}

// ReportWarning reports a warning message
func (r *TerminalReporter) ReportWarning(format string, args ...interface{}) {
	r.warnColor.Fprintf(r.out, format+"\n", args...)
}

// ReportInfo reports an informational message
func (r *TerminalReporter) ReportInfo(format string, args ...interface{}) {
	r.infoColor.Fprintf(r.out, format+"\n", args...)
}

// ReportSuccess reports a success message
func (r *TerminalReporter) ReportSuccess(format string, args ...interface{}) {
	r.successColor.Fprintf(r.out, "✅ "+format+"\n", args...)
}

// PrintBanner prints the application banner
func (r *TerminalReporter) PrintBanner() {
	banner := `
  __  __                 _  _     _  _  _
 |  \/  | _  _   __ _  __| |( ) __| |(_)| |__
 | |\/| || || | / _` + "`" + ` |/ _` + "`" + ` ||/ / _` + "`" + ` || || '_ \
 | |  | || _,_|| (_| || (_| |  | (_| || || |_) |
 |_|  |_| \__,_|\__,_| \__,_|   \__,_||_||_.__/

   Shai-Hulud NPM Worm Scanner for GitHub
`
	r.headerColor.Fprintln(r.out, banner)
	fmt.Fprintln(r.out, strings.Repeat("─", 60))
}
