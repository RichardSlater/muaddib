package github

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-github/v67/github"
)

// Repository represents a GitHub repository
type Repository struct {
	Owner         string
	Name          string
	FullName      string
	Description   string
	Private       bool
	Archived      bool
	DefaultBranch string
}

// Branch represents a GitHub branch
type Branch struct {
	Name     string
	RepoName string
}

// MaliciousRepoDescription is the description used by repos created by the Shai-Hulud worm
const MaliciousRepoDescription = "Shai-Hulud Migration"

// MaliciousRepoSuffix is the suffix added to repo names by the Shai-Hulud worm
const MaliciousRepoSuffix = "-migration"

// MaliciousBranchName is the name of the branch created by the Shai-Hulud worm
const MaliciousBranchName = "shai-hulud"

// IsMaliciousMigrationRepo checks if a repository matches the Shai-Hulud migration pattern
func IsMaliciousMigrationRepo(repo *Repository) bool {
	return strings.HasSuffix(strings.ToLower(repo.Name), MaliciousRepoSuffix) &&
		repo.Description == MaliciousRepoDescription
}

// ListOrgRepos lists all repositories for an organization with pagination
func (c *Client) ListOrgRepos(ctx context.Context, org string) ([]*Repository, error) {
	var allRepos []*Repository

	opts := &github.RepositoryListByOrgOptions{
		Type: "all",
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}

	page := 1
	for {
		if err := c.wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limit wait: %w", err)
		}

		c.progress("📦 Fetching repositories for org '%s' (page %d)...", org, page)

		repos, resp, err := c.client.Repositories.ListByOrg(ctx, org, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to list org repos: %w", err)
		}
		c.handleRateLimit(resp)

		for _, repo := range repos {
			allRepos = append(allRepos, convertRepo(repo))
		}

		c.progress("📦 Fetched %d repositories so far...", len(allRepos))

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
		page++
	}

	return allRepos, nil
}

// ListUserRepos lists all repositories for a user with pagination
func (c *Client) ListUserRepos(ctx context.Context, user string) ([]*Repository, error) {
	var allRepos []*Repository

	opts := &github.RepositoryListByUserOptions{
		Type: "owner", // Only repos owned by the user, not org repos they have access to
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}

	page := 1
	for {
		if err := c.wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limit wait: %w", err)
		}

		c.progress("📦 Fetching repositories for user '%s' (page %d)...", user, page)

		repos, resp, err := c.client.Repositories.ListByUser(ctx, user, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to list user repos: %w", err)
		}
		c.handleRateLimit(resp)

		for _, repo := range repos {
			allRepos = append(allRepos, convertRepo(repo))
		}

		c.progress("📦 Fetched %d repositories so far...", len(allRepos))

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
		page++
	}

	return allRepos, nil
}

func convertRepo(repo *github.Repository) *Repository {
	r := &Repository{
		FullName: repo.GetFullName(),
		Name:     repo.GetName(),
		Private:  repo.GetPrivate(),
		Archived: repo.GetArchived(),
	}

	if repo.Owner != nil {
		r.Owner = repo.Owner.GetLogin()
	}

	if repo.Description != nil {
		r.Description = *repo.Description
	}

	if repo.DefaultBranch != nil {
		r.DefaultBranch = *repo.DefaultBranch
	} else {
		r.DefaultBranch = "main" // fallback
	}

	return r
}

// ListRepoBranches lists all branches for a repository
func (c *Client) ListRepoBranches(ctx context.Context, owner, repo string) ([]*Branch, error) {
	var allBranches []*Branch

	opts := &github.BranchListOptions{
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}

	for {
		if err := c.wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limit wait: %w", err)
		}

		branches, resp, err := c.client.Repositories.ListBranches(ctx, owner, repo, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to list branches: %w", err)
		}
		c.handleRateLimit(resp)

		for _, branch := range branches {
			allBranches = append(allBranches, &Branch{
				Name:     branch.GetName(),
				RepoName: owner + "/" + repo,
			})
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allBranches, nil
}

// FindMaliciousBranches finds branches matching the Shai-Hulud pattern in a repository
func (c *Client) FindMaliciousBranches(ctx context.Context, repo *Repository) ([]*Branch, error) {
	branches, err := c.ListRepoBranches(ctx, repo.Owner, repo.Name)
	if err != nil {
		return nil, err
	}

	var malicious []*Branch
	for _, branch := range branches {
		if strings.EqualFold(branch.Name, MaliciousBranchName) {
			malicious = append(malicious, branch)
		}
	}

	return malicious, nil
}
