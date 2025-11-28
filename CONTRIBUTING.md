# Contributing to Muaddib

First off, thank you for considering contributing to Muaddib! It's people like you that make Muaddib such a great tool.

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When you create a bug report, please include as many details as possible:

- **Use a clear and descriptive title** for the issue
- **Describe the exact steps to reproduce the problem**
- **Provide specific examples** to demonstrate the steps
- **Describe the behavior you observed** and explain why it's problematic
- **Explain the behavior you expected** to see instead
- **Include your environment details** (OS, Go version, etc.)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear and descriptive title**
- **Provide a step-by-step description** of the suggested enhancement
- **Explain why this enhancement would be useful** to most users
- **List any alternatives you've considered**

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Follow the coding style** used in the project
3. **Add tests** for any new functionality
4. **Ensure all tests pass** by running `go test ./...`
5. **Update documentation** as needed
6. **Write a clear commit message** describing your changes

## Development Setup

1. Clone your fork:

   ```bash
   git clone https://github.com/YOUR_USERNAME/muaddib.git
   cd muaddib
   ```

2. Install dependencies:

   ```bash
   go mod download
   ```

3. Set up pre-commit hooks:

   ```bash
   # Install pre-commit (if not already installed)
   pip install pre-commit
   # or: brew install pre-commit

   # Install the git hooks
   pre-commit install
   ```

4. Run tests:

   ```bash
   go test ./...
   ```

5. Build the project:

   ```bash
   go build -o muaddib ./cmd/muaddib/
   ```

## Pre-commit Hooks

This project uses [pre-commit](https://pre-commit.com/) to ensure code quality before commits. The hooks will automatically:

- Fix trailing whitespace and ensure files end with a newline
- Run `go fmt` to format code
- Run `go vet` for static analysis
- Run `go imports` to organize imports
- Run all unit tests

If any check fails, the commit will be blocked until you fix the issues.

## Coding Guidelines

### Go Style

- Follow the [Effective Go](https://golang.org/doc/effective_go) guidelines
- Run `go fmt` before committing
- Run `go vet` to catch common issues
- Use meaningful variable and function names
- Add comments for exported functions and types

### Testing

- Write tests for new functionality
- Use table-driven tests where appropriate
- Use descriptive test names that explain what's being tested
- Use test package names with fake data (e.g., `test-muaddib-*`) to avoid false positives

### Commits

- Use clear, concise commit messages
- Reference issues in commits when applicable (e.g., "Fixes #123")
- Keep commits focused on a single change

## Project Structure

```text
muaddib/
├── cmd/muaddib/          # Main application entry point
├── internal/
│   ├── github/           # GitHub API client
│   ├── reporter/         # Terminal output formatting
│   ├── scanner/          # Package file parsing and matching
│   └── vuln/             # Vulnerability database handling
├── .github/workflows/    # CI/CD configuration
└── README.md
```

## Questions?

Feel free to open an issue with your question, or reach out to the maintainers directly.

Thank you for contributing! 🙏
