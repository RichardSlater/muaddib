# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Muaddib, please report it by sending an email to the maintainers rather than opening a public issue.

When reporting a vulnerability, please include:

1. A description of the vulnerability
2. Steps to reproduce the issue
3. Potential impact of the vulnerability
4. Any suggested fixes (if applicable)

We will acknowledge receipt of your report within 48 hours and provide a more detailed response within 7 days, including our assessment and expected timeline for a fix.

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| Latest  | :white_check_mark: |

## Security Best Practices

When using Muaddib:

1. **Protect your GitHub Token**: Never commit your `GITHUB_TOKEN` to version control. Use environment variables or secure secret management.

2. **Minimal Permissions**: Use a GitHub token with the minimum required permissions (`Contents: Read` and `Metadata: Read`).

3. **Keep Updated**: Always use the latest version to ensure you have the most up-to-date IOC database and security fixes.
