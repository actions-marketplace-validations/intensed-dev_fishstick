# Fishstick
[![CI](https://github.com/intensed-dev/fishstick/actions/workflows/ci.yml/badge.svg)](https://github.com/intensed-dev/fishstick/actions/workflows/ci.yml)

A lightweight tool for finding security vulnerabilities and bugs in code repositories.

## Status

Fishstick is currently an early MVP.

## Install

```bash
npm install
npm run build
```

Then:

```bash
node dist/cli.js scan .
```

For a machine-readable result:

```bash
node dist/cli.js scan . --json
```

Fail CI when a finding reaches a severity:

```bash
node dist/cli.js scan . --fail-on high
```

## Current checks

### Secrets
- GitHub, AWS, Slack and npm token patterns
- Private keys
- JWTs
- Database connection strings with credentials
- Generic API keys and access tokens
- Hardcoded passwords

### JavaScript / TypeScript
- `eval()` and `new Function()`
- `innerHTML`, `insertAdjacentHTML()` and `document.write()`
- `dangerouslySetInnerHTML`
- Shell execution and `shell: true`
- Potential SQL injection
- Disabled TLS verification
- Prototype pollution
- Dynamic timer code
- Potential open redirects
- Plain HTTP URLs
- Insecure randomness
- Client-side cookie assignment

### Python
- `eval()` and `exec()`
- Unsafe pickle deserialization
- Unsafe YAML loading
- Shell execution and `shell=True`
- Disabled TLS verification
- Potential SQL injection
- Security-sensitive assertions
- Insecure temporary files

Findings are reported as GitHub Actions warnings by default. The action does not fail just because vulnerabilities were found. Use `fail-on` explicitly when you want security findings to fail a workflow.

## GitHub Action

Use Fishstick directly from a workflow:

```yaml
- uses: intensed-dev/fishstick@main
  with:
    fail-on: high
```

## Roadmap

- AST-based JavaScript/TypeScript analysis
- Dependency vulnerability checks
- Git history secret scanning
- Pull request annotations
- More language rules
- Configurable rules
