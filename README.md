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

- GitHub token patterns
- AWS access key patterns
- Private key headers
- JavaScript/TypeScript `eval()`
- JavaScript/TypeScript `innerHTML =`
- JavaScript/TypeScript shell execution

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
