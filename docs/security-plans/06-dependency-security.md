# Security Plan 06: Dependency Security & Supply Chain Hardening

## Overview

This plan addresses dependency auditing, lock file management, update policies, and supply chain attack mitigations for the OCMT monorepo.

## Current State

### Package Structure

- Main monorepo at root with `pnpm-lock.yaml`
- Multiple sub-projects with separate `package.json`:
  - `management-server/` - Express with argon2, bcrypt, jsonwebtoken, pg, axios
  - `agent-server/` - Express with dockerode, http-proxy
  - `relay-server/` - Express with pg, ws
  - `user-ui/` - Vite + Lit with DOMPurify, marked
  - `admin-ui/` - Express with fs-extra
  - Multiple extensions under `extensions/`

### Existing Security Infrastructure

- GitHub Dependabot configured for npm, GitHub Actions, Swift, Gradle
- `detect-secrets` for secret scanning in CI
- `pnpm.overrides` for pinning vulnerable packages
- `onlyBuiltDependencies` list for native module control
- SECURITY.md with disclosure policy

### High-Risk Dependencies

| Package            | Risk   | Notes                            |
| ------------------ | ------ | -------------------------------- |
| `argon2`, `bcrypt` | High   | Password hashing, native modules |
| `jsonwebtoken`     | High   | Auth tokens, history of CVEs     |
| `express`          | Medium | v4.x in sub-servers, v5 at root  |
| `pg`               | High   | Database access                  |
| `dockerode`        | High   | Docker API access                |
| `http-proxy`       | Medium | Reverse proxy                    |
| `sharp`            | Medium | Native image processing          |

---

## Implementation Plan

### Phase 1: Dependency Auditing Setup

#### 1.1 Add pnpm audit to CI

Add to `.github/workflows/ci.yml`:

```yaml
security-audit:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4

    - name: Setup pnpm
      uses: pnpm/action-setup@v2
      with:
        version: 9

    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: "22"
        cache: "pnpm"

    - name: Install dependencies
      run: pnpm install --frozen-lockfile

    - name: Run security audit
      run: pnpm audit --audit-level=high
      continue-on-error: false

    - name: Audit sub-packages
      run: |
        for dir in management-server agent-server relay-server user-ui admin-ui; do
          if [ -f "$dir/package.json" ]; then
            echo "Auditing $dir..."
            cd $dir
            npm audit --audit-level=high || true
            cd ..
          fi
        done
```

#### 1.2 Create audit configuration

Create `pnpm-audit.config.json`:

```json
{
  "auditLevel": "high",
  "ignoredAdvisories": [],
  "allowedSeverities": ["info", "low", "moderate"],
  "excludePackages": []
}
```

#### 1.3 Add npm scripts

Add to root `package.json`:

```json
{
  "scripts": {
    "audit": "pnpm audit --audit-level=high",
    "audit:fix": "pnpm audit --fix",
    "audit:report": "pnpm audit --json > audit-report.json"
  }
}
```

---

### Phase 2: Lock File Best Practices

#### 2.1 Verify lock file integrity in CI

Add to CI workflow:

```yaml
- name: Verify lock file integrity
  run: |
    # Check that lock file exists and is not empty
    if [ ! -s pnpm-lock.yaml ]; then
      echo "ERROR: pnpm-lock.yaml is missing or empty"
      exit 1
    fi

    # Verify lock file matches package.json
    pnpm install --frozen-lockfile

    # Check for uncommitted changes to lock file
    if ! git diff --quiet pnpm-lock.yaml; then
      echo "ERROR: pnpm-lock.yaml is out of sync with package.json"
      git diff pnpm-lock.yaml
      exit 1
    fi
```

#### 2.2 Lock file update procedures

Create `docs/DEPENDENCY_UPDATES.md`:

```markdown
# Dependency Update Procedures

## Adding a new dependency

1. Add to package.json: `pnpm add <package>`
2. Review the package on npm/GitHub
3. Check for known vulnerabilities: `pnpm audit`
4. Commit both package.json and pnpm-lock.yaml together
5. Create PR with rationale for new dependency

## Updating dependencies

1. Check for updates: `pnpm outdated`
2. Update specific package: `pnpm update <package>`
3. Run full test suite: `pnpm test`
4. Run security audit: `pnpm audit`
5. Commit lock file changes

## Emergency security patches

1. Check advisory details on GitHub Security Advisories
2. Update immediately if exploitable: `pnpm update <package>`
3. If no fix available, add to pnpm.overrides or remove
4. Create hotfix PR with security label
```

---

### Phase 3: Dependency Update Policy

#### 3.1 Enhance Dependabot configuration

Update `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "09:00"
      timezone: "UTC"
    open-pull-requests-limit: 10
    groups:
      # Auto-merge patch updates
      patch-updates:
        patterns:
          - "*"
        update-types:
          - "patch"
      # Group minor updates for review
      minor-updates:
        patterns:
          - "*"
        update-types:
          - "minor"
    ignore:
      # Packages we manually manage
      - dependency-name: "typescript"
        update-types: ["version-update:semver-major"]
    labels:
      - "dependencies"
      - "security"
    commit-message:
      prefix: "deps"
      include: "scope"

  # Sub-packages
  - package-ecosystem: "npm"
    directory: "/management-server"
    schedule:
      interval: "weekly"
    labels:
      - "dependencies"
      - "management-server"

  - package-ecosystem: "npm"
    directory: "/agent-server"
    schedule:
      interval: "weekly"
    labels:
      - "dependencies"
      - "agent-server"

  - package-ecosystem: "npm"
    directory: "/relay-server"
    schedule:
      interval: "weekly"
    labels:
      - "dependencies"
      - "relay-server"
```

#### 3.2 Auto-merge configuration

Create `.github/workflows/dependabot-auto-merge.yml`:

```yaml
name: Dependabot Auto-Merge

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: write
  pull-requests: write

jobs:
  auto-merge:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]'
    steps:
      - name: Dependabot metadata
        id: metadata
        uses: dependabot/fetch-metadata@v2
        with:
          github-token: "${{ secrets.GITHUB_TOKEN }}"

      - name: Auto-merge patch updates
        if: steps.metadata.outputs.update-type == 'version-update:semver-patch'
        run: gh pr merge --auto --squash "$PR_URL"
        env:
          PR_URL: ${{ github.event.pull_request.html_url }}
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Auto-merge minor updates (dev deps only)
        if: |
          steps.metadata.outputs.update-type == 'version-update:semver-minor' &&
          steps.metadata.outputs.dependency-type == 'direct:development'
        run: gh pr merge --auto --squash "$PR_URL"
        env:
          PR_URL: ${{ github.event.pull_request.html_url }}
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

### Phase 4: Supply Chain Attack Mitigations

#### 4.1 Enable npm provenance verification

Add to `.npmrc`:

```ini
# Require provenance for published packages
provenance=true

# Audit settings
audit=true
audit-level=high

# Registry security
//registry.npmjs.org/:_authToken=${NPM_TOKEN}
registry=https://registry.npmjs.org/

# Strict peer dependencies
strict-peer-dependencies=true
```

#### 4.2 Pin critical dependencies

Ensure `pnpm.overrides` in root `package.json` includes all security-critical packages:

```json
{
  "pnpm": {
    "overrides": {
      "fast-xml-parser": "4.5.1",
      "form-data": "4.0.1",
      "hono": "4.6.14",
      "qs": "6.13.0",
      "tar": "6.2.1",
      "tough-cookie": "5.0.0",
      "jsonwebtoken": ">=9.0.2",
      "axios": ">=1.7.4",
      "express": ">=4.21.0"
    },
    "onlyBuiltDependencies": ["argon2", "bcrypt", "sharp", "better-sqlite3", "libsql"]
  }
}
```

#### 4.3 Verify package signatures

Create `scripts/verify-deps.sh`:

```bash
#!/bin/bash
set -e

echo "Verifying dependency integrity..."

# Check for unexpected postinstall scripts
echo "Checking for postinstall scripts..."
pnpm list --depth=0 --json | jq -r '.dependencies | keys[]' | while read pkg; do
  scripts=$(npm view "$pkg" scripts.postinstall 2>/dev/null || echo "")
  if [ -n "$scripts" ]; then
    echo "WARNING: $pkg has postinstall script: $scripts"
  fi
done

# Verify checksums match lock file
echo "Verifying lock file checksums..."
pnpm install --frozen-lockfile --ignore-scripts

# Check for typosquatting
echo "Checking for typosquatting..."
SUSPICIOUS_PATTERNS="expresss|lodahs|reactt|axois|expresjs"
if pnpm list --depth=10 2>/dev/null | grep -iE "$SUSPICIOUS_PATTERNS"; then
  echo "ERROR: Potentially typosquatted packages detected!"
  exit 1
fi

echo "Dependency verification complete."
```

---

### Phase 5: Security Scanning Integration

#### 5.1 Add Socket.dev integration (optional)

Create `.github/workflows/socket-security.yml`:

```yaml
name: Socket Security

on:
  pull_request:
    paths:
      - "package.json"
      - "pnpm-lock.yaml"
      - "**/package.json"

jobs:
  socket:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: socketdev/socket-action@v1
        with:
          socket-api-key: ${{ secrets.SOCKET_API_KEY }}
```

#### 5.2 SARIF output for GitHub Security tab

Add to CI:

```yaml
- name: Run npm audit with SARIF output
  run: |
    pnpm audit --json > audit.json || true
    node scripts/audit-to-sarif.js audit.json > audit.sarif

- name: Upload SARIF to GitHub
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: audit.sarif
```

Create `scripts/audit-to-sarif.js`:

```javascript
#!/usr/bin/env node
const fs = require("fs");

const auditJson = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));

const sarif = {
  version: "2.1.0",
  $schema: "https://json.schemastore.org/sarif-2.1.0.json",
  runs: [
    {
      tool: {
        driver: {
          name: "pnpm-audit",
          version: "1.0.0",
          rules: [],
        },
      },
      results: [],
    },
  ],
};

if (auditJson.advisories) {
  for (const [id, advisory] of Object.entries(auditJson.advisories)) {
    sarif.runs[0].tool.driver.rules.push({
      id: `npm-advisory-${id}`,
      name: advisory.title,
      shortDescription: { text: advisory.title },
      fullDescription: { text: advisory.overview },
      helpUri: advisory.url,
      properties: {
        severity: advisory.severity,
      },
    });

    sarif.runs[0].results.push({
      ruleId: `npm-advisory-${id}`,
      level: advisory.severity === "critical" ? "error" : "warning",
      message: { text: `${advisory.module_name}: ${advisory.title}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: "package.json" },
          },
        },
      ],
    });
  }
}

console.log(JSON.stringify(sarif, null, 2));
```

---

### Phase 6: CVE Response Process

#### 6.1 Response timeline

| Severity | Response Time | Patch Time   |
| -------- | ------------- | ------------ |
| Critical | 4 hours       | 24 hours     |
| High     | 24 hours      | 72 hours     |
| Medium   | 1 week        | 2 weeks      |
| Low      | 1 month       | Next release |

#### 6.2 CVE response runbook

Create `docs/CVE_RESPONSE.md`:

```markdown
# CVE Response Runbook

## 1. Triage (within response time)

1. Verify the CVE affects our usage:
   - Check if vulnerable code path is reachable
   - Review advisory for exploitation requirements

2. Assess impact:
   - What data could be exposed?
   - What systems could be compromised?
   - Is there evidence of active exploitation?

## 2. Mitigation (if no patch available)

1. Check for workarounds in advisory
2. Consider disabling affected feature
3. Add WAF rules if applicable
4. Document temporary mitigations

## 3. Patching

1. Check for patched version: `npm view <package> versions`
2. Update package: `pnpm update <package>`
3. If patch breaks compatibility:
   - Fork and patch
   - Add to pnpm.overrides with fixed version
4. Run full test suite
5. Deploy to staging, verify fix
6. Deploy to production

## 4. Post-incident

1. Update CHANGELOG with security fix
2. Notify users if data exposure possible
3. Add regression test for vulnerability
4. Review similar packages for same issue
```

---

## Testing Approach

### Manual Testing

```bash
# Run full audit
pnpm audit

# Check specific package
npm audit --package-lock-only --json | jq '.advisories | to_entries[] | select(.value.module_name == "jsonwebtoken")'

# Verify lock file
pnpm install --frozen-lockfile

# Check for outdated packages
pnpm outdated
```

### CI Verification

1. All PRs must pass security audit
2. Lock file must be in sync
3. No critical/high vulnerabilities allowed
4. Dependabot PRs auto-tested

---

## Files to Modify

| File                       | Change                               |
| -------------------------- | ------------------------------------ |
| `.github/workflows/ci.yml` | Add security-audit job               |
| `.github/dependabot.yml`   | Enhance with groups and sub-packages |
| `package.json`             | Add audit scripts, update overrides  |
| `.npmrc`                   | Add security settings                |

## Files to Create

| File                                          | Purpose                     |
| --------------------------------------------- | --------------------------- |
| `.github/workflows/dependabot-auto-merge.yml` | Auto-merge patch updates    |
| `scripts/verify-deps.sh`                      | Verify dependency integrity |
| `scripts/audit-to-sarif.js`                   | Convert audit to SARIF      |
| `docs/DEPENDENCY_UPDATES.md`                  | Update procedures           |
| `docs/CVE_RESPONSE.md`                        | CVE response runbook        |

---

## Priority

**High** - Foundation for all other security work. Should be implemented first to catch vulnerabilities in other dependencies.

## Estimated Effort

- Phase 1-2: 2-3 hours
- Phase 3: 1-2 hours
- Phase 4-5: 3-4 hours
- Phase 6: 2 hours (documentation)

**Total: ~1 day**
