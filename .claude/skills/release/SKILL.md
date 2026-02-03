---
name: release
description: Release workflow for AgentMesh. Updates changelog, publishes SDK packages, updates documentation, deploys registry, and commits changes.
license: MIT
compatibility: Requires npm, railway CLI, git.
metadata:
  author: AgentMesh
  version: "1.0"
---

AgentMesh Release Workflow - Comprehensive release automation.

**Usage**: `/release [patch|minor|major]` or `/release` for auto-detection

**What This Does**:
1. Analyzes what changed since last release
2. Updates CHANGELOG.md with new entries
3. Bumps and publishes npm packages if needed
4. Updates /skill.md if SDK APIs changed
5. Updates /docs if needed
6. Deploys registry to Railway if backend changed
7. Updates README if needed
8. Commits and pushes all changes

---

## Workflow Steps

### Phase 1: Analyze Changes

1. **Get current state**
   ```bash
   git status
   git log --oneline -20
   git diff --name-only HEAD~10
   ```

2. **Identify changed components**

   Check each component directory for changes:
   - `registry/` → Backend API changes
   - `agentmesh-js/` → JavaScript SDK changes
   - `openclaw-skill/agentmesh/` → Python SDK changes
   - `registry/frontend/` → Landing page/docs changes
   - `relay/` → Relay server changes

3. **Determine version bump type**

   If not specified, analyze commits:
   - `fix:` commits → patch
   - `feat:` commits → minor
   - `BREAKING:` or `!:` → major
   - Default to patch if unclear

4. **Display analysis**
   ```
   ## Release Analysis

   **Components with changes:**
   - [x] Registry API (src/handlers.rs, src/main.rs)
   - [x] JavaScript SDK (src/identity.ts)
   - [ ] Python SDK (no changes)
   - [x] Documentation (frontend/src/pages/docs/)

   **Suggested version bump:** minor (new features detected)
   **Current versions:**
   - @agentmesh/sdk: 0.1.2
   - Registry: 0.2.0

   Proceed with release? [Yes/No]
   ```

### Phase 2: Update Changelog

1. **Read current changelog**
   ```bash
   Read CHANGELOG.md
   ```

2. **Generate new entries based on git commits**

   Parse commits since last release tag:
   ```bash
   git log $(git describe --tags --abbrev=0)..HEAD --oneline
   ```

3. **Categorize changes**
   - **Added**: New features (`feat:` commits)
   - **Changed**: Modifications (`refactor:`, `perf:` commits)
   - **Fixed**: Bug fixes (`fix:` commits)
   - **Removed**: Removed features
   - **Security**: Security fixes (`security:` commits)

4. **Update CHANGELOG.md**
   - Move [Unreleased] content to new version section
   - Add date: `## [X.Y.Z] - YYYY-MM-DD`
   - Organize by component (Registry, Python SDK, JS SDK, etc.)

5. **Show changelog diff for review**

### Phase 3: JavaScript SDK (@agentmesh/sdk)

**Only if `agentmesh-js/` has changes:**

1. **Check current version**
   ```bash
   cat agentmesh-js/package.json | grep version
   ```

2. **Bump version**
   ```bash
   cd agentmesh-js && npm version patch|minor|major --no-git-tag-version
   ```

3. **Build and test**
   ```bash
   cd agentmesh-js && npm run build && npm test
   ```

4. **Publish to npm** (requires confirmation)
   ```
   Ready to publish @agentmesh/sdk@X.Y.Z to npm.
   This is a PUBLIC release. Proceed? [Yes/No]
   ```

   If confirmed:
   ```bash
   cd agentmesh-js && npm publish --access public
   ```

### Phase 4: Python SDK (agentmesh)

**Only if `openclaw-skill/agentmesh/` has changes:**

1. **Update version in __init__.py**
   ```python
   __version__ = "X.Y.Z"
   ```

2. **Note**: Python SDK is not published to PyPI yet. Document version in changelog.

### Phase 5: Update /skill.md

**Check if SDK APIs changed:**

1. **Compare SDK exports/methods**
   - If `Identity`, `RegistryClient`, `RelayTransport` APIs changed
   - If new methods added or signatures changed

2. **Update SKILL_MD in handlers.rs**
   - Update code examples to match current API
   - Ensure both Python and JavaScript examples are accurate
   - Update version numbers in Resources section

3. **Verify locally**
   ```bash
   cargo check
   ```

### Phase 6: Update Documentation

**Check if docs need updating:**

1. **API changes** → Update `/docs/api-reference/*`
2. **New features** → Update `/docs/getting-started/*` or add to `/docs/guides/*`
3. **SDK changes** → Update `/docs/python-sdk/*` or `/docs/javascript-sdk/*`

Update files in `registry/frontend/src/pages/docs/` as needed.

### Phase 7: Deploy Registry

**Only if `registry/src/` or `registry/frontend/` changed:**

1. **Build and verify locally**
   ```bash
   cd registry && cargo build --release
   ```

2. **Deploy to Railway**
   ```bash
   cd registry && railway up --service registry
   ```

3. **Verify deployment**
   ```bash
   curl -s https://agentmesh.online/v1/health
   curl -s https://agentmesh.online/skill.md | head -20
   ```

4. **Wait for healthcheck**
   - Confirm `/v1/health` returns 200
   - Confirm landing page loads

### Phase 8: Update README

**Only if major features changed:**

1. **Check if README needs updates**
   - New installation instructions
   - New features to highlight
   - Updated badges/versions

2. **Update README.md at project root**

### Phase 9: Commit and Push

1. **Stage all changes**
   ```bash
   git add CHANGELOG.md README.md
   git add agentmesh-js/package.json agentmesh-js/package-lock.json
   git add openclaw-skill/agentmesh/__init__.py
   git add registry/src/handlers.rs
   git add registry/frontend/
   ```

2. **Create release commit**
   ```bash
   git commit -m "release: vX.Y.Z

   Components updated:
   - Registry: deployed to agentmesh.online
   - @agentmesh/sdk: vX.Y.Z published to npm
   - Python SDK: vX.Y.Z
   - Documentation: updated

   See CHANGELOG.md for details."
   ```

3. **Create git tag**
   ```bash
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   ```

4. **Push to remote**
   ```bash
   git push origin main --tags
   ```

---

## Output Format

### During Release
```
## AgentMesh Release Workflow

### Phase 1: Analyzing Changes
✓ Found changes in: registry, agentmesh-js, docs

### Phase 2: Updating Changelog
✓ Added 5 entries to CHANGELOG.md

### Phase 3: JavaScript SDK
✓ Bumped @agentmesh/sdk to 0.1.3
? Publish to npm? [Yes]
✓ Published @agentmesh/sdk@0.1.3

### Phase 4: Python SDK
✓ Updated version to 0.2.1

### Phase 5: Updating /skill.md
✓ No API changes detected - skill.md is current

### Phase 6: Documentation
✓ Updated 2 documentation pages

### Phase 7: Deploying Registry
✓ Deployed to Railway
✓ Healthcheck passed

### Phase 8: README
✓ No updates needed

### Phase 9: Commit and Push
✓ Created commit: release: v0.2.1
✓ Created tag: v0.2.1
✓ Pushed to origin/main
```

### On Completion
```
## Release Complete! 🎉

**Version:** 0.2.1
**Date:** 2026-02-03

### Published
- @agentmesh/sdk@0.1.3 → npm
- Registry → agentmesh.online
- Documentation → agentmesh.online/docs

### Links
- Changelog: CHANGELOG.md
- npm: https://www.npmjs.com/package/@agentmesh/sdk
- Registry: https://agentmesh.online
- GitHub: (commit link)
```

---

## Guardrails

- **Always ask before publishing to npm** - this is irreversible
- **Always ask before deploying to production** - affects live users
- **Verify healthchecks pass** before marking deploy complete
- **Don't skip changelog** - documentation is important
- **Test builds locally** before publishing
- **Use semantic versioning** correctly
- **Include all changed files** in commit
- **Create git tags** for releases

## Rollback

If something goes wrong:
1. **npm**: `npm unpublish @agentmesh/sdk@X.Y.Z` (within 72 hours)
2. **Railway**: Use Railway dashboard to rollback to previous deployment
3. **Git**: `git revert HEAD` and push

## Skip Options

Use flags to skip phases:
- `/release --skip-npm` - Don't publish to npm
- `/release --skip-deploy` - Don't deploy to Railway
- `/release --skip-docs` - Don't update documentation
- `/release --dry-run` - Analyze only, don't make changes
