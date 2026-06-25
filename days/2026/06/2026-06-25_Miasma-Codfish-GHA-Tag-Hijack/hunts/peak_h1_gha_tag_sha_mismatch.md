# PEAK Hunt H1 — GitHub Actions Tag SHA Mismatch (Orphan Commit Detection)

**Hunt ID:** H1  
**Hypothesis:** At least one GitHub Actions workflow in the organization references a
third-party action by a floating version tag (`@v2`, `@v3`, etc.) where the commit SHA
currently resolved by that tag is NOT an ancestor of the action repository's default
branch. This would indicate a tag hijack (imposter commit / orphan commit) identical
to the Miasma codfish/semantic-release-action technique of 2026-06-24.

**PEAK phase:** Scoping  
**Data sources:** GitHub Actions workflow files (`.github/workflows/*.yml`), GitHub API
(tag resolution + commit ancestry check)  
**Skill level:** Intermediate  

## Procedure

### Step 1 — Enumerate floating tag references in your org

```bash
# List all workflow files with floating-tag uses: references (not pinned to SHA)
# Run from your org root or clone all repos
find . -path '*/.github/workflows/*.yml' -exec grep -Hn 'uses:.*@v[0-9]' {} \; \
  | grep -v '@[a-f0-9]\{40\}'   # exclude already-SHA-pinned refs
```

### Step 2 — Resolve current tag SHA via GitHub API

```bash
# For each action@tag found, resolve the current SHA
# Example: codfish/semantic-release-action@v4
gh api /repos/codfish/semantic-release-action/git/ref/tags/v4 --jq '.object.sha'

# General form:
resolve_tag_sha() {
    local repo=$1 tag=$2
    gh api "/repos/${repo}/git/ref/tags/${tag}" --jq '.object.sha' 2>/dev/null
}
```

### Step 3 — Check if resolved SHA is an ancestor of the default branch

```bash
# A legitimate tag should be reachable from main/master
# An orphan commit (tag hijack) will NOT be a git ancestor
check_ancestor() {
    local repo=$1 tag_sha=$2
    # Clone shallow to check ancestry
    git clone --depth 50 "https://github.com/${repo}" /tmp/check_repo 2>/dev/null
    cd /tmp/check_repo
    git fetch --tags --depth 50
    if git merge-base --is-ancestor "$tag_sha" HEAD 2>/dev/null; then
        echo "ANCESTOR: OK"
    else
        echo "ORPHAN: SUSPICIOUS — tag SHA not in main branch history"
    fi
    cd - && rm -rf /tmp/check_repo
}
```

### Step 4 — Alert on orphan commits

Any tag where the resolved SHA fails the ancestry check is a candidate for a tag hijack.
Prioritize floating major-version tags (`@v1`, `@v2`, `@v3`, ...) and actions used in
release workflows (which hold `GITHUB_TOKEN`, `NPM_TOKEN`, cloud credentials).

## Expected outcome

- **Clean environment:** All floating tags resolve to commits that are ancestors of
  the action's `main` or `master` branch.
- **Compromise indicator:** One or more tags resolve to an orphan SHA not in the
  branch history. Escalate immediately: identify which workflows ran after the tag
  was hijacked, review runner logs, rotate credentials in scope.

## Notes

- This hunt catches the attack AFTER the fact; the preventive control is SHA-pinning.
- Tool: [step-security/action-opsgenie-on-failure](https://app.stepsecurity.io/) and
  `step-security/harden-runner` can automate this check in CI.
- GitHub's Protected Tags feature prevents force-push on tag refs by non-admins; enable
  it for all tag patterns (`v*`) as a structural control.
