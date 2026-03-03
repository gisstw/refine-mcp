---
name: github-publish
description: Publish a Rust project to GitHub. Use when the user asks to create a GitHub repo, push code to GitHub, or publish/release an open source project. Covers gh CLI setup, repo creation, remote configuration, topic/description settings, and first push.
---

# GitHub Publish (Rust Projects)

## Prerequisites

```bash
# Install gh CLI (Ubuntu/Debian)
sudo apt install gh

# Authenticate
gh auth login
# Choose: GitHub.com → HTTPS → Login with browser (or token)
```

Verify: `gh auth status` should show "Logged in to github.com".

## Workflow

### 1. Create repo and push

```bash
cd /path/to/project

# Create public repo from current directory (uses Cargo.toml name)
REPO_NAME=$(grep '^name' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
DESCRIPTION=$(grep '^description' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')

gh repo create "$REPO_NAME" \
  --public \
  --description "$DESCRIPTION" \
  --source . \
  --remote origin \
  --push
```

This creates the repo, sets `origin`, and pushes the current branch in one command.

### 2. Configure repo settings

```bash
# Add topics (from Cargo.toml keywords)
gh repo edit --add-topic mcp --add-topic code-review --add-topic security --add-topic tree-sitter --add-topic red-team --add-topic rust

# Set homepage (optional)
gh repo edit --homepage "https://crates.io/crates/$REPO_NAME"

# Enable discussions (optional)
gh repo edit --enable-discussions
```

### 3. Create first release (optional)

```bash
VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
gh release create "v$VERSION" \
  --title "v$VERSION" \
  --notes "Initial release" \
  --latest
```

### 4. Verify

```bash
gh repo view --web  # Opens in browser
```

## Notes

- `--source .` uses the current directory as source, auto-detects git
- If remote `origin` already exists, remove first: `git remote remove origin`
- For private repos, replace `--public` with `--private`
- Cargo.toml should have `repository` field pointing to the new repo URL — update after creation
