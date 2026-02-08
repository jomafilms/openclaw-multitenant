#!/bin/bash
# Sync with upstream openclaw repository
# Usage: ./scripts/sync-upstream.sh [preview|merge|cherry-pick COMMIT]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$ROOT_DIR"

log() {
    echo "[sync] $1"
}

# Ensure we have the upstream remote
if ! git remote | grep -q upstream; then
    log "Adding upstream remote..."
    git remote add upstream https://github.com/openclaw/openclaw.git
fi

preview() {
    log "Fetching upstream..."
    git fetch upstream

    echo ""
    echo "=== Commits ahead of us ==="
    git log main..upstream/main --oneline | head -30

    echo ""
    echo "=== Changed files ==="
    git diff main..upstream/main --stat | tail -20

    echo ""
    echo "=== Key areas changed ==="
    echo ""
    echo "Security/Infra:"
    git diff main..upstream/main --stat -- src/infra/ | tail -5
    echo ""
    echo "Core CLI:"
    git diff main..upstream/main --stat -- src/cli/ | tail -5
    echo ""
    echo "Channels:"
    git diff main..upstream/main --stat -- src/channels/ src/telegram/ src/discord/ | tail -5
    echo ""

    COMMITS=$(git rev-list main..upstream/main | wc -l | tr -d ' ')
    log "Total commits behind upstream: $COMMITS"
    echo ""
    echo "To merge all: ./scripts/sync-upstream.sh merge"
    echo "To cherry-pick: ./scripts/sync-upstream.sh cherry-pick <commit>"
}

merge_upstream() {
    log "Fetching upstream..."
    git fetch upstream

    log "Creating sync branch..."
    BRANCH="upstream-sync-$(date +%Y%m%d-%H%M)"
    git checkout -b "$BRANCH"

    log "Merging upstream/main..."
    if git merge upstream/main --no-edit; then
        log "Merge successful!"
        echo ""
        echo "Next steps:"
        echo "  1. Review changes: git diff main"
        echo "  2. Test: npm test && npm run build"
        echo "  3. If OK: git checkout main && git merge $BRANCH"
        echo "  4. Push: git push origin main"
    else
        log "Merge conflicts detected. Resolve manually:"
        git status
    fi
}

cherry_pick() {
    COMMIT=$1
    if [ -z "$COMMIT" ]; then
        echo "Usage: $0 cherry-pick <commit-sha>"
        exit 1
    fi

    log "Fetching upstream..."
    git fetch upstream

    log "Cherry-picking $COMMIT..."
    if git cherry-pick "$COMMIT"; then
        log "Cherry-pick successful!"
        echo "Commit applied. Test and push when ready."
    else
        log "Cherry-pick has conflicts. Resolve manually."
        git status
    fi
}

show_help() {
    echo "OpenPaw Upstream Sync Script"
    echo ""
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  preview      Show what's new in upstream (default)"
    echo "  merge        Merge all upstream changes into a new branch"
    echo "  cherry-pick  Apply a specific commit"
    echo ""
    echo "Upstream: https://github.com/openclaw/openclaw"
    echo ""
    echo "Recommended workflow:"
    echo "  1. ./scripts/sync-upstream.sh preview"
    echo "  2. Review changes, decide what to sync"
    echo "  3. ./scripts/sync-upstream.sh merge  OR"
    echo "     ./scripts/sync-upstream.sh cherry-pick <commit>"
    echo "  4. Test locally"
    echo "  5. Push to origin"
}

case "${1:-preview}" in
    preview|status|check)
        preview
        ;;
    merge|sync)
        merge_upstream
        ;;
    cherry-pick|pick)
        cherry_pick "$2"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
