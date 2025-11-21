#!/bin/bash

# Security Remediation Script for Exposed Credentials
# Run this script to remove users.json from Git history and secure the repository

set -e  # Exit on error

echo "============================================"
echo "Security Remediation: Remove users.json"
echo "============================================"
echo ""
echo "⚠️  WARNING: This script will rewrite Git history!"
echo "    - All collaborators must re-clone the repository"
echo "    - Coordinate with your team before proceeding"
echo "    - Backup your repository first"
echo ""
read -p "Have you coordinated with your team? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Aborting. Please coordinate with your team first."
    exit 1
fi

echo ""
echo "Step 1: Checking if git-filter-repo is installed..."
if ! command -v git-filter-repo &> /dev/null; then
    echo "❌ git-filter-repo not found!"
    echo ""
    echo "Install it first:"
    echo "  pip3 install git-filter-repo"
    echo "  # or"
    echo "  brew install git-filter-repo  # macOS"
    echo ""
    exit 1
fi

echo "✓ git-filter-repo is installed"
echo ""

echo "Step 2: Backing up current repository..."
BACKUP_DIR="../SecureChatServer_backup_$(date +%Y%m%d_%H%M%S)"
cp -r . "$BACKUP_DIR"
echo "✓ Backup created at: $BACKUP_DIR"
echo ""

echo "Step 3: Removing users.json from Git history..."
git filter-repo --path server/users.json --invert-paths --force

echo "✓ users.json removed from history"
echo ""

echo "Step 4: Cleaning up Git repository..."
git reflog expire --expire=now --all
git gc --prune=now --aggressive

echo "✓ Repository cleaned"
echo ""

echo "Step 5: Verifying removal..."
if git log --all --oneline -- server/users.json | grep -q .; then
    echo "❌ Warning: users.json still appears in history!"
    echo "   Manual verification needed"
else
    echo "✓ users.json successfully removed from all history"
fi
echo ""

echo "============================================"
echo "Next Steps:"
echo "============================================"
echo ""
echo "1. Force push to remote (⚠️  DESTRUCTIVE):"
echo "   git push origin --force --all"
echo "   git push origin --force --tags"
echo ""
echo "2. Notify ALL collaborators to:"
echo "   a) Delete their local clone"
echo "   b) Re-clone the repository: git clone <url>"
echo "   c) Delete their local copy of users.json"
echo ""
echo "3. Rotate ALL exposed credentials:"
echo "   - Force password reset for all users"
echo "   - Update any API keys or secrets"
echo ""
echo "4. Audit access logs for the exposure period"
echo ""
echo "5. Create new users.json from template:"
echo "   cp server/users.json.example server/users.json"
echo ""
echo "============================================"
echo ""
echo "✅ Local history cleanup complete!"
echo "   Review the output above and proceed with force push."
echo ""
