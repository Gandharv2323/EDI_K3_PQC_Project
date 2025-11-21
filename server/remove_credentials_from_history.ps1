# Security Remediation Script for Exposed Credentials (Windows PowerShell)
# Run this script to remove users.json from Git history and secure the repository

$ErrorActionPreference = "Stop"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Security Remediation: Remove users.json" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "⚠️  WARNING: This script will rewrite Git history!" -ForegroundColor Yellow
Write-Host "    - All collaborators must re-clone the repository" -ForegroundColor Yellow
Write-Host "    - Coordinate with your team before proceeding" -ForegroundColor Yellow
Write-Host "    - Backup your repository first" -ForegroundColor Yellow
Write-Host ""

$confirm = Read-Host "Have you coordinated with your team? (yes/no)"

if ($confirm -ne "yes") {
    Write-Host "Aborting. Please coordinate with your team first." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Step 1: Checking if git-filter-repo is installed..." -ForegroundColor Green

try {
    $filterRepoCheck = git filter-repo --version 2>&1
    Write-Host "✓ git-filter-repo is installed" -ForegroundColor Green
} catch {
    Write-Host "❌ git-filter-repo not found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Install it first:" -ForegroundColor Yellow
    Write-Host "  pip3 install git-filter-repo"
    Write-Host "  # or download from: https://github.com/newren/git-filter-repo"
    Write-Host ""
    exit 1
}

Write-Host ""
Write-Host "Step 2: Backing up current repository..." -ForegroundColor Green
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupDir = "..\SecureChatServer_backup_$timestamp"
Copy-Item -Path . -Destination $backupDir -Recurse -Force
Write-Host "✓ Backup created at: $backupDir" -ForegroundColor Green
Write-Host ""

Write-Host "Step 3: Removing users.json from Git history..." -ForegroundColor Green
git filter-repo --path server/users.json --invert-paths --force

Write-Host "✓ users.json removed from history" -ForegroundColor Green
Write-Host ""

Write-Host "Step 4: Cleaning up Git repository..." -ForegroundColor Green
git reflog expire --expire=now --all
git gc --prune=now --aggressive

Write-Host "✓ Repository cleaned" -ForegroundColor Green
Write-Host ""

Write-Host "Step 5: Verifying removal..." -ForegroundColor Green
$logCheck = git log --all --oneline -- server/users.json 2>&1

if ($logCheck) {
    Write-Host "❌ Warning: users.json still appears in history!" -ForegroundColor Red
    Write-Host "   Manual verification needed" -ForegroundColor Yellow
} else {
    Write-Host "✓ users.json successfully removed from all history" -ForegroundColor Green
}
Write-Host ""

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Force push to remote (⚠️  DESTRUCTIVE):" -ForegroundColor Yellow
Write-Host "   git push origin --force --all"
Write-Host "   git push origin --force --tags"
Write-Host ""
Write-Host "2. Notify ALL collaborators to:" -ForegroundColor Yellow
Write-Host "   a) Delete their local clone"
Write-Host "   b) Re-clone the repository: git clone <url>"
Write-Host "   c) Delete their local copy of users.json"
Write-Host ""
Write-Host "3. Rotate ALL exposed credentials:" -ForegroundColor Yellow
Write-Host "   - Force password reset for all users"
Write-Host "   - Update any API keys or secrets"
Write-Host ""
Write-Host "4. Audit access logs for the exposure period" -ForegroundColor Yellow
Write-Host ""
Write-Host "5. Create new users.json from template:" -ForegroundColor Yellow
Write-Host "   Copy-Item server\users.json.example server\users.json"
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "✅ Local history cleanup complete!" -ForegroundColor Green
Write-Host "   Review the output above and proceed with force push." -ForegroundColor Green
Write-Host ""
