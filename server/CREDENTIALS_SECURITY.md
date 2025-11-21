# User Credentials Security

## ⚠️ IMPORTANT SECURITY NOTICE

This directory previously contained a `users.json` file with real password hashes that was accidentally committed to version control. **This file has been removed from tracking and added to `.gitignore`.**

## Setup Instructions

### For Development/Testing

1. Copy the template file:
   ```bash
   cp server/users.json.example server/users.json
   ```

2. The server will automatically create an `admin/admin` user if `users.json` is not found or is empty.

3. Register new users through the application's signup feature - passwords will be automatically hashed using PBKDF2-HMAC-SHA256.

### For Production

**DO NOT** commit real user credentials to the repository. Instead:

1. **Use environment-specific configuration:**
   - Keep production `users.json` on the server only
   - Use proper file permissions (0600 on Unix: `chmod 600 server/users.json`)
   - Ensure the file is owned by the application user

2. **Or migrate to a proper database:**
   - PostgreSQL, MySQL, MongoDB, etc.
   - Use environment variables for connection strings
   - Enable database-level encryption at rest

3. **Implement secrets management:**
   - Use AWS Secrets Manager, Azure Key Vault, or HashiCorp Vault
   - Store database credentials and encryption keys securely
   - Rotate credentials regularly

## Password Hash Format

The application uses PBKDF2-HMAC-SHA256 with the following format:
```
pbkdf2:sha256:<iterations>$<salt>$<hash>
```

- **Iterations**: 600,000 (meets NIST recommendations)
- **Salt**: 32-byte random hex string
- **Hash**: 64-byte hex string derived from password + salt

## Security Best Practices

### ✅ DO:
- Keep `server/users.json` in `.gitignore`
- Use strong, unique passwords
- Rotate credentials if they were exposed
- Use HTTPS in production
- Enable rate limiting for authentication
- Implement account lockout after failed attempts
- Log authentication events securely

### ❌ DON'T:
- Commit `users.json` to version control
- Share credentials via chat, email, or tickets
- Use the same password across accounts
- Store plaintext passwords anywhere
- Expose password hashes publicly

## Credential Rotation (If Compromised)

If you believe credentials were exposed:

1. **Immediate Actions:**
   ```bash
   # Remove from working directory
   rm server/users.json
   
   # Copy fresh template
   cp server/users.json.example server/users.json
   ```

2. **Purge from Git history** (coordinate with team before force-pushing):
   ```bash
   # Using git-filter-repo (recommended)
   git filter-repo --path server/users.json --invert-paths
   
   # Or using BFG Repo-Cleaner
   bfg --delete-files users.json
   git reflog expire --expire=now --all
   git gc --prune=now --aggressive
   
   # Force push (WARNING: requires team coordination)
   git push origin --force --all
   ```

3. **Notify all users** to change their passwords immediately

4. **Audit logs** for unauthorized access during the exposure period

## Template File

The `users.json.example` file contains only placeholder data:
- Username: `example_user`
- Password hash: Non-functional example format

**This is safe to commit** as it contains no real credentials.

## Questions?

If you have security concerns or questions about credential management:
1. Check the main project README
2. Review the authentication implementation in `server/ClientHandler.cpp`
3. Consult your security team or senior developers

---

**Last Updated**: 2025-11-14
**Security Level**: Production-ready with proper setup
