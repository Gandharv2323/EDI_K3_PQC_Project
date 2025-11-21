/**
 * Utility to hash passwords in users.json
 * Run this once to migrate from plaintext to hashed passwords
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// PBKDF2 parameters matching C++ implementation
const ITERATIONS = 600000;
const SALT_LENGTH = 16;
const HASH_LENGTH = 32;

function generateSalt() {
    return crypto.randomBytes(SALT_LENGTH).toString('hex');
}

function hashPassword(password, salt = null) {
    const actualSalt = salt || generateSalt();
    const hash = crypto.pbkdf2Sync(
        password,
        Buffer.from(actualSalt, 'hex'),
        ITERATIONS,
        HASH_LENGTH,
        'sha256'
    );
    
    return `pbkdf2:sha256:${ITERATIONS}$${actualSalt}$${hash.toString('hex')}`;
}

function migrateUsersFile(filePath) {
    console.log('Reading users.json from:', filePath);
    
    // Read and parse users file with error handling
    let data;
    let usersData;
    
    try {
        data = fs.readFileSync(filePath, 'utf8');
    } catch (readError) {
        console.error('\n❌ FATAL ERROR: Failed to read users.json');
        console.error('Error details:', readError.message);
        console.error('\n🔧 TROUBLESHOOTING:');
        console.error(`   1. Verify file exists: ${filePath}`);
        console.error('   2. Check file permissions (must be readable)');
        console.error('   3. Ensure file is not locked by another process');
        process.exit(1);
    }
    
    try {
        usersData = JSON.parse(data);
    } catch (parseError) {
        console.error('\n❌ FATAL ERROR: Failed to parse users.json (invalid JSON)');
        console.error('Error details:', parseError.message);
        console.error('\n🔧 TROUBLESHOOTING:');
        console.error(`   1. Validate JSON syntax: https://jsonlint.com/`);
        console.error('   2. Check for trailing commas, missing brackets, or quotes');
        console.error('   3. Restore from backup if available');
        process.exit(1);
    }
    
    // Validate users array exists
    if (!usersData.users || !Array.isArray(usersData.users)) {
        console.error('\n❌ FATAL ERROR: Invalid users.json structure');
        console.error('Expected format: { "users": [...] }');
        console.error(`Actual: usersData.users is ${usersData.users ? typeof usersData.users : 'undefined'}`);
        console.error('\n🔧 TROUBLESHOOTING:');
        console.error('   1. Ensure top-level "users" key exists');
        console.error('   2. Ensure "users" value is an array');
        console.error('   3. Example: { "users": [{"username": "alice", "password": "..."}] }');
        process.exit(1);
    }
    
    console.log(`Found ${usersData.users.length} users`);
    
    // Create backup with restrictive permissions (AFTER successful parse/validation)
    const backupPath = filePath + '.backup';
    const backupTempPath = backupPath + '.tmp';
    
    try {
        // Write backup to temp file with restrictive permissions
        fs.writeFileSync(backupTempPath, data, { mode: 0o600 });
        
        // Atomic rename to final backup location
        fs.renameSync(backupTempPath, backupPath);
    } catch (backupError) {
        console.error('\n❌ FATAL ERROR: Failed to create backup file');
        console.error('Error details:', backupError.message);
        
        // Clean up temp file if it exists
        try {
            if (fs.existsSync(backupTempPath)) {
                fs.unlinkSync(backupTempPath);
            }
        } catch (cleanupError) {
            console.error('⚠️  Warning: Failed to clean up temp backup:', cleanupError.message);
        }
        
        console.error('\n⚠️  Migration aborted: Cannot proceed without backup');
        process.exit(1);
    }
    
    // Set restrictive permissions on backup (owner read/write only)
    if (process.platform !== 'win32') {
        // Unix-like systems: FAIL if we cannot set restrictive permissions
        try {
            fs.chmodSync(backupPath, 0o600);
            console.log('✓ Backup created with restrictive permissions (0600):', backupPath);
        } catch (chmodError) {
            console.error('\n❌ FATAL ERROR: Cannot set restrictive permissions on backup file');
            console.error('Error details:', chmodError.message);
            console.error('\n🔧 SECURITY RISK:');
            console.error('   Backup file contains PLAINTEXT PASSWORDS and is currently world-readable!');
            console.error('\n🔧 REMEDIATION:');
            console.error(`   1. Manually set permissions: chmod 600 "${backupPath}"`);
            console.error(`   2. Or delete the backup: rm "${backupPath}"`);
            console.error(`   3. Then re-run this migration script`);
            console.error('\n⚠️  Migration aborted to prevent security exposure');
            
            // Clean up the insecure backup file
            try {
                fs.unlinkSync(backupPath);
                console.error('✓ Removed insecure backup file');
            } catch (unlinkError) {
                console.error(`⚠️  Warning: Failed to remove insecure backup at "${backupPath}":`);
                console.error('   ', unlinkError.message);
                console.error('   MANUAL ACTION REQUIRED: Delete this file immediately!');
            }
            
            process.exit(1);
        }
    } else {
        // Windows: Cannot set Unix permissions, warn user about security risk
        console.log('✓ Backup created:', backupPath);
        console.error('\n⚠️  ⚠️  ⚠️  CRITICAL SECURITY WARNING (Windows) ⚠️  ⚠️  ⚠️');
        console.error('Windows does not support Unix-style permissions (chmod 600).');
        console.error('The backup file may be readable by other users on this system!');
        console.error('\n🔒 REQUIRED ACTIONS:');
        console.error('   1. Move backup to a secure, encrypted location immediately');
        console.error('   2. Restrict NTFS permissions to your user account only:');
        console.error(`      Right-click "${backupPath}" → Properties → Security`);
        console.error('      Remove all users except yourself (Full Control)');
        console.error('   3. Or delete the backup after verifying migration succeeded');
        console.error('\n📋 BACKUP CONTAINS: Plaintext passwords for all users');
        console.error('   - NEVER commit this file to version control');
        console.error('   - Delete after migration verification\n');
        
        // Require explicit confirmation to proceed
        const forceFlag = process.argv.includes('--force');
        if (!forceFlag) {
            console.error('❌ MIGRATION ABORTED');
            console.error('   To proceed despite this security risk, re-run with: --force');
            console.error('   Example: node hash_passwords.cjs --force');
            console.error('\n⚠️  Only use --force if you understand the security implications');
            
            // Clean up backup on abort
            try {
                fs.unlinkSync(backupPath);
                console.error('✓ Removed backup file (migration aborted)');
            } catch (unlinkError) {
                console.error(`⚠️  Warning: Failed to remove backup at "${backupPath}"`);
                console.error('   MANUAL ACTION REQUIRED: Delete this file!');
            }
            
            process.exit(1);
        }
        
        console.log('\n⚠️  --force flag detected: Proceeding with migration');
        console.log('   Remember to secure the backup file manually!\n');
    }
    
    console.log('⚠️  IMPORTANT: Backup file contains plaintext passwords!');
    console.log('   - Keep this file secure and never commit to version control');
    console.log('   - Delete after verifying migration succeeded\n');
    
    // Hash passwords
    let hashedCount = 0;
    let alreadyHashedCount = 0;
    let malformedCount = 0;
    
    usersData.users = usersData.users.map(user => {
        // Validate user object has password field
        if (!user.password || typeof user.password !== 'string') {
            const username = user.username || '<unknown>';
            console.error(`  ✗ ${username}: malformed user object (password missing or not a string)`);
            malformedCount++;
            return user;  // Return unchanged to preserve data
        }
        
        // Check if already hashed
        if (user.password.startsWith('pbkdf2:')) {
            console.log(`  - ${user.username}: already hashed (skipping)`);
            alreadyHashedCount++;
            return user;
        }
        
        // Capture original length before hashing (non-sensitive info)
        const originalLength = user.password.length;
        const hashedPassword = hashPassword(user.password);
        console.log(`  - ${user.username}: hashed (${originalLength} chars → ${hashedPassword.length} chars)`);
        hashedCount++;
        
        return {
            ...user,
            password: hashedPassword
        };
    });
    
    // Write updated file using atomic write pattern
    const tempFilePath = filePath + '.tmp';
    
    try {
        // Step 1: Write to temporary file
        fs.writeFileSync(tempFilePath, JSON.stringify(usersData, null, 2), { mode: 0o600 });
        
        // Step 2: Atomic rename (overwrites target)
        fs.renameSync(tempFilePath, filePath);
        
        console.log(`\n✓ Updated users.json:`);
        console.log(`  - ${hashedCount} passwords hashed`);
        console.log(`  - ${alreadyHashedCount} already hashed`);
        if (malformedCount > 0) {
            console.log(`  - ${malformedCount} malformed users (skipped)`);
        }
        console.log(`  - Total: ${usersData.users.length} users`);
    } catch (error) {
        console.error('\n❌ FATAL ERROR: Failed to write users.json');
        console.error('Error details:', error.message);
        
        // Clean up temporary file if it exists
        try {
            if (fs.existsSync(tempFilePath)) {
                fs.unlinkSync(tempFilePath);
                console.error('✓ Cleaned up temporary file:', tempFilePath);
            }
        } catch (cleanupError) {
            console.error('⚠️  Warning: Failed to clean up temp file:', cleanupError.message);
        }
        
        // Point user to backup for recovery
        console.error('\n🔧 RECOVERY INSTRUCTIONS:');
        console.error(`   1. Original file preserved at: ${backupPath}`);
        console.error(`   2. To restore: copy "${backupPath}" to "${filePath}"`);
        console.error(`   3. Command: cp "${backupPath}" "${filePath}"`);
        console.error('\n⚠️  users.json may be in an inconsistent state - use backup to recover');
        
        process.exit(1);
    }
}

// Main
const usersFilePath = path.join(__dirname, '../server/users.json');

if (!fs.existsSync(usersFilePath)) {
    console.error('ERROR: users.json not found at:', usersFilePath);
    console.error('Please run this script from the react-chat-app directory');
    process.exit(1);
}

migrateUsersFile(usersFilePath);
console.log('\n✅ Migration complete!');
console.log('\nNOTE: New users registered via the app will automatically use hashed passwords.');
console.log('Existing users can still login (backward compatibility), but consider forcing a password reset.\n');
