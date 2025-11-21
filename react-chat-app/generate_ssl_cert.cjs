/**
 * Generate self-signed SSL certificates for local development
 * For production, use proper certificates from Let's Encrypt or a CA
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const certsDir = path.join(__dirname, 'certs');

// Create certs directory if it doesn't exist
if (!fs.existsSync(certsDir)) {
    fs.mkdirSync(certsDir);
    console.log('✓ Created certs directory');
}

const keyPath = path.join(certsDir, 'key.pem');
const certPath = path.join(certsDir, 'cert.pem');

// Check if certificates exist and handle all three states
const keyExists = fs.existsSync(keyPath);
const certExists = fs.existsSync(certPath);

if (keyExists && certExists) {
    // Both exist - keep current behavior
    console.log('⚠️  SSL certificates already exist:');
    console.log('   - Key:', keyPath);
    console.log('   - Cert:', certPath);
    console.log('\nTo regenerate, delete the existing files and run this script again.\n');
    process.exit(0);
} else if (keyExists || certExists) {
    // Partial state - one exists but not the other
    console.error('❌ Inconsistent SSL certificate state detected:');
    if (keyExists && !certExists) {
        console.error('   - Private key exists at:', keyPath);
        console.error('   - Certificate is MISSING at:', certPath);
    } else {
        console.error('   - Certificate exists at:', certPath);
        console.error('   - Private key is MISSING at:', keyPath);
    }
    console.error('\n📋 To fix this inconsistency:');
    console.error('   1. Remove the remaining file(s):');
    console.error('      - Key:', keyPath);
    console.error('      - Cert:', certPath);
    console.error('   2. Run this script again to generate a matching pair');
    console.error('\nCommand to remove both files:');
    if (process.platform === 'win32') {
        console.error(`   del "${keyPath}" "${certPath}"`);
    } else {
        console.error(`   rm "${keyPath}" "${certPath}"`);
    }
    console.error('');
    process.exit(1);
}
// If neither exists, proceed to generate below

try {
    console.log('Generating self-signed SSL certificate...\n');
    
    // Generate private key and certificate in one command
    const opensslCmd = `openssl req -x509 -newkey rsa:4096 -keyout "${keyPath}" -out "${certPath}" -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/OU=Department/CN=localhost"`;
    
    execSync(opensslCmd, { stdio: 'inherit' });
    
    // Set restrictive permissions on private key (owner read/write only: 0o600)
    // Only apply on Unix-like systems; Windows ACLs work differently
    if (process.platform !== 'win32') {
        try {
            fs.chmodSync(keyPath, 0o600);
            console.log('✓ Set restrictive permissions on private key (0o600)');
        } catch (chmodError) {
            console.error('\n❌ Failed to set permissions on private key:', chmodError.message);
            console.error('   File:', keyPath);
            console.error('   The private key file exists but has incorrect permissions.');
            console.error('   Run manually: chmod 600 "' + keyPath + '"\n');
            process.exit(1);
        }
    } else {
        console.log('ℹ️  Skipping chmod on Windows (ACL permissions apply)');
        console.log('   Private key location:', keyPath);
        console.log('   Ensure only your user account has read/write access');
    }
    
    console.log('\n✅ SSL certificates generated successfully!');
    console.log('   - Private key:', keyPath);
    console.log('   - Certificate:', certPath);
    console.log('\n📋 Certificate details:');
    console.log('   - Algorithm: RSA 4096-bit');
    console.log('   - Valid for: 365 days');
    console.log('   - Subject: CN=localhost');
    console.log('\n⚠️  IMPORTANT:');
    console.log('   - These are self-signed certificates for DEVELOPMENT ONLY');
    console.log('   - Browsers will show a security warning (this is expected)');
    console.log('   - For production, use certificates from Let\'s Encrypt or a trusted CA');
    console.log('\n🔧 Next steps:');
    console.log('   1. Update react-chat-app/.env with HTTPS_ENABLED=true');
    console.log('   2. Restart the Node.js server');
    console.log('   3. Access the app via https://localhost:5000');
    console.log('   4. Accept the browser security warning (for dev only)\n');
    
} catch (error) {
    console.error('\n❌ Error generating SSL certificates:', error.message);
    console.error('\nMake sure OpenSSL is installed and available in your PATH.');
    console.error('Windows: Download from https://slproweb.com/products/Win32OpenSSL.html');
    console.error('Or use Git Bash which includes OpenSSL.\n');
    process.exit(1);
}
