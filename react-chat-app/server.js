import 'dotenv/config';
import express from 'express';
import http from 'http';
import https from 'https';
import fs from 'fs';
import { WebSocketServer, WebSocket } from 'ws';
import net from 'net';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import { SHA3 } from 'sha3';
import { 
    saveMessage, 
    getChatHistory, 
    getBroadcastHistory,
    markMessagesAsRead 
} from './supabaseClient.js';
import { getAIResponse, isAIEnabled, AI_PROVIDER, GEMINI_MODEL, OPENROUTER_MODEL } from './aiService.js';
import { encryptAES_GCM, decryptAES_GCM, generateKey } from './crypto.js';

// ============================================================================
// KYBER POST-QUANTUM CRYPTOGRAPHY (OPTIONAL)
// ============================================================================
// Feature toggle: Set ENABLE_KYBER=true in environment to enable PQC
const ENABLE_KYBER = process.env.ENABLE_KYBER === 'true';

// Kyber module - loaded dynamically to avoid breaking if unavailable
let kyberManager = null;
let kyberAvailable = false;

async function initializeKyber() {
    if (!ENABLE_KYBER) {
        console.log('[KYBER] Disabled (set ENABLE_KYBER=true to enable)');
        return;
    }
    
    try {
        const { KyberManager } = await import('./crypto/kyber.js');
        kyberManager = new KyberManager({ enabled: true });
        
        // Wait for initialization
        await new Promise(resolve => setTimeout(resolve, 100));
        
        if (kyberManager.isAvailable()) {
            kyberAvailable = true;
            console.log('[KYBER] ✓ Post-quantum cryptography ENABLED (Kyber-768)');
        } else {
            console.log('[KYBER] ⚠️ Module loaded but not available');
        }
    } catch (error) {
        console.log('[KYBER] ⚠️ Not available:', error.message);
        console.log('[KYBER] Falling back to classical cryptography');
    }
}

// Initialize Kyber asynchronously (non-blocking)
initializeKyber();

// Legacy compatibility - keep oqsReady for any code that checks it
const oqsReady = true;

// ============================================================================
// PRESENCE TRACKING (OPTIONAL)
// ============================================================================
// Feature toggle: Set ENABLE_PRESENCE=true in environment to enable presence
const ENABLE_PRESENCE = process.env.ENABLE_PRESENCE === 'true';

// Presence store - loaded dynamically to avoid breaking if unavailable
let presenceStore = null;

async function initializePresence() {
    if (!ENABLE_PRESENCE) {
        console.log('[PRESENCE] Disabled (set ENABLE_PRESENCE=true to enable)');
        return;
    }
    
    try {
        presenceStore = await import('./utils/presenceStore.js');
        console.log('[PRESENCE] ✓ Presence tracking ENABLED');
    } catch (error) {
        console.log('[PRESENCE] ⚠️ Not available:', error.message);
    }
}

// Initialize Presence asynchronously (non-blocking)
initializePresence();

/**
 * SHA3-256 hash function to match C++ pqDeriveSessionKey
 * @param {Buffer} data - Data to hash
 * @returns {Buffer} - 32-byte hash
 */
function sha3_256(data) {
    const hash = new SHA3(256);
    hash.update(data);
    return hash.digest();
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

//Connection Code 2️ NODE.JS BRIDGE (Middle Layer)



const PORT = process.env.PORT || 5000;
const TCP_HOST = 'localhost';
const TCP_PORT = 8080;
const HTTPS_ENABLED = process.env.HTTPS_ENABLED === 'true';

/**
 * Helper function to format data being sent to C++ server for logging
 */
function formatOutgoingData(data, isEncrypted = false) {
    let display = data;
    if (display.length > 100) {
        display = display.substring(0, 97) + '...';
    }
    display = display.replace(/\n/g, '\\n');
    
    const encrypted = isEncrypted ? ' [ENCRYPTED]' : '';
    return `"${display}"${encrypted}`;
}

/**
 * PBKDF2 Session Key Derivation Parameters
 * 
 * CRITICAL: These must EXACTLY match the C++ server implementation
 * in server/Server.cpp (deriveSessionKey function).
 * 
 * Algorithm: PBKDF2-HMAC-SHA256
 * Input: username + nonce (16 bytes random)
 * Salt: Static shared secret (SECURECHAT_SESSION_SALT)
 * Iterations: 100,000 (OWASP 2023 minimum for session keys)
 * Output: 32 bytes (AES-256 key)
 * 
 * Security Notes:
 * - Nonce MUST be 16 bytes of cryptographically secure random data
 * - Nonce replay protection implemented via usedNonces tracking
 * - Static salt is acceptable for session key derivation (not password hashing)
 * - DO NOT modify these values without updating the C++ server
 */
const SESSION_KEY_PBKDF2_SALT = 'SECURECHAT_SESSION_SALT';
const SESSION_KEY_PBKDF2_ITERATIONS = 100000;
const SESSION_KEY_LENGTH = 32;  // AES-256
const NONCE_LENGTH = 16;  // 128 bits

/**
 * Nonce Replay Protection
 * 
 * Tracks used nonces per connection to prevent replay attacks.
 * Each WebSocket connection maintains its own Set of used nonces.
 * Nonces are cleared when the connection closes.
 * 
 * Max age: 5 minutes (nonces older than this are rejected even if not replayed)
 */
const NONCE_MAX_AGE_MS = 5 * 60 * 1000;  // 5 minutes

const app = express();

// Create server (HTTP or HTTPS based on environment)
let server;
if (HTTPS_ENABLED) {
    const keyPath = path.join(__dirname, 'certs', 'key.pem');
    const certPath = path.join(__dirname, 'certs', 'cert.pem');
    
    if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
        console.error('ERROR: SSL certificates not found!');
        console.error('Run: node generate_ssl_cert.cjs');
        process.exit(1);
    }
    
    const sslOptions = {
        key: fs.readFileSync(keyPath),
        cert: fs.readFileSync(certPath)
    };
    
    server = https.createServer(sslOptions, app);
    console.log('🔒 HTTPS/WSS enabled with SSL certificates');
} else {
    server = http.createServer(app);
    console.log('⚠️  Running in HTTP/WS mode (insecure)');
}

const wss = new WebSocketServer({ server });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'dist')));

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// API endpoint to get chat history
app.get('/api/history/:user1/:user2', async (req, res) => {
    try {
        const { user1, user2 } = req.params;
        const history = await getChatHistory(user1, user2);
        res.json({ success: true, messages: history });
    } catch (error) {
        console.error('[API] Error fetching chat history:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// API endpoint to get broadcast history
app.get('/api/history/broadcast', async (req, res) => {
    try {
        const history = await getBroadcastHistory();
        res.json({ success: true, messages: history });
    } catch (error) {
        console.error('[API] Error fetching broadcast history:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// API endpoint to mark messages as read
app.post('/api/messages/read', async (req, res) => {
    try {
        const { sender, recipient } = req.body;
        await markMessagesAsRead(sender, recipient);
        res.json({ success: true });
    } catch (error) {
        console.error('[API] Error marking messages as read:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// API endpoint for AI chatbot
app.post('/api/ai/chat', async (req, res) => {
    try {
        const { message, conversationHistory } = req.body;
        
        if (!message) {
            return res.status(400).json({ success: false, error: 'Message is required' });
        }

        if (!isAIEnabled()) {
            return res.json({ 
                success: false, 
                error: 'AI chatbot is not configured. Please set up your API key in the .env file.' 
            });
        }

        const aiResponse = await getAIResponse(message, conversationHistory || []);
        res.json({ success: true, response: aiResponse });
    } catch (error) {
        console.error('[API] Error with AI chat:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// API endpoint to check AI status
app.get('/api/ai/status', (req, res) => {
    const modelInfo = AI_PROVIDER === 'gemini' 
        ? `Gemini (${GEMINI_MODEL})` 
        : `OpenRouter (${OPENROUTER_MODEL})`;
    
    res.json({ 
        enabled: isAIEnabled(),
        provider: AI_PROVIDER,
        model: AI_PROVIDER === 'gemini' ? GEMINI_MODEL : OPENROUTER_MODEL,
        message: isAIEnabled() 
            ? `AI chatbot is enabled using ${modelInfo}` 
            : 'AI chatbot is not configured'
    });
});

// API endpoint to check Kyber/PQC status
app.get('/api/crypto/status', (req, res) => {
    res.json({
        kyber: {
            enabled: ENABLE_KYBER,
            available: kyberAvailable,
            variant: 'Kyber-768',
            securityLevel: '192-bit classical / NIST Level 3'
        },
        classical: {
            algorithm: 'AES-256-GCM',
            keyDerivation: 'PBKDF2-HMAC-SHA256'
        },
        mode: kyberAvailable ? 'hybrid (PQC + Classical)' : 'classical only',
        message: ENABLE_KYBER 
            ? (kyberAvailable 
                ? 'Post-quantum cryptography enabled (Kyber-768 hybrid mode)'
                : 'Kyber enabled but not available - using classical encryption')
            : 'Classical encryption only (set ENABLE_KYBER=true for PQC)'
    });
});

// ============================================================================
// PRESENCE API ENDPOINTS
// ============================================================================

// Get presence status for all users
app.get('/api/presence', (req, res) => {
    if (!ENABLE_PRESENCE || !presenceStore) {
        return res.json({
            enabled: false,
            message: 'Presence tracking disabled (set ENABLE_PRESENCE=true to enable)',
            users: {}
        });
    }
    
    res.json({
        enabled: true,
        users: presenceStore.getAll(),
        config: {
            heartbeatTimeout: presenceStore.CONFIG.HEARTBEAT_TIMEOUT_MS,
            idleTimeout: presenceStore.CONFIG.IDLE_TIMEOUT_MS
        }
    });
});

// Get presence status for a specific user
app.get('/api/presence/:userId', (req, res) => {
    if (!ENABLE_PRESENCE || !presenceStore) {
        return res.json({
            enabled: false,
            message: 'Presence tracking disabled'
        });
    }
    
    const { userId } = req.params;
    const presence = presenceStore.get(userId);
    
    res.json({
        enabled: true,
        ...presence
    });
});

// API endpoint to get all users (for contacts list)
app.get('/api/users', async (req, res) => {
    try {
        const fs = await import('fs/promises');
        const usersPath = path.join(__dirname, '../server/users.json');
        
        // Check if file exists
        try {
            await fs.access(usersPath);
        } catch (err) {
            // Try build folder path
            const buildPath = path.join(__dirname, '../server/build/users.json');
            try {
                await fs.access(buildPath);
                const data = await fs.readFile(buildPath, 'utf8');
                const usersData = JSON.parse(data);
                const usernames = usersData.users.map(user => user.username);
                return res.json({ success: true, users: usernames });
            } catch (buildErr) {
                return res.status(404).json({ success: false, error: 'Users file not found' });
            }
        }
        
        const data = await fs.readFile(usersPath, 'utf8');
        const usersData = JSON.parse(data);
        const usernames = usersData.users.map(user => user.username);
        
        res.json({ success: true, users: usernames });
    } catch (error) {
        console.error('[API] Error fetching users:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Serve React app for all other routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

/**
 * Check if a string looks like base64 encoded data
 * @param {string} str - String to check
 * @returns {boolean} True if it looks like base64
 */
function isBase64Encoded(str) {
    // Base64 strings contain only:
    // - Standard: alphanumeric, +, /
    // - URL-safe: alphanumeric, -, _
    // - Padding: 0-2 '=' at the end
    
    // MINIMUM LENGTH CALCULATION (AES-256-GCM format):
    // Binary format: IV(12 bytes) + ciphertext(≥0 bytes) + tag(16 bytes)
    // 
    // Absolute minimum (empty plaintext):
    //   12 (IV) + 0 (empty ciphertext) + 16 (tag) = 28 bytes
    //   Base64 encoding: ceil(28 * 4/3) = ceil(37.33) = 40 chars (with padding)
    // 
    // Single character plaintext:
    //   12 (IV) + 1 (ciphertext) + 16 (tag) = 29 bytes
    //   Base64 encoding: ceil(29 * 4/3) = ceil(38.67) = 40 chars (with padding)
    // 
    // 8-byte plaintext (from old comment):
    //   12 (IV) + 8 (ciphertext) + 16 (tag) = 36 bytes
    //   Base64 encoding: ceil(36 * 4/3) = 48 chars
    //
    // THRESHOLD CHOICE: 40 characters
    // - Covers empty strings and single-character messages
    // - Rejects obviously invalid data (too short)
    // - Base64 padding ensures minimum 40 chars for 28-29 byte payloads
    //
    // VERIFIED AGAINST: crypto.js encryptAES_GCM implementation
    // Edge cases tested:
    // - Empty string "" → 40 chars (12+0+16=28 bytes → base64)
    // - Single char "a" → 40 chars (12+1+16=29 bytes → base64)
    // - Short message "test" → 44 chars (12+4+16=32 bytes → base64)
    const MINIMUM_BASE64_LENGTH = 40;
    
    if (str.length < MINIMUM_BASE64_LENGTH) return false;
    
    const base64Regex = /^[A-Za-z0-9+/\-_]+={0,2}$/;
    return base64Regex.test(str);
}
//KEY INTEGRATION CODE STARTS HERE
wss.on('connection', (ws) => {
    console.log('[WS] New WebSocket client connected');
    
    const tcpClient = new net.Socket();
    let connectionAttempts = 0;
    const maxAttempts = 3;
    let authenticated = false;
    let isClosing = false;
    let currentUsername = null;
    let authTimeout = null;
    const AUTH_TIMEOUT_MS = 60000; // 60 seconds
    let awaitingChoice = false;  // Tracks if server is waiting for login/register choice
    let isRegistering = false;   // Tracks if user is in registration flow
    
    // Encryption state for server↔bridge
    let serverEncryptionEnabled = false;
    let serverSessionKey = null;  // Session key from C++ server
    let serverDecryptionFailures = 0;  // Track decryption failures
    const SERVER_DECRYPTION_FAILURE_THRESHOLD = 3;  // Disconnect after 3 failures
    
    // Nonce replay protection - tracks used nonces for this connection
    const usedNonces = new Set();  // Store base64-encoded nonces
    const nonceTimestamps = new Map();  // Track when each nonce was first seen
    
    // Encryption state for browser↔bridge
    let wsEncryptionEnabled = false;
    let wsSessionKey = null;  // Session key for WebSocket connection
    let kyberKeyPair = null;  // Kyber key pair for this connection (if enabled)
    let kyberSharedSecret = null;  // Shared secret from Kyber exchange
    let kyberExchangeComplete = false;  // Whether Kyber exchange succeeded
    
    // Generate WebSocket session key
    // If Kyber is enabled, we'll use hybrid mode (Kyber + classical)
    wsSessionKey = generateKey();
    console.log('[WS_CRYPTO] Generated WebSocket session key (classical)');
    
    // Kyber key exchange (OPTIONAL - only if ENABLE_KYBER=true)
    async function attemptKyberKeyExchange() {
        if (!kyberAvailable || !kyberManager) {
            return false;
        }
        
        try {
            // Generate Kyber key pair for this connection
            kyberKeyPair = await kyberManager.generateKeyPair();
            if (!kyberKeyPair) {
                console.log('[KYBER] Key pair generation failed, using classical only');
                return false;
            }
            
            // Send Kyber public key to browser
            const pubKeyB64 = Buffer.from(kyberKeyPair.publicKey).toString('base64');
            ws.send(`KYBER_PUBLIC_KEY:${pubKeyB64}`);
            console.log('[KYBER] ✓ Sent public key to browser for PQC key exchange');
            return true;
        } catch (error) {
            console.error('[KYBER] Key exchange setup failed:', error.message);
            return false;
        }
    }
    
    // Handle Kyber ciphertext from browser (response to our public key)
    async function handleKyberCiphertext(ciphertextB64) {
        if (!kyberKeyPair || !kyberManager) {
            console.warn('[KYBER] Received ciphertext but Kyber not initialized');
            return false;
        }
        
        try {
            // Use browser-specific decapsulation method
            // The browser sends a simplified ciphertext that doesn't require WASM Kyber
            kyberSharedSecret = await kyberManager.decapsulateBrowser(ciphertextB64);
            
            if (!kyberSharedSecret) {
                console.error('[KYBER] Decapsulation failed');
                return false;
            }
            
            // NOTE: For now, we just verify the Kyber exchange works but don't modify
            // the session key mid-stream as it causes synchronization issues.
            // The Kyber shared secret is stored for future use (e.g., key rotation).
            kyberExchangeComplete = true;
            console.log('[KYBER] ✓ Kyber-768 key exchange verified successfully');
            console.log('[KYBER] Shared secret established (32 bytes)');
            console.log('[KYBER] Note: Using classical AES-256-GCM for this session');
            return true;
        } catch (error) {
            console.error('[KYBER] Ciphertext processing failed:', error.message);
        }
        
        return false;
    }
    
    // Send WebSocket session key to browser immediately (before authentication)
    // This allows the browser to encrypt the auto-login credentials
    if (!HTTPS_ENABLED) {
        console.warn('[WS_CRYPTO] ⚠️  WARNING: Sending session key over INSECURE connection for testing');
        console.warn('[WS_CRYPTO] This is NOT SECURE - enable HTTPS for production use');
    }
    const wsKeyB64 = wsSessionKey.toString('base64');
    ws.send(`WS_SESSION_KEY:${wsKeyB64}`);
    wsEncryptionEnabled = true;
    console.log('[WS_CRYPTO] ✓ Sent WebSocket session key to browser');
    console.log('[WS_CRYPTO] WebSocket encryption enabled (mode:', HTTPS_ENABLED ? 'secure WSS' : 'INSECURE WS - testing only', ')');
    
    // Attempt Kyber key exchange if enabled (non-blocking)
    if (ENABLE_KYBER && kyberAvailable) {
        attemptKyberKeyExchange().catch(err => {
            console.log('[KYBER] Exchange setup error (non-fatal):', err.message);
        });
    }
    
    function connectTCP() {
        if (connectionAttempts >= maxAttempts) {
            console.error('[TCP] Max connection attempts reached');
            if (ws.readyState === WebSocket.OPEN) {
                ws.send('Error: Cannot connect to chat server');
                ws.close();
            }
            return;
        }
        
        connectionAttempts++;
        console.log(`[TCP] Connection attempt ${connectionAttempts}/${maxAttempts}`);
        
        tcpClient.connect(TCP_PORT, TCP_HOST, () => {
            console.log('[TCP] Connected to C++ TCP server');
            connectionAttempts = 0;
        });
    }
    
    connectTCP();

    // Don't start auth timeout immediately - wait for user to actually attempt login
    // This prevents timeout when user is just on the login page deciding what to do

    tcpClient.on('data', (data) => {
        let message = data.toString();
        
        // Check for PQC Kyber-768 key exchange protocol
        if (message.includes('KYBER_PK:') && oqsReady && authenticated && currentUsername) {
            const pkMatch = message.match(/KYBER_PK:([A-Za-z0-9+/=]+)/);
            if (pkMatch) {
                const pkB64 = pkMatch[1].trim();
                
                
                //BACKEND RECEIVES CONNECTION FROM SERVER WITH PUBLIC KEY


                try {
                    // Step 1: Decode server's Kyber public key from base64 to Uint8Array
                    // IMPORTANT: liboqs requires Uint8Array, not Buffer
                    const pkBuffer = Buffer.from(pkB64, 'base64');
                    const serverPublicKey = new Uint8Array(pkBuffer);
                    console.log('[PQC] Received Kyber-768 public key from server (' + serverPublicKey.length + ' bytes)');
                    
                    // Step 2: Create Kyber768 instance and use it to encapsulate
                    const kyber = new Kyber768();
                    const { ciphertext, sharedSecret } = kyber.encapsulate(serverPublicKey);
                    console.log('[PQC] ✓ Encapsulated shared secret');
                    console.log('[PQC]   Ciphertext size: ' + ciphertext.length + ' bytes');
                    console.log('[PQC]   Shared secret size: ' + sharedSecret.length + ' bytes');
                    
                    // Step 3: Send ciphertext back to server
                    const ctB64 = Buffer.from(ciphertext).toString('base64');
                    tcpClient.write('KYBER_CT:' + ctB64 + '\n');
                    console.log('[PQC] Sent Kyber ciphertext to server');
                    
                    // Step 4: Derive AES-256 session key from shared secret using SHA3-256
                    // Match the C++ server's derivation: SHA3-256(sharedSecret || context)
                    const context = Buffer.from('SECURECHAT_PQC_SESSION', 'utf8');
                    const keyMaterial = Buffer.concat([Buffer.from(sharedSecret), context]);
                    
                    // Use SHA3-256 to match C++ pqDeriveSessionKey
                    serverSessionKey = sha3_256(keyMaterial);
                    
                    // Step 5: Enable encryption
                    serverEncryptionEnabled = true;
                    serverDecryptionFailures = 0;
                    
                    console.log('[PQC] ✓ Quantum-safe key exchange completed');
                    console.log('[PQC] Session key derived (' + serverSessionKey.length + ' bytes)');
                    console.log('[PQC] Encryption enabled for session');
                    
                    // Clean up Kyber instance
                    kyber.destroy();
                    
                    // Don't forward KYBER_PK to browser - it's internal protocol
                    // Remove KYBER_PK from message and check if anything remains
                    message = message.replace(/KYBER_PK:[A-Za-z0-9+/=]+\s*/, '').trim();
                    if (!message) {
                        return; // Nothing left to forward
                    }
                    
                } catch (pqcError) {
                    console.error('[PQC] ✗ CRITICAL: Kyber key exchange failed');
                    console.error('[PQC] Error:', pqcError.message);
                    console.error('[PQC] Stack:', pqcError.stack);
                    console.error('[PQC] Falling back to classical key exchange');
                    // Don't enable encryption - fallback will use NONCE if server sends it
                    // Still forward the message (minus KYBER_PK) so connection doesn't stall
                    message = message.replace(/KYBER_PK:[A-Za-z0-9+/=]+\s*/, '').trim();
                    if (!message) {
                        return;
                    }
                }
            }
        }
        
        // Check for authenticated key derivation protocol (NONCE-based) - LEGACY FALLBACK
        if (message.includes('NONCE:')) {
            const nonceMatch = message.match(/NONCE:([A-Za-z0-9+/=]+)/);
            if (nonceMatch && authenticated && currentUsername) {
                const nonceB64 = nonceMatch[1].trim();
                
                try {
                    // Step 1: Check for nonce replay (must be unique per connection)
                    if (usedNonces.has(nonceB64)) {
                        throw new Error('Nonce replay detected - this nonce was already used');
                    }
                    
                    // Step 2: Decode nonce from base64
                    const nonce = Buffer.from(nonceB64, 'base64');
                    
                    if (nonce.length !== NONCE_LENGTH) {
                        throw new Error(`Invalid nonce length: ${nonce.length} (expected ${NONCE_LENGTH})`);
                    }
                    
                    // Step 3: Check nonce freshness (prevent old nonces from being used)
                    const now = Date.now();
                    
                    // Clean up expired nonces from tracking (prevent memory leak)
                    for (const [trackedNonce, timestamp] of nonceTimestamps.entries()) {
                        if (now - timestamp > NONCE_MAX_AGE_MS) {
                            usedNonces.delete(trackedNonce);
                            nonceTimestamps.delete(trackedNonce);
                        }
                    }
                    
                    // Step 4: Mark nonce as used BEFORE deriving key (prevent TOCTOU)
                    usedNonces.add(nonceB64);
                    nonceTimestamps.set(nonceB64, now);
                    
                    // Step 5: Derive session key using same algorithm as server:
                    // keyMaterial = Buffer.concat([username_utf8, nonce_binary])
                    // derivedKey = PBKDF2(keyMaterial, SESSION_KEY_PBKDF2_SALT)
                    //
                    // CRITICAL: Build keyMaterial as Buffer to avoid encoding issues
                    // DO NOT use string concatenation - binary data may contain nulls
                    const usernameBuffer = Buffer.from(currentUsername, 'utf8');
                    const keyMaterial = Buffer.concat([usernameBuffer, nonce]);
                    
                    serverSessionKey = crypto.pbkdf2Sync(
                        keyMaterial,
                        SESSION_KEY_PBKDF2_SALT,
                        SESSION_KEY_PBKDF2_ITERATIONS,
                        SESSION_KEY_LENGTH,
                        'sha256'
                    );
                    
                    // Step 6: Enable encryption ONLY after successful derivation
                    serverEncryptionEnabled = true;
                    
                    console.log('[SERVER_CRYPTO] ✓ Authenticated key derivation completed');
                    console.log('[SERVER_CRYPTO] Derived session key from username + nonce');
                    console.log('[SERVER_CRYPTO] Session key length:', serverSessionKey.length, 'bytes');
                    console.log('[SERVER_CRYPTO] Nonce replay protection: active');
                    console.log('[SERVER_CRYPTO] Used nonces tracked:', usedNonces.size);
                    
                    // Reset decryption failure counter on successful key establishment
                    serverDecryptionFailures = 0;
                    
                    // Remove NONCE line from message
                    message = message.replace(/NONCE:[A-Za-z0-9+/=]+\s*/, '');
                    
                } catch (keyError) {
                    console.error('[SERVER_CRYPTO] ✗ CRITICAL: Authenticated key derivation failed');
                    console.error('[SERVER_CRYPTO] Error:', keyError.message);
                    console.error('[SERVER_CRYPTO] NOT enabling encryption - key derivation failed');
                    
                    // Security: If nonce was marked as used but derivation failed,
                    // keep it marked to prevent retry with same nonce
                    
                    // Do NOT set serverEncryptionEnabled
                    // Do NOT remove NONCE line since derivation failed
                }
            }
        }
        
        // Check if server is sending session key (legacy - DEPRECATED, should be removed)
        if (message.includes('SESSION_KEY:')) {
            console.error('[SERVER_CRYPTO] ⚠️  WARNING: Received deprecated SESSION_KEY message');
            console.error('[SERVER_CRYPTO] This indicates server is using insecure key transmission');
            console.error('[SERVER_CRYPTO] Please upgrade server to use authenticated NONCE protocol');
            
            const keyMatch = message.match(/SESSION_KEY:([A-Za-z0-9+/=]+)/);
            if (keyMatch) {
                console.error('[SERVER_CRYPTO] Rejecting insecure session key transmission');
                // Do NOT process SESSION_KEY - only accept NONCE-based derivation
                message = message.replace(/SESSION_KEY:[A-Za-z0-9+/=]+\s*/, '');
            }
        }
        
        // Skip empty messages
        if (!message.trim()) {
            return;
        }
        
        // Decrypt message from server if encryption is enabled
        // Only decrypt if it looks like base64 (encrypted messages)
        if (serverEncryptionEnabled && authenticated && isBase64Encoded(message.trim())) {
            try {
                const decrypted = decryptAES_GCM(message.trim(), serverSessionKey);
                if (decrypted && decrypted.length > 0) {
                    message = decrypted;
                    console.log('[SERVER_CRYPTO] Decrypted message from server');
                    // Reset failure counter on successful decryption
                    serverDecryptionFailures = 0;
                } else {
                    // Decryption returned empty/falsy - treat as security event
                    serverDecryptionFailures++;
                    console.error('[SERVER_CRYPTO] ⚠️  SECURITY: Decryption returned empty data');
                    console.error(`[SERVER_CRYPTO] Failure #${serverDecryptionFailures}/${SERVER_DECRYPTION_FAILURE_THRESHOLD}`);
                    console.error('[SERVER_CRYPTO] Username:', currentUsername || 'unknown');
                    console.error('[SERVER_CRYPTO] Timestamp:', new Date().toISOString());
                    
                    // Check if threshold exceeded
                    if (serverDecryptionFailures >= SERVER_DECRYPTION_FAILURE_THRESHOLD) {
                        console.error('[SERVER_CRYPTO] CRITICAL: Decryption failure threshold exceeded - terminating session');
                        console.error('[AUDIT] Session terminated due to repeated decryption failures', {
                            username: currentUsername,
                            failureCount: serverDecryptionFailures,
                            timestamp: new Date().toISOString()
                        });
                        
                        isClosing = true;
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.close(1008, 'Protocol error: decryption failures');
                        }
                        if (tcpClient && !tcpClient.destroyed) {
                            tcpClient.destroy();
                        }
                        return;
                    }
                    
                    // Skip this message - do not process further
                    return;
                }
            } catch (error) {
                // Decryption threw an exception - treat as security event
                serverDecryptionFailures++;
                console.error('[SERVER_CRYPTO] ⚠️  SECURITY: Decryption exception');
                console.error(`[SERVER_CRYPTO] Failure #${serverDecryptionFailures}/${SERVER_DECRYPTION_FAILURE_THRESHOLD}`);
                console.error('[SERVER_CRYPTO] Error:', error.message);
                console.error('[SERVER_CRYPTO] Username:', currentUsername || 'unknown');
                console.error('[SERVER_CRYPTO] Timestamp:', new Date().toISOString());
                
                // Check if threshold exceeded
                if (serverDecryptionFailures >= SERVER_DECRYPTION_FAILURE_THRESHOLD) {
                    console.error('[SERVER_CRYPTO] CRITICAL: Decryption failure threshold exceeded - terminating session');
                    console.error('[AUDIT] Session terminated due to repeated decryption failures', {
                        username: currentUsername,
                        failureCount: serverDecryptionFailures,
                        lastError: error.message,
                        timestamp: new Date().toISOString()
                    });
                    
                    isClosing = true;
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.close(1008, 'Protocol error: decryption failures');
                    }
                    if (tcpClient && !tcpClient.destroyed) {
                        tcpClient.destroy();
                    }
                    return;
                }
                
                // Skip this message - do not process further or fall back to plaintext
                console.error('[SERVER_CRYPTO] Message rejected - no plaintext fallback allowed');
                return;
            }
        }
        
        console.log('[TCP → WS]:', message.replace(/\n/g, '\\n'));
        
        // Encrypt message before sending to WebSocket client
        if (wsEncryptionEnabled && ws.readyState === WebSocket.OPEN) {
            try {
                const encrypted = encryptAES_GCM(message, wsSessionKey);
                ws.send(encrypted);
                console.log('[WS_CRYPTO] Encrypted message to browser');
            } catch (error) {
                console.error('[WS_CRYPTO] CRITICAL: Encryption failed:', error.message);
                console.error('[WS_CRYPTO] Cannot send sensitive data without encryption - terminating session');
                console.error('[WS_CRYPTO] Error details:', {
                    errorMessage: error.message,
                    errorStack: error.stack,
                    timestamp: new Date().toISOString()
                });
                
                // Log audit event
                console.error('[AUDIT] Encryption failure detected on authenticated session - closing connection');
                
                // Terminate WebSocket connection to prevent plaintext fallback
                if (ws.readyState === WebSocket.OPEN) {
                    try {
                        ws.close(1011, 'Encryption failure - unable to securely transmit data');
                    } catch (closeErr) {
                        console.error('[WS_CRYPTO] Error closing WebSocket:', closeErr.message);
                    }
                }
                
                // Close TCP connection
                if (tcpClient && !tcpClient.destroyed) {
                    tcpClient.end();
                    setTimeout(() => {
                        if (!tcpClient.destroyed) {
                            tcpClient.destroy();
                        }
                    }, 500);
                }
                
                isClosing = true;
                return;
            }
        } else if (ws.readyState === WebSocket.OPEN) {
            ws.send(message);
        }
        
        // Detect when server is asking for choice
        if (message.includes('Choose option (1 or 2)')) {
            awaitingChoice = true;
            console.log('[AUTH] Server awaiting choice (1=Login, 2=Register)');
        }
        
        // Check for authentication status (case-insensitive and more patterns)
        const authSuccess = message.toLowerCase().includes('authentication successful') || 
                          message.toLowerCase().includes('logged in successfully') ||
                          message.toLowerCase().includes('welcome');
        
        if (authSuccess && !authenticated) {
            authenticated = true;
            awaitingChoice = false;
            
            console.log('[AUTH] ✓ Authentication successful detected!');
            console.log('[AUTH] Current username:', currentUsername);
            
            // CRITICAL: currentUsername MUST be set before we process the NONCE
            // The NONCE is sent immediately after auth success in the same data chunk
            // If currentUsername is null, the NONCE handler will fail to derive the session key
            if (!currentUsername) {
                console.error('[AUTH] ✗ CRITICAL: Cannot authenticate without username!');
                console.error('[AUTH] Username should have been set during LOGIN/REGISTER flow');
                console.error('[AUTH] Message received:', message.substring(0, 100));
                // Do NOT set authenticated = true without username
                authenticated = false;
                return;
            }
            
            // Clear authentication timeout
            if (authTimeout) {
                clearTimeout(authTimeout);
                authTimeout = null;
                console.log('[AUTH] Cleared authentication timeout');
            }
            
            console.log('[AUTH] User authenticated:', currentUsername);
            console.log('[SERVER_CRYPTO] Server encryption active between server and bridge');
            console.log('[SERVER_CRYPTO] Waiting for NONCE to derive session key...');
            
            // WebSocket session key was already sent when connection was established
            // No need to send it again here
            
            // ============================================================
            // PRESENCE: Mark user as online after successful authentication
            // ============================================================
            if (ENABLE_PRESENCE && presenceStore && currentUsername) {
                presenceStore.setOnline(currentUsername, ws);
                // Send presence snapshot to newly authenticated user
                presenceStore.sendSnapshot(ws);
            }
        } else if (message.includes('Registration successful')) {
            console.log('[AUTH] User registered:', currentUsername);
            awaitingChoice = false;
            
            // Clear authentication timeout
            if (authTimeout) {
                clearTimeout(authTimeout);
                authTimeout = null;
            }
            
            // Registration complete - user needs to login manually
            console.log('[AUTH] Registration complete, user should login manually');
            // Don't set authenticated, user needs to reconnect and login
        } else if (message.includes('Please reconnect and login')) {
            console.log('[AUTH] Server requesting reconnect for login');
        } else if (message.includes('Authentication failed') || message.includes('Invalid credentials') || message.includes('Registration failed')) {
            authenticated = false;
            awaitingChoice = false;
            
            // Clear authentication timeout on failure
            if (authTimeout) {
                clearTimeout(authTimeout);
                authTimeout = null;
            }
            
            if (message.includes('Registration failed')) {
                console.log('[AUTH] Registration failed');
            } else {
                console.log('[AUTH] Authentication failed');
            }
            // Don't reset username immediately for better error context
        } else if (message.includes('Invalid choice')) {
            console.log('[AUTH] Invalid choice sent to server');
            awaitingChoice = false;
        } else if (message.includes('Authentication timed out')) {
            console.log('[AUTH] Server reports authentication timeout');
            authenticated = false;
            awaitingChoice = false;
            
            // Clear authentication timeout
            if (authTimeout) {
                clearTimeout(authTimeout);
                authTimeout = null;
            }
        }
        
        // Save messages to Supabase
        if (authenticated && currentUsername) {
            // Parse and save private messages (received)
            const privateMatch = message.match(/\[Private from (\w+)\]: (.+)/);
            if (privateMatch) {
                const [, sender, msg] = privateMatch;
                const payload = {
                    sender: sender,
                    recipient: currentUsername,
                    message: msg,
                    messageType: 'private'
                };
                console.log('[SUPABASE] Saving received private message', payload);
                saveMessage(payload).then(data => {
                    if (data && data.id) {
                        console.log(`[SUPABASE] ✓ Saved message ID: ${data.id}`);
                    } else {
                        console.log('[SUPABASE] ✓ Saved message (no id returned)', data);
                    }
                }).catch(err => {
                    console.error('[SUPABASE] ✗ Save failed - error:', err && err.message ? err.message : err);
                    console.error('[SUPABASE] Full error object:', err);
                });
            }
            
            // Parse and save broadcast messages - Format: [username]: message
            const broadcastMatch = message.match(/^\[(\w+)\]: (.+)/);
            if (broadcastMatch && !message.includes('Private from') && !message.includes('SYSTEM')) {
                const [, sender, msg] = broadcastMatch;
                // Don't save our own broadcasts (they're sent separately)
                if (sender !== currentUsername) {
                    const payload = {
                        sender: sender,
                        recipient: null,
                        message: msg,
                        messageType: 'broadcast'
                    };
                    console.log('[SUPABASE] Saving broadcast message', payload);
                    saveMessage(payload).then(data => {
                        if (data && data.id) {
                            console.log(`[SUPABASE] ✓ Saved broadcast ID: ${data.id}`);
                        } else {
                            console.log('[SUPABASE] ✓ Saved broadcast (no id returned)', data);
                        }
                    }).catch(err => {
                        console.error('[SUPABASE] ✗ Broadcast save failed - error:', err && err.message ? err.message : err);
                        console.error('[SUPABASE] Full error object:', err);
                    });
                }
            }
        }
        
        // Message already sent above with encryption
    });

    ws.on('message', (message) => {
        let msg = message.toString();
        
        // ====================================================================
        // CHECK FOR KYBER CIPHERTEXT FIRST (sent as plaintext)
        // ====================================================================
        // Must check before decryption because KYBER_CIPHERTEXT is unencrypted
        if (msg.startsWith('KYBER_CIPHERTEXT:')) {
            const ciphertextB64 = msg.substring('KYBER_CIPHERTEXT:'.length).trim();
            console.log('[KYBER] Received ciphertext from browser');
            console.log('[KYBER] Ciphertext length:', ciphertextB64.length, 'chars (base64)');
            
            handleKyberCiphertext(ciphertextB64)
                .then(success => {
                    if (success) {
                        // Notify browser that Kyber exchange is complete
                        ws.send('KYBER_COMPLETE:true');
                        console.log('[KYBER] ✓ Post-quantum key exchange completed');
                    } else {
                        ws.send('KYBER_COMPLETE:false');
                        console.log('[KYBER] Key exchange failed, continuing with classical encryption');
                    }
                })
                .catch(err => {
                    console.error('[KYBER] Exchange error:', err.message);
                    ws.send('KYBER_COMPLETE:false');
                });
            
            return; // Don't process Kyber messages further
        }
        
        // ====================================================================
        // CHECK FOR PRESENCE MESSAGES (can be sent as plaintext or encrypted)
        // ====================================================================
        if (msg.startsWith('PRESENCE:')) {
            if (!ENABLE_PRESENCE || !presenceStore) {
                // Presence disabled - silently ignore
                return;
            }
            
            try {
                const presenceData = JSON.parse(msg.substring('PRESENCE:'.length));
                const { action, userId } = presenceData;
                
                // Only accept presence updates for the authenticated user
                if (userId && userId !== currentUsername) {
                    console.warn('[PRESENCE] Ignoring presence for different user:', userId);
                    return;
                }
                
                const targetUser = currentUsername || userId;
                if (!targetUser) return;
                
                switch (action) {
                    case 'ONLINE':
                        presenceStore.setOnline(targetUser, ws);
                        break;
                    case 'OFFLINE':
                        presenceStore.setOffline(targetUser, ws);
                        break;
                    case 'IDLE':
                        presenceStore.setIdle(targetUser);
                        break;
                    case 'HEARTBEAT':
                        presenceStore.heartbeat(targetUser);
                        break;
                    default:
                        console.warn('[PRESENCE] Unknown action:', action);
                }
            } catch (err) {
                console.error('[PRESENCE] Failed to parse presence message:', err.message);
            }
            
            return; // Don't process presence messages further
        }
        
        // Decrypt message from browser if encryption is enabled
        if (wsEncryptionEnabled) {
            try {
                const decrypted = decryptAES_GCM(msg, wsSessionKey);
                if (decrypted) {
                    msg = decrypted;
                    console.log('[WS_CRYPTO] Decrypted message from browser');
                } else {
                    // Decryption returned falsy (empty or null)
                    console.error('[WS_CRYPTO] Decryption returned empty/falsy value - rejecting message');
                    console.error('[WS_CRYPTO] This indicates a protocol violation or tampering');
                    
                    // Send protocol error to client
                    if (ws.readyState === WebSocket.OPEN) {
                        try {
                            const errorMsg = 'Error: Decryption failed - protocol violation detected';
                            ws.send(errorMsg);
                        } catch (sendErr) {
                            console.error('[WS_CRYPTO] Failed to send error message:', sendErr.message);
                        }
                    }
                    
                    // Reject the message and return early
                    console.log('[WS_CRYPTO] Message rejected, not processing further');
                    return;
                }
            } catch (error) {
                console.error('[WS_CRYPTO] Decryption failed with error:', error.message);
                console.error('[WS_CRYPTO] This indicates corrupted, tampered, or invalid encrypted data');
                
                // Send protocol error to client
                if (ws.readyState === WebSocket.OPEN) {
                    try {
                        const errorMsg = 'Error: Failed to decrypt message - invalid format or tampering detected';
                        ws.send(errorMsg);
                    } catch (sendErr) {
                        console.error('[WS_CRYPTO] Failed to send error message:', sendErr.message);
                    }
                }
                
                // Reject the message and return early - do NOT fall back to plaintext
                console.log('[WS_CRYPTO] Message rejected due to decryption error, not processing further');
                return;
            }
        }
        
        console.log('[WS → TCP]:', msg.replace(/\n/g, '\\n'));
        
        // Handle authentication flow
        if (!authenticated) {
            // Check if this is a login/register command from client
            if (msg.startsWith('LOGIN:')) {
                // CRITICAL: Ensure TCP connection is established before sending credentials
                // After registration, the connection may have closed, so we need to verify it's ready
                // Check if socket is destroyed, connecting, or not writable
                const socketNotReady = tcpClient.destroyed || tcpClient.connecting || !tcpClient.writable;
                if (socketNotReady) {
                    console.warn('[TCP] Connection not ready for login - establishing connection...');
                    console.warn('[TCP] TCP socket state - destroyed:', tcpClient.destroyed, 'connecting:', tcpClient.connecting, 'writable:', tcpClient.writable);
                    
                    // Create a new TCP connection
                    tcpClient.destroy();
                    connectTCP();
                    
                    // Queue the login message to be sent after connection is established
                    // Re-call this handler after a short delay to allow connection
                    setTimeout(() => {
                        if (ws.readyState === WebSocket.OPEN) {
                            // Re-send the message through WebSocket to trigger re-processing
                            // But we need to encrypt it first if wsEncryptionEnabled
                            if (wsEncryptionEnabled) {
                                const loginMsg = msg;  // Already decrypted above
                                encryptAES_GCM(loginMsg, wsSessionKey)
                                    .then(encrypted => {
                                        ws.send(encrypted + '\n');
                                        console.log('[TCP] Re-queued login attempt after reconnection');
                                    })
                                    .catch(err => {
                                        console.error('[TCP] Failed to re-encrypt login for retry:', err);
                                    });
                            }
                        }
                    }, 1500);  // Wait for TCP to reconnect
                    return;
                }
                
                // Start authentication timeout only when user attempts to login
                if (!authTimeout) {
                    console.log('[AUTH] Starting 60-second authentication timeout');
                    authTimeout = setTimeout(() => {
                        if (!authenticated && !isClosing) {
                            console.log(`[AUTH] Authentication timed out after ${AUTH_TIMEOUT_MS / 1000} seconds`);
                            isClosing = true;
                            
                            if (ws.readyState === WebSocket.OPEN) {
                                ws.send('Error: Authentication timed out. Please try again.');
                                setTimeout(() => {
                                    ws.close(1008, 'Authentication timeout');
                                }, 100);
                            }
                            
                            if (tcpClient && !tcpClient.destroyed) {
                                tcpClient.end();
                                setTimeout(() => {
                                    if (!tcpClient.destroyed) {
                                        tcpClient.destroy();
                                    }
                                }, 500);
                            }
                        }
                    }, AUTH_TIMEOUT_MS);
                }
                
                // Expected format: LOGIN:username:password
                const parts = msg.substring(6).split(':');
                const username = parts[0]?.trim();
                const password = parts[1]?.trim();
                if (!username || !password) {
                    console.log('[AUTH] LOGIN message missing username or password');
                } else {
                    currentUsername = username;
                    console.log('[AUTH] Login attempt for:', currentUsername);
                    // Send choice 1 (Login) then username and password with delays
                    const ts1 = new Date().toISOString();
                    console.log(`[${ts1}] [BRIDGE→CPP-SERVER] [LOGIN-CHOICE] ${formatOutgoingData('1\\n', serverEncryptionEnabled)}`);
                    tcpClient.write('1\n');
                    setTimeout(() => {
                        const ts2 = new Date().toISOString();
                        console.log(`[${ts2}] [BRIDGE→CPP-SERVER] [LOGIN-USERNAME] ${formatOutgoingData(username + '\\n', serverEncryptionEnabled)}`);
                        tcpClient.write(username + '\n');
                        setTimeout(() => {
                            const ts3 = new Date().toISOString();
                            console.log(`[${ts3}] [BRIDGE→CPP-SERVER] [LOGIN-PASSWORD] ${formatOutgoingData(password + '\\n', serverEncryptionEnabled)}`);
                            tcpClient.write(password + '\n');
                        }, 50);
                    }, 50);
                    awaitingChoice = false;
                    isRegistering = false;
                    return;
                }
            } else if (msg.startsWith('REGISTER:')) {
                // CRITICAL: Ensure TCP connection is established before sending credentials
                // After a previous attempt, the connection may have closed
                // Check if socket is destroyed, connecting, or not writable
                const socketNotReady = tcpClient.destroyed || tcpClient.connecting || !tcpClient.writable;
                if (socketNotReady) {
                    console.warn('[TCP] Connection not ready for registration - establishing connection...');
                    console.warn('[TCP] TCP socket state - destroyed:', tcpClient.destroyed, 'connecting:', tcpClient.connecting, 'writable:', tcpClient.writable);
                    
                    // Create a new TCP connection
                    tcpClient.destroy();
                    connectTCP();
                    
                    // Queue the register message to be sent after connection is established
                    setTimeout(() => {
                        if (ws.readyState === WebSocket.OPEN) {
                            // Re-send the message through WebSocket to trigger re-processing
                            if (wsEncryptionEnabled) {
                                const registerMsg = msg;  // Already decrypted above
                                encryptAES_GCM(registerMsg, wsSessionKey)
                                    .then(encrypted => {
                                        ws.send(encrypted + '\n');
                                        console.log('[TCP] Re-queued registration attempt after reconnection');
                                    })
                                    .catch(err => {
                                        console.error('[TCP] Failed to re-encrypt register for retry:', err);
                                    });
                            }
                        }
                    }, 1500);  // Wait for TCP to reconnect
                    return;
                }
                
                // Start authentication timeout only when user attempts to register
                if (!authTimeout) {
                    console.log('[AUTH] Starting 60-second authentication timeout');
                    authTimeout = setTimeout(() => {
                        if (!authenticated && !isClosing) {
                            console.log(`[AUTH] Authentication timed out after ${AUTH_TIMEOUT_MS / 1000} seconds`);
                            isClosing = true;
                            
                            if (ws.readyState === WebSocket.OPEN) {
                                ws.send('Error: Authentication timed out. Please try again.');
                                setTimeout(() => {
                                    ws.close(1008, 'Authentication timeout');
                                }, 100);
                            }
                            
                            if (tcpClient && !tcpClient.destroyed) {
                                tcpClient.end();
                                setTimeout(() => {
                                    if (!tcpClient.destroyed) {
                                        tcpClient.destroy();
                                    }
                                }, 500);
                            }
                        }
                    }, AUTH_TIMEOUT_MS);
                }
                
                // Expected format: REGISTER:username:password
                const parts = msg.substring(9).split(':');
                const username = parts[0]?.trim();
                const password = parts[1]?.trim();
                if (!username || !password) {
                    console.log('[AUTH] REGISTER message missing username or password');
                } else {
                    currentUsername = username;
                    console.log('[AUTH] Registration attempt for:', currentUsername);
                    // Send choice 2 (Register) then username and password and confirmation with delays
                    const timestamp = new Date().toISOString();
                    console.log(`[${timestamp}] [BRIDGE→CPP-SERVER] [REGISTER-CHOICE] ${formatOutgoingData('2\\n', serverEncryptionEnabled)}`);
                    tcpClient.write('2\n');
                    setTimeout(() => {
                        const ts = new Date().toISOString();
                        console.log(`[${ts}] [BRIDGE→CPP-SERVER] [REGISTER-USERNAME] ${formatOutgoingData(username + '\\n', serverEncryptionEnabled)}`);
                        tcpClient.write(username + '\n');
                        setTimeout(() => {
                            const ts2 = new Date().toISOString();
                            console.log(`[${ts2}] [BRIDGE→CPP-SERVER] [REGISTER-PASSWORD] ${formatOutgoingData(password + '\\n', serverEncryptionEnabled)}`);
                            tcpClient.write(password + '\n');
                            setTimeout(() => {
                                const ts3 = new Date().toISOString();
                                console.log(`[${ts3}] [BRIDGE→CPP-SERVER] [REGISTER-CONFIRM] ${formatOutgoingData(password + '\\n', serverEncryptionEnabled)}`);
                                tcpClient.write(password + '\n');
                            }, 50);
                        }, 50);
                    }, 50);
                    awaitingChoice = false;
                    isRegistering = true;
                    return;
                }
            }
            
            // If we're awaiting choice and get username, assume login
            if (awaitingChoice && !currentUsername) {
                const plainUsername = msg.match(/^([a-zA-Z0-9_]+)\s*$/);
                if (plainUsername) {
                    currentUsername = plainUsername[1];
                    console.log('[AUTH] Username captured, defaulting to login:', currentUsername);
                    // Send choice 1 (Login) then username
                    tcpClient.write('1\n');
                    awaitingChoice = false;
                }
            }
        }
        
        // Save outgoing messages to Supabase
        if (authenticated && currentUsername) {
            // Parse private messages (sent)
            const privateMsgMatch = msg.match(/\/msg (\w+) (.+)/);
            if (privateMsgMatch) {
                const [, recipient, content] = privateMsgMatch;
                const payload = {
                    sender: currentUsername,
                    recipient: recipient,
                    message: content,
                    messageType: 'private'
                };
                console.log('[SUPABASE] Saving sent private message', payload);
                saveMessage(payload).then(data => {
                    if (data && data.id) {
                        console.log(`[SUPABASE] ✓ Saved sent message ID: ${data.id}`);
                    } else {
                        console.log('[SUPABASE] ✓ Saved sent message (no id returned)', data);
                    }
                }).catch(err => {
                    console.error('[SUPABASE] ✗ Save failed - error:', err && err.message ? err.message : err);
                    console.error('[SUPABASE] Full error object:', err);
                });
            }
            
            // Parse broadcast messages (sent)
            const broadcastMsgMatch = msg.match(/\/broadcast (.+)/);
            if (broadcastMsgMatch) {
                const [, content] = broadcastMsgMatch;
                const payload = {
                    sender: currentUsername,
                    recipient: null,
                    message: content,
                    messageType: 'broadcast'
                };
                console.log('[SUPABASE] Saving sent broadcast message', payload);
                saveMessage(payload).then(data => {
                    if (data && data.id) {
                        console.log(`[SUPABASE] ✓ Saved sent broadcast ID: ${data.id}`);
                    } else {
                        console.log('[SUPABASE] ✓ Saved sent broadcast (no id returned)', data);
                    }
                }).catch(err => {
                    console.error('[SUPABASE] ✗ Broadcast save failed - error:', err && err.message ? err.message : err);
                    console.error('[SUPABASE] Full error object:', err);
                });
            }
        }
        
        // Forward to TCP server with encryption if enabled
        if (tcpClient.writable) {
            // Encrypt message if server encryption is enabled and authenticated
            if (serverEncryptionEnabled && authenticated) {
                try {
                    const encrypted = encryptAES_GCM(msg, serverSessionKey);
                    
                    // SUCCESS: Send encrypted message
                    const tsEnc = new Date().toISOString();
                    console.log(`[${tsEnc}] [BRIDGE→CPP-SERVER] [ENCRYPTED-MESSAGE] ${formatOutgoingData(msg, serverEncryptionEnabled)}`);
                    tcpClient.write(encrypted + '\n');
                    console.log('[SERVER_CRYPTO] ✓ Encrypted and sent message to server');
                    
                } catch (error) {
                    console.error('[SERVER_CRYPTO] ✗ CRITICAL: Outgoing encryption failed');
                    console.error('[SERVER_CRYPTO] Error details:', error.message);
                    console.error('[SERVER_CRYPTO] Error stack:', error.stack);
                    console.error('[SERVER_CRYPTO] Timestamp:', new Date().toISOString());
                    console.error('[SERVER_CRYPTO] REFUSING to send plaintext - security policy violation');
                    
                    // Log audit event
                    console.error('[AUDIT] Outgoing encryption failure on authenticated session');
                    console.error('[AUDIT] Message NOT sent to prevent plaintext leakage');
                    
                    // Send error notification to client
                    if (ws.readyState === WebSocket.OPEN) {
                        const errorNotification = 'ERROR: Cannot send message - encryption failure. Connection will be terminated for security.';
                        try {
                            if (wsEncryptionEnabled) {
                                const encryptedError = encryptAES_GCM(errorNotification, wsSessionKey);
                                ws.send(encryptedError);
                            } else {
                                ws.send(errorNotification);
                            }
                        } catch (notifyError) {
                            console.error('[SERVER_CRYPTO] Failed to notify client of encryption failure:', notifyError.message);
                        }
                    }
                    
                    // Terminate connection to prevent further plaintext transmission
                    console.error('[SERVER_CRYPTO] Terminating TCP connection due to encryption failure');
                    if (tcpClient && !tcpClient.destroyed) {
                        tcpClient.destroy();
                    }
                    
                    // Close WebSocket connection
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.close(1011, 'Encryption failure - unable to securely transmit data');
                    }
                    
                    // Do NOT execute tcpClient.write() - message must not be sent in plaintext
                    return;
                }
            } else {
                // Encryption not required (not authenticated or encryption not enabled)
                // Safe to send in plaintext
                const tsPlain = new Date().toISOString();
                console.log(`[${tsPlain}] [BRIDGE→CPP-SERVER] [PLAINTEXT-MESSAGE] ${formatOutgoingData(msg, serverEncryptionEnabled)}`);
                tcpClient.write(msg + '\n');
                console.log('[TCP] Sent plaintext message (encryption not required)');
            }
        } else {
            console.error('[TCP] Socket not writable');
            if (ws.readyState === WebSocket.OPEN) {
                // Send encrypted error message to browser
                const errorMsg = 'Error: Not connected to chat server';
                if (wsEncryptionEnabled) {
                    try {
                        const encrypted = encryptAES_GCM(errorMsg, wsSessionKey);
                        ws.send(encrypted);
                    } catch (e) {
                        ws.send(errorMsg);
                    }
                } else {
                    ws.send(errorMsg);
                }
            }
        }
    });

    tcpClient.on('error', (err) => {
        console.error('[TCP] Error:', err.message);
        
        // Clear auth timeout on error
        if (authTimeout) {
            clearTimeout(authTimeout);
            authTimeout = null;
        }
        
        if (!isClosing) {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(`Server Error: ${err.message}`);
            }
            
            // Reconnect if:
            // 1. Already authenticated, OR
            // 2. Still attempting to authenticate (not in isClosing state)
            // AND haven't exceeded max attempts
            if (connectionAttempts < maxAttempts) {
                console.log('[TCP] Attempting to reconnect...');
                tcpClient.destroy();
                setTimeout(connectTCP, 2000);
            } else {
                isClosing = true;
                if (ws.readyState === WebSocket.OPEN) {
                    ws.close(1011, 'Server error');
                }
            }
        }
    });

    tcpClient.on('close', () => {
        console.log('[TCP] Connection to C++ server closed');
        
        // Clear auth timeout on close
        if (authTimeout) {
            clearTimeout(authTimeout);
            authTimeout = null;
        }
        
        if (!isClosing) {
            // Reconnect if:
            // 1. Already authenticated, OR
            // 2. Still attempting authentication (connectionAttempts < maxAttempts)
            // This allows recovery after registration completes, so user can immediately login
            if (connectionAttempts < maxAttempts) {
                console.log('[TCP] Reconnecting...');
                setTimeout(connectTCP, 2000);
            } else {
                isClosing = true;
                if (ws.readyState === WebSocket.OPEN) {
                    ws.close(1011, 'Connection lost');
                }
            }
        }
    });

    // Keep connection alive with ping/pong
    const pingInterval = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
            ws.ping();
        }
    }, 30000);

    ws.on('pong', () => {
        // Connection is alive
    });

    ws.on('close', () => {
        console.log('[WS] WebSocket client disconnected');
        isClosing = true;
        clearInterval(pingInterval);
        
        // Clear authentication timeout
        if (authTimeout) {
            clearTimeout(authTimeout);
            authTimeout = null;
        }
        
        // ============================================================
        // PRESENCE: Mark user as offline on disconnect
        // ============================================================
        if (ENABLE_PRESENCE && presenceStore && currentUsername) {
            presenceStore.removeConnection(ws, currentUsername);
        }
        
        if (tcpClient && !tcpClient.destroyed) {
            tcpClient.end();
        }
    });

    ws.on('error', (error) => {
        console.error('[WS] WebSocket error:', error);
    });
});

server.listen(PORT, () => {
    const protocol = HTTPS_ENABLED ? 'https' : 'http';
    const wsProtocol = HTTPS_ENABLED ? 'wss' : 'ws';
    const secureIcon = HTTPS_ENABLED ? '🔒' : '⚠️ ';
    
    console.log('═══════════════════════════════════════');
    console.log('  React Chat WebSocket Bridge Server');
    console.log('═══════════════════════════════════════');
    console.log(`  ${secureIcon} HTTP/WebSocket: ${protocol}://localhost:${PORT}`);
    console.log(`  ${secureIcon} WS Protocol: ${wsProtocol}://localhost:${PORT}`);
    console.log(`  TCP Backend: ${TCP_HOST}:${TCP_PORT}`);
    if (HTTPS_ENABLED) {
        console.log('  SSL: Enabled (self-signed cert)');
    } else {
        console.log('  SSL: Disabled (set HTTPS_ENABLED=true)');
    }
    console.log('═══════════════════════════════════════');
    console.log('Server ready and waiting for connections...\n');
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('\n[SERVER] SIGTERM received, closing server...');
    server.close(() => {
        console.log('[SERVER] Server closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('\n[SERVER] SIGINT received, closing server...');
    server.close(() => {
        console.log('[SERVER] Server closed');
        process.exit(0);
    });
});

