/**
 * Presence Store Module
 * 
 * Isolated, in-memory presence tracking for real-time online/offline status.
 * Feature-flagged via ENABLE_PRESENCE environment variable.
 * 
 * @module utils/presenceStore
 */

// Feature toggle - default to false for backwards compatibility
const ENABLE_PRESENCE = process.env.ENABLE_PRESENCE === 'true';

// Presence status enum
const PresenceStatus = {
    ONLINE: 'online',
    OFFLINE: 'offline',
    IDLE: 'idle',
    UNKNOWN: 'unknown'
};

// Configuration
const CONFIG = {
    // How long before a user is considered offline if no heartbeat received
    HEARTBEAT_TIMEOUT_MS: 45000, // 45 seconds (heartbeat should come every 20s)
    // How long before a user is considered idle
    IDLE_TIMEOUT_MS: 300000, // 5 minutes
    // Cleanup interval for stale entries
    CLEANUP_INTERVAL_MS: 60000, // 1 minute
};

/**
 * In-memory presence store
 * Map<userId, PresenceEntry>
 */
const presenceMap = new Map();

/**
 * WebSocket connections per user (for broadcasting)
 * Map<userId, Set<WebSocket>>
 */
const userConnections = new Map();

/**
 * All active WebSocket connections (for broadcasting to everyone)
 * Set<WebSocket>
 */
const allConnections = new Set();

/**
 * Presence entry structure
 * @typedef {Object} PresenceEntry
 * @property {string} userId - User identifier
 * @property {string} status - online|offline|idle
 * @property {string} lastSeen - ISO8601 timestamp
 * @property {string} lastHeartbeat - ISO8601 timestamp of last heartbeat
 */

/**
 * Check if presence feature is enabled
 * @returns {boolean}
 */
function isEnabled() {
    return ENABLE_PRESENCE;
}

/**
 * Set user as online
 * @param {string} userId - User identifier
 * @param {WebSocket} ws - WebSocket connection (optional, for broadcasting)
 * @returns {boolean} Success
 */
function setOnline(userId, ws = null) {
    if (!ENABLE_PRESENCE || !userId) return false;
    
    const now = new Date().toISOString();
    const previousStatus = presenceMap.get(userId)?.status;
    
    presenceMap.set(userId, {
        userId,
        status: PresenceStatus.ONLINE,
        lastSeen: now,
        lastHeartbeat: now
    });
    
    // Track WebSocket connection
    if (ws) {
        if (!userConnections.has(userId)) {
            userConnections.set(userId, new Set());
        }
        userConnections.get(userId).add(ws);
        allConnections.add(ws);
    }
    
    console.log(`[PRESENCE] ✓ ${userId} is now ONLINE`);
    
    // Broadcast presence change if status actually changed
    if (previousStatus !== PresenceStatus.ONLINE) {
        broadcastPresence(userId, PresenceStatus.ONLINE);
    }
    
    return true;
}

/**
 * Set user as offline
 * @param {string} userId - User identifier
 * @param {WebSocket} ws - WebSocket connection to remove (optional)
 * @returns {boolean} Success
 */
function setOffline(userId, ws = null) {
    if (!ENABLE_PRESENCE || !userId) return false;
    
    const now = new Date().toISOString();
    
    // Remove WebSocket from tracking
    if (ws) {
        allConnections.delete(ws);
        if (userConnections.has(userId)) {
            userConnections.get(userId).delete(ws);
            // Only set offline if no more connections for this user
            if (userConnections.get(userId).size > 0) {
                console.log(`[PRESENCE] ${userId} still has ${userConnections.get(userId).size} active connection(s)`);
                return true;
            }
            userConnections.delete(userId);
        }
    }
    
    const previousStatus = presenceMap.get(userId)?.status;
    
    presenceMap.set(userId, {
        userId,
        status: PresenceStatus.OFFLINE,
        lastSeen: now,
        lastHeartbeat: now
    });
    
    console.log(`[PRESENCE] ✓ ${userId} is now OFFLINE`);
    
    // Broadcast presence change if status actually changed
    if (previousStatus !== PresenceStatus.OFFLINE) {
        broadcastPresence(userId, PresenceStatus.OFFLINE);
    }
    
    return true;
}

/**
 * Set user as idle
 * @param {string} userId - User identifier
 * @returns {boolean} Success
 */
function setIdle(userId) {
    if (!ENABLE_PRESENCE || !userId) return false;
    
    const entry = presenceMap.get(userId);
    if (!entry || entry.status === PresenceStatus.OFFLINE) {
        return false; // Can't go idle if offline
    }
    
    const now = new Date().toISOString();
    const previousStatus = entry.status;
    
    presenceMap.set(userId, {
        ...entry,
        status: PresenceStatus.IDLE,
        lastSeen: now
    });
    
    console.log(`[PRESENCE] ${userId} is now IDLE`);
    
    // Broadcast presence change if status actually changed
    if (previousStatus !== PresenceStatus.IDLE) {
        broadcastPresence(userId, PresenceStatus.IDLE);
    }
    
    return true;
}

/**
 * Update heartbeat for user (keeps them online)
 * @param {string} userId - User identifier
 * @returns {boolean} Success
 */
function heartbeat(userId) {
    if (!ENABLE_PRESENCE || !userId) return false;
    
    const entry = presenceMap.get(userId);
    if (!entry) {
        // User not in presence store, add them as online
        return setOnline(userId);
    }
    
    const now = new Date().toISOString();
    const wasIdle = entry.status === PresenceStatus.IDLE;
    
    presenceMap.set(userId, {
        ...entry,
        status: PresenceStatus.ONLINE,
        lastHeartbeat: now,
        lastSeen: now
    });
    
    // If they were idle, broadcast they're back online
    if (wasIdle) {
        console.log(`[PRESENCE] ${userId} is back ONLINE from IDLE`);
        broadcastPresence(userId, PresenceStatus.ONLINE);
    }
    
    return true;
}

/**
 * Get presence for a specific user
 * @param {string} userId - User identifier
 * @returns {PresenceEntry|null}
 */
function get(userId) {
    if (!ENABLE_PRESENCE) return null;
    return presenceMap.get(userId) || {
        userId,
        status: PresenceStatus.UNKNOWN,
        lastSeen: null,
        lastHeartbeat: null
    };
}

/**
 * Get all presence entries
 * @returns {Object} Map of userId -> PresenceEntry
 */
function getAll() {
    if (!ENABLE_PRESENCE) return {};
    
    const result = {};
    presenceMap.forEach((entry, key) => {
        result[key] = entry;
    });
    return result;
}

/**
 * Get presence snapshot for synchronization
 * @returns {Array<PresenceEntry>}
 */
function getSnapshot() {
    if (!ENABLE_PRESENCE) return [];
    return Array.from(presenceMap.values());
}

/**
 * Broadcast presence update to all connected clients
 * @param {string} userId - User whose status changed
 * @param {string} status - New status
 */
function broadcastPresence(userId, status) {
    if (!ENABLE_PRESENCE) return;
    
    const presenceEvent = {
        type: 'PRESENCE',
        action: status.toUpperCase(),
        userId,
        timestamp: new Date().toISOString()
    };
    
    const message = `PRESENCE:${JSON.stringify(presenceEvent)}`;
    let sentCount = 0;
    
    allConnections.forEach(ws => {
        try {
            if (ws.readyState === 1) { // WebSocket.OPEN
                ws.send(message);
                sentCount++;
            }
        } catch (err) {
            console.error(`[PRESENCE] Broadcast error:`, err.message);
        }
    });
    
    console.log(`[PRESENCE] Broadcast ${userId}:${status} to ${sentCount} clients`);
}

/**
 * Send presence snapshot to a specific connection
 * @param {WebSocket} ws - WebSocket connection
 */
function sendSnapshot(ws) {
    if (!ENABLE_PRESENCE) return;
    
    try {
        const snapshot = getSnapshot();
        const message = `PRESENCE_SNAPSHOT:${JSON.stringify(snapshot)}`;
        
        if (ws.readyState === 1) { // WebSocket.OPEN
            ws.send(message);
            console.log(`[PRESENCE] Sent snapshot with ${snapshot.length} entries`);
        }
    } catch (err) {
        console.error(`[PRESENCE] Snapshot send error:`, err.message);
    }
}

/**
 * Remove a WebSocket connection (on disconnect)
 * @param {WebSocket} ws - WebSocket connection
 * @param {string} userId - User identifier (optional)
 */
function removeConnection(ws, userId = null) {
    if (!ENABLE_PRESENCE) return;
    
    allConnections.delete(ws);
    
    if (userId && userConnections.has(userId)) {
        userConnections.get(userId).delete(ws);
        if (userConnections.get(userId).size === 0) {
            userConnections.delete(userId);
            setOffline(userId);
        }
    }
}

/**
 * Cleanup stale presence entries
 * Called periodically to mark users as offline if heartbeat expired
 */
function cleanup() {
    if (!ENABLE_PRESENCE) return;
    
    const now = Date.now();
    let cleanedCount = 0;
    
    presenceMap.forEach((entry, userId) => {
        if (entry.status === PresenceStatus.OFFLINE) return;
        
        const lastHeartbeat = new Date(entry.lastHeartbeat).getTime();
        const elapsed = now - lastHeartbeat;
        
        // Check for heartbeat timeout
        if (elapsed > CONFIG.HEARTBEAT_TIMEOUT_MS) {
            console.log(`[PRESENCE] ${userId} heartbeat timeout (${Math.round(elapsed/1000)}s)`);
            setOffline(userId);
            cleanedCount++;
        }
        // Check for idle timeout (only if still online)
        else if (entry.status === PresenceStatus.ONLINE && elapsed > CONFIG.IDLE_TIMEOUT_MS) {
            setIdle(userId);
        }
    });
    
    if (cleanedCount > 0) {
        console.log(`[PRESENCE] Cleanup: marked ${cleanedCount} users as offline`);
    }
}

// Start cleanup interval if presence is enabled
let cleanupInterval = null;
if (ENABLE_PRESENCE) {
    cleanupInterval = setInterval(cleanup, CONFIG.CLEANUP_INTERVAL_MS);
    console.log('[PRESENCE] ✓ Presence store initialized');
    console.log(`[PRESENCE]   Heartbeat timeout: ${CONFIG.HEARTBEAT_TIMEOUT_MS/1000}s`);
    console.log(`[PRESENCE]   Idle timeout: ${CONFIG.IDLE_TIMEOUT_MS/1000}s`);
}

// Export
export {
    PresenceStatus,
    CONFIG,
    isEnabled,
    setOnline,
    setOffline,
    setIdle,
    heartbeat,
    get,
    getAll,
    getSnapshot,
    broadcastPresence,
    sendSnapshot,
    removeConnection,
    cleanup
};

export default {
    PresenceStatus,
    CONFIG,
    isEnabled,
    setOnline,
    setOffline,
    setIdle,
    heartbeat,
    get,
    getAll,
    getSnapshot,
    broadcastPresence,
    sendSnapshot,
    removeConnection,
    cleanup
};
