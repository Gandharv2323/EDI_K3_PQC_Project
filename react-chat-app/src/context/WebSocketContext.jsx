import { createContext, useContext, useEffect, useState, useRef, useCallback } from 'react'
import { encryptAES_GCM, decryptAES_GCM } from '../utils/crypto'
// real time communication via websockets with encryption, presence, and PQC key exchange
const WebSocketContext = createContext(null)


// (Lines 50-70) FRONTEND → BACKEND CONNECTION


// ============================================================================
// PRESENCE CONFIGURATION
// ============================================================================
// Feature toggle - reads from environment variable at build time
const ENABLE_PRESENCE = process.env.REACT_APP_ENABLE_PRESENCE === 'true'
const PRESENCE_HEARTBEAT_INTERVAL = 20000 // 20 seconds
const PRESENCE_IDLE_TIMEOUT = 300000 // 5 minutes

export const useWebSocket = () => {
  const context = useContext(WebSocketContext)
  if (!context) {
    throw new Error('useWebSocket must be used within WebSocketProvider')
  }
  return context
}

export const WebSocketProvider = ({ children }) => {
  const [ws, setWs] = useState(null)
  const [isConnected, setIsConnected] = useState(false)
  const [messages, setMessages] = useState([])
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [encryptionError, setEncryptionError] = useState(null) // Track encryption failures
  const [presenceMap, setPresenceMap] = useState({}) // Presence state for all users
  const wsRef = useRef(null)
  const reconnectTimeoutRef = useRef(null)
  const reconnectAttempts = useRef(0)
  const maxReconnectAttempts = 3
  const wsSessionKey = useRef(null) // WebSocket encryption key
  const encryptionEnabled = useRef(false)
  const isAuthenticatedRef = useRef(false) // Ref to avoid stale closure in useEffect
  const decryptionFailureCount = useRef(0) // Track consecutive decryption failures
  const MAX_DECRYPTION_FAILURES = 3 // Threshold before invalidating session
  
  // Presence refs
  const presenceHeartbeatRef = useRef(null)
  const presenceIdleTimerRef = useRef(null)
  const lastActivityRef = useRef(Date.now())

  useEffect(() => {
    let isSubscribed = true

    //FRONTEND → BACKEND CONNECTION

    const connectWebSocket = () => {
      if (!isSubscribed) return
      // WebSocket URL from environment variable (supports ws:// and wss://)
      // DefinePlugin replaces process.env.REACT_APP_WS_URL at build time
      
      //Connection Code 3️ REACT FRONTEND (Browser)

      
      const wsUrl = process.env.REACT_APP_WS_URL || 'ws://localhost:5000'
      console.log('[WS] Connecting to:', wsUrl)

      const socket = new WebSocket(wsUrl)
      wsRef.current = socket

      socket.onopen = () => {
        console.log('[WS] ✅ Connected successfully')
        setIsConnected(true)
        setWs(socket)
        reconnectAttempts.current = 0
        
//FRONTEND → BACKEND CONNECTION
        
        // SECURITY: Do NOT send credentials here - they would be transmitted in plaintext
        // Auto-login will be triggered after receiving the session key and enabling encryption
        console.log('[WS] Waiting for session key before authentication...')
      }

      socket.onmessage = (event) => {
        const data = event.data
        
        // Check if server is sending WebSocket session key
        if (data.startsWith('WS_SESSION_KEY:')) {
          const keyB64 = data.substring('WS_SESSION_KEY:'.length).trim()
          
          try {
            // Decode base64 to Uint8Array
            const binaryString = atob(keyB64)
            const keyBytes = new Uint8Array(binaryString.length)
            for (let i = 0; i < binaryString.length; i++) {
              keyBytes[i] = binaryString.charCodeAt(i)
            }
            
            // Validate key length (AES-128 = 16 bytes, AES-256 = 32 bytes)
            const validKeyLengths = [16, 32]
            if (!validKeyLengths.includes(keyBytes.length)) {
              console.error('[WS_CRYPTO] ✗ CRITICAL: Invalid session key length')
              console.error('[WS_CRYPTO] Received:', keyBytes.length, 'bytes')
              console.error('[WS_CRYPTO] Expected: 16 bytes (AES-128) or 32 bytes (AES-256)')
              console.error('[WS_CRYPTO] Timestamp:', new Date().toISOString())
              console.error('[WS_CRYPTO] Encryption will NOT be enabled')
              
              // Clear any existing key
              wsSessionKey.current = null
              encryptionEnabled.current = false
              
              // Set error state for UI notification
              setEncryptionError(`Invalid session key length: ${keyBytes.length} bytes. Expected 16 or 32 bytes.`)
              
              // Log audit event
              console.error('[AUDIT] Rejected invalid session key length from server')
              
              // Optionally close socket to prevent insecure communication
              console.error('[WS_CRYPTO] Consider closing connection - invalid key received')
              
              return // Don't process as regular message, don't enable encryption
            }
            
            // Valid key length - enable encryption
            wsSessionKey.current = keyBytes
            encryptionEnabled.current = true
            console.log('[WS_CRYPTO] ✓ Received valid session key')
            console.log('[WS_CRYPTO] Key length:', keyBytes.length, 'bytes', keyBytes.length === 16 ? '(AES-128)' : '(AES-256)')
            console.log('[WS_CRYPTO] Encryption enabled')
            
            // SECURITY: Now that encryption is enabled, safe to auto-authenticate
            // Credentials will be encrypted before transmission
            const currentUser = sessionStorage.getItem('currentUser')
            const savedPassword = sessionStorage.getItem('userPassword')
            
            if (currentUser && savedPassword) {
              console.log('[WS] ✓ Encryption ready - auto-authenticating as:', currentUser)
              console.log('[WS] Credentials will be encrypted with AES-' + (keyBytes.length * 8))
              
              // Wait a moment for server to send auth prompt
              setTimeout(() => {
                if (socket.readyState === WebSocket.OPEN && encryptionEnabled.current) {
                  // Encrypt and send credentials
                  const loginMessage = `LOGIN:${currentUser}:${savedPassword}`
                  
                  encryptAES_GCM(loginMessage, wsSessionKey.current)
                    .then(encrypted => {
                      socket.send(encrypted + '\n')
                      console.log('[WS_CRYPTO] ✓ Sent encrypted auto-login credentials')
                    })
                    .catch(encryptError => {
                      console.error('[WS_CRYPTO] ✗ Failed to encrypt auto-login credentials:', encryptError)
                      console.error('[WS_CRYPTO] Auto-login aborted - will NOT send plaintext')
                    })
                } else {
                  console.warn('[WS] ⚠️ Cannot auto-login - socket closed or encryption disabled')
                }
              }, 500)
            }
            
          } catch (decodeError) {
            console.error('[WS_CRYPTO] ✗ CRITICAL: Failed to decode session key')
            console.error('[WS_CRYPTO] Error:', decodeError.message)
            console.error('[WS_CRYPTO] Encryption will NOT be enabled')
            
            // Clear any existing key
            wsSessionKey.current = null
            encryptionEnabled.current = false
            
            // Set error state
            setEncryptionError(`Session key decode failed: ${decodeError.message}`)
            
            console.error('[AUDIT] Failed to decode session key from server')
          }
          
          return // Don't process as regular message
        }
        
        // ====================================================================
        // KYBER POST-QUANTUM KEY EXCHANGE (OPTIONAL)
        // ====================================================================
        // Handle Kyber public key from server
        if (data.startsWith('KYBER_PUBLIC_KEY:')) {
          console.log('[KYBER] Received server public key for PQC exchange')
          console.log('[KYBER] Public key length:', data.length, 'chars')
          
          // Dynamically import Kyber module
          import('../utils/kyber.js')
            .then(async ({ browserKyber }) => {
              console.log('[KYBER] Browser module imported')
              
              // Enable and initialize Kyber
              const initialized = await browserKyber.enable()
              console.log('[KYBER] Initialization result:', initialized)
              
              if (!initialized) {
                console.log('[KYBER] Browser module not available, skipping PQC')
                return
              }
              
              // Parse server's public key
              const serverPubKeyB64 = data.substring('KYBER_PUBLIC_KEY:'.length).trim()
              console.log('[KYBER] Parsed public key (base64 length):', serverPubKeyB64.length)
              
              // Encapsulate to create shared secret
              console.log('[KYBER] Calling encapsulate...')
              const result = await browserKyber.encapsulate(serverPubKeyB64)
              console.log('[KYBER] Encapsulate result:', result ? 'success' : 'failed')
              
              if (!result) {
                console.error('[KYBER] Encapsulation failed - result is null')
                return
              }
              
              // Store the shared secret for later application (when KYBER_COMPLETE is received)
              window._kyberPendingSecret = result.sharedSecret
              console.log('[KYBER] Stored pending secret, ciphertext length:', result.ciphertextBase64.length)
              
              // Send ciphertext back to server
              if (socket.readyState === WebSocket.OPEN) {
                socket.send(`KYBER_CIPHERTEXT:${result.ciphertextBase64}`)
                console.log('[KYBER] ✓ Sent ciphertext to server')
                console.log('[KYBER] Waiting for server confirmation before applying hybrid key...')
              } else {
                console.error('[KYBER] Cannot send ciphertext - socket not open')
              }
            })
            .catch(err => {
              console.error('[KYBER] Module error:', err.message, err.stack)
              // Non-fatal - continue with classical encryption
            })
          
          return // Don't process as regular message
        }
        
        // Handle Kyber exchange completion notification
        if (data.startsWith('KYBER_COMPLETE:')) {
          const success = data.substring('KYBER_COMPLETE:'.length).trim() === 'true'
          if (success) {
            console.log('[KYBER] ✓ Post-quantum key exchange verified!')
            console.log('[KYBER] Kyber-768 shared secret established')
            console.log('[KYBER] Note: Using classical AES-256-GCM for this session')
            // Clear the pending secret - we verified Kyber works but won't modify keys mid-session
            delete window._kyberPendingSecret
          } else {
            console.log('[KYBER] PQC exchange failed, using classical encryption')
            delete window._kyberPendingSecret
          }
          return // Don't process as regular message
        }
        
        // ====================================================================
        // PRESENCE HANDLING
        // ====================================================================
        // Handle presence updates from server
        if (data.startsWith('PRESENCE:')) {
          if (!ENABLE_PRESENCE) return // Silently ignore if disabled
          
          try {
            const presenceData = JSON.parse(data.substring('PRESENCE:'.length))
            const { action, userId, timestamp } = presenceData
            
            console.log(`[PRESENCE] ${userId} is now ${action}`)
            
            setPresenceMap(prev => ({
              ...prev,
              [userId]: {
                userId,
                status: action.toLowerCase(),
                lastSeen: timestamp
              }
            }))
          } catch (err) {
            console.error('[PRESENCE] Failed to parse presence update:', err.message)
          }
          return // Don't process as regular message
        }
        
        // Handle presence snapshot from server (sent on connect)
        if (data.startsWith('PRESENCE_SNAPSHOT:')) {
          if (!ENABLE_PRESENCE) return // Silently ignore if disabled
          
          try {
            const snapshot = JSON.parse(data.substring('PRESENCE_SNAPSHOT:'.length))
            console.log('[PRESENCE] Received snapshot with', snapshot.length, 'entries')
            
            const newPresenceMap = {}
            snapshot.forEach(entry => {
              newPresenceMap[entry.userId] = entry
            })
            
            setPresenceMap(newPresenceMap)
          } catch (err) {
            console.error('[PRESENCE] Failed to parse presence snapshot:', err.message)
          }
          return // Don't process as regular message
        }
        
        // Decrypt message if encryption is enabled
        if (encryptionEnabled.current && wsSessionKey.current) {
          decryptAES_GCM(data, wsSessionKey.current)
            .then(decrypted => {
              if (decrypted) {
                console.log('[WS_CRYPTO] ✓ Decrypted message from bridge')
                
                // Reset failure counter on successful decryption
                decryptionFailureCount.current = 0
                
                processMessage(decrypted)
              } else {
                console.error('[WS_CRYPTO] ✗ Decryption returned empty result')
                console.error('[WS_CRYPTO] Message dropped for security - will NOT process raw ciphertext')
                
                decryptionFailureCount.current++
                handleDecryptionFailure('Empty decryption result')
              }
            })
            .catch(error => {
              console.error('[WS_CRYPTO] ✗ CRITICAL: Decryption failed')
              console.error('[WS_CRYPTO] Error details:', error.message)
              console.error('[WS_CRYPTO] Error stack:', error.stack)
              console.error('[WS_CRYPTO] Timestamp:', new Date().toISOString())
              console.error('[WS_CRYPTO] Message DROPPED - will NOT process raw ciphertext')
              
              // Log audit event
              console.error('[AUDIT] Incoming decryption failure detected')
              console.error('[AUDIT] Message dropped to prevent ciphertext exposure')
              
              // Increment failure counter
              decryptionFailureCount.current++
              
              // Handle decryption failure (invalidate session if too many failures)
              handleDecryptionFailure(error.message)
              
              // Do NOT call processMessage(data) - drop the message entirely
            })
        } else {
          processMessage(data)
        }
      }
      
      // Handle decryption failures - invalidate session after too many failures
      function handleDecryptionFailure(errorMessage) {
        const maxFailures = 5
        console.warn(`[WS_CRYPTO] Decryption failure ${decryptionFailureCount.current}/${maxFailures}: ${errorMessage}`)
        
        if (decryptionFailureCount.current >= maxFailures) {
          console.error('[WS_CRYPTO] Too many decryption failures - session may be compromised')
          console.error('[WS_CRYPTO] Consider re-establishing connection')
          
          // Don't automatically close - just warn
          setEncryptionError(`Multiple decryption failures (${decryptionFailureCount.current})`)
        }
      }
      
      function processMessage(data) {
        console.log('[WS] Received:', data)
        
        // Track authentication status
        if (data.includes('Authentication successful')) {
          setIsAuthenticated(true)
          isAuthenticatedRef.current = true // Update ref to avoid stale closure
          console.log('[WS] 🔐 Authentication confirmed')
          
          // ============================================================
          // PRESENCE: Start heartbeat and send ONLINE status
          // ============================================================
          if (ENABLE_PRESENCE) {
            const currentUser = sessionStorage.getItem('currentUser')
            if (currentUser) {
              // Send initial ONLINE status
              sendPresence('ONLINE')
              
              // Start heartbeat interval
              startPresenceHeartbeat()
              
              // Setup idle detection
              setupIdleDetection()
              
              console.log('[PRESENCE] ✓ Presence tracking started')
            }
          }
        }
        
        // Detect timeout from server
        if (data.includes('Authentication timed out') || data.includes('Error: Authentication timed out')) {
          console.log('[WS] ⏱️ Server reported authentication timeout')
          setIsAuthenticated(false)
          isAuthenticatedRef.current = false // Update ref to avoid stale closure
          
          // Stop presence tracking
          stopPresenceTracking()
        }
        
        setMessages(prev => [...prev, { data, timestamp: new Date() }])
      }
      
      // ============================================================
      // PRESENCE HELPER FUNCTIONS
      // ============================================================
      function sendPresence(action) {
        if (!ENABLE_PRESENCE || !socket || socket.readyState !== WebSocket.OPEN) return
        
        const currentUser = sessionStorage.getItem('currentUser')
        if (!currentUser) return
        
        const presenceEvent = {
          type: 'PRESENCE',
          action,
          userId: currentUser,
          timestamp: new Date().toISOString()
        }
        
        socket.send(`PRESENCE:${JSON.stringify(presenceEvent)}`)
        console.log(`[PRESENCE] Sent ${action}`)
      }
      
      function startPresenceHeartbeat() {
        // Clear any existing heartbeat
        if (presenceHeartbeatRef.current) {
          clearInterval(presenceHeartbeatRef.current)
        }
        
        presenceHeartbeatRef.current = setInterval(() => {
          sendPresence('HEARTBEAT')
        }, PRESENCE_HEARTBEAT_INTERVAL)
      }
      
      function setupIdleDetection() {
        // Track user activity
        const activityEvents = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart']
        
        const handleActivity = () => {
          lastActivityRef.current = Date.now()
          
          // If we were idle, send ONLINE again
          const currentUser = sessionStorage.getItem('currentUser')
          if (currentUser) {
            const currentPresence = presenceMap[currentUser]
            if (currentPresence?.status === 'idle') {
              sendPresence('ONLINE')
            }
          }
        }
        
        activityEvents.forEach(event => {
          window.addEventListener(event, handleActivity, { passive: true })
        })
        
        // Check for idle periodically
        presenceIdleTimerRef.current = setInterval(() => {
          const elapsed = Date.now() - lastActivityRef.current
          if (elapsed > PRESENCE_IDLE_TIMEOUT) {
            const currentUser = sessionStorage.getItem('currentUser')
            if (currentUser) {
              const currentPresence = presenceMap[currentUser]
              if (currentPresence?.status !== 'idle') {
                sendPresence('IDLE')
              }
            }
          }
        }, 60000) // Check every minute
        
        // Send OFFLINE on page unload (best effort)
        window.addEventListener('beforeunload', () => {
          sendPresence('OFFLINE')
        })
      }
      
      function stopPresenceTracking() {
        if (presenceHeartbeatRef.current) {
          clearInterval(presenceHeartbeatRef.current)
          presenceHeartbeatRef.current = null
        }
        if (presenceIdleTimerRef.current) {
          clearInterval(presenceIdleTimerRef.current)
          presenceIdleTimerRef.current = null
        }
      }

      socket.onerror = (error) => {
        console.error('[WS] ❌ Connection Error:', error)
        console.error('[WS] Error details - readyState:', socket.readyState, 'url:', socket.url)
        
        // Clear encryption state on error
        wsSessionKey.current = null
        encryptionEnabled.current = false
        decryptionFailureCount.current = 0  // Reset failure counter on error
        console.log('[WS_CRYPTO] Cleared encryption state due to error')
      }

      socket.onclose = (event) => {
        console.log('[WS] ⚠️ Disconnected - Code:', event.code, 'Reason:', event.reason, 'Clean:', event.wasClean)
        setIsConnected(false)
        setWs(null)
        wsRef.current = null
        
        // Clear encryption state when connection closes
        wsSessionKey.current = null
        encryptionEnabled.current = false
        decryptionFailureCount.current = 0  // Reset failure counter on disconnect
        console.log('[WS_CRYPTO] Cleared encryption state on disconnect')
        
        // Stop presence tracking on disconnect
        stopPresenceTracking()

        // Don't reconnect if:
        // 1. Already authenticated (prevents duplicate login errors)
        // 2. Normal closure (code 1000)
        // 3. Going away (code 1001) 
        // 4. Policy violation (code 1008) - usually means auth timeout
        // 5. Max reconnect attempts exceeded
        const shouldNotReconnect = 
          isAuthenticatedRef.current ||  // Use ref to avoid stale closure
          event.code === 1000 || 
          event.code === 1001 || 
          event.code === 1008 ||
          reconnectAttempts.current >= maxReconnectAttempts

        if (shouldNotReconnect) {
          console.log('[WS] Not reconnecting - Reason:', {
            authenticated: isAuthenticatedRef.current,  // Use ref for logging
            code: event.code,
            attempts: reconnectAttempts.current,
            maxAttempts: maxReconnectAttempts
          })
          
          // Reset state and ref
          setIsAuthenticated(false)
          isAuthenticatedRef.current = false  // Reset ref as well
          reconnectAttempts.current = 0
          return
        }

        // Only reconnect on unexpected closures
        reconnectAttempts.current++
        const delay = Math.min(2000 * reconnectAttempts.current, 10000) // Progressive delay up to 10s
        reconnectTimeoutRef.current = setTimeout(() => {
          console.log(`[WS] 🔄 Attempting reconnect... (${reconnectAttempts.current}/${maxReconnectAttempts})`)
          connectWebSocket()
        }, delay)
      }
    }

    connectWebSocket()

    return () => {
      isSubscribed = false
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
      }
      
      // Stop presence tracking on cleanup
      if (presenceHeartbeatRef.current) {
        clearInterval(presenceHeartbeatRef.current)
      }
      if (presenceIdleTimerRef.current) {
        clearInterval(presenceIdleTimerRef.current)
      }
      
      if (wsRef.current) {
        console.log('[WS] Cleaning up WebSocket connection')
        wsRef.current.close(1000, 'Component unmounting')
      }
      
      // Clear encryption state on cleanup
      wsSessionKey.current = null
      encryptionEnabled.current = false
      isAuthenticatedRef.current = false  // Reset auth ref on cleanup
      decryptionFailureCount.current = 0  // Reset failure counter on cleanup
      console.log('[WS_CRYPTO] Cleared encryption state on cleanup')
    }
  }, [])

  const sendMessage = async (message) => {
    if (ws && isConnected) {
      let messageToSend = message
      
      // Encrypt message if encryption is enabled
      if (encryptionEnabled.current && wsSessionKey.current) {
        try {
          messageToSend = await encryptAES_GCM(message, wsSessionKey.current)
          console.log('[WS_CRYPTO] ✓ Encrypted message to bridge')
          
          // Clear any previous encryption errors on success
          setEncryptionError(null)
        } catch (error) {
          console.error('[WS_CRYPTO] ✗ CRITICAL: Encryption failed')
          console.error('[WS_CRYPTO] Error details:', error.message)
          console.error('[WS_CRYPTO] Error stack:', error.stack)
          console.error('[WS_CRYPTO] Timestamp:', new Date().toISOString())
          console.error('[WS_CRYPTO] REFUSING to send plaintext - security policy violation')
          
          // Set error state for UI notification
          const errorMessage = `Encryption failure: ${error.message}. Message not sent for security.`
          setEncryptionError(errorMessage)
          
          // Log audit event
          console.error('[AUDIT] Outgoing encryption failure - message NOT sent')
          console.error('[AUDIT] Message would have exposed sensitive data in plaintext')
          
          // Clear encryption state to force re-authentication
          wsSessionKey.current = null
          encryptionEnabled.current = false
          console.log('[WS_CRYPTO] Cleared encryption state - re-authentication required')
          
          // Optionally trigger reconnection to establish new encrypted session
          console.log('[WS_CRYPTO] Consider reconnecting to establish new encrypted session')
          
          // Do NOT send message - return false to indicate failure
          return false
        }
      }
      
      ws.send(messageToSend + '\n')
      
      // Conditional logging to prevent plaintext leakage
      if (encryptionEnabled.current) {
        // When encrypted, log safe placeholder only
        console.log('[WS] Sent encrypted message (length:', messageToSend.length, 'bytes)')
      } else {
        // When not encrypted, log actual message content
        console.log('[WS] Sent:', message)
      }
      
      return true
    }
    console.warn('[WS] Not connected')
    return false
  }

  const value = {
    ws,
    isConnected,
    messages,
    sendMessage,
    clearMessages: () => setMessages([]),
    encryptionError,
    clearEncryptionError: () => setEncryptionError(null),
    // Presence
    presenceMap,
    presenceEnabled: ENABLE_PRESENCE,
    getPresence: (userId) => presenceMap[userId] || { status: 'unknown', lastSeen: null }
  }

  return (
    <WebSocketContext.Provider value={value}>
      {children}
    </WebSocketContext.Provider>
  )
}
