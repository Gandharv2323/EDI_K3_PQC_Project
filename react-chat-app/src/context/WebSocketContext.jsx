import { createContext, useContext, useEffect, useState, useRef } from 'react'
import { encryptAES_GCM, decryptAES_GCM } from '../utils/crypto'

const WebSocketContext = createContext(null)

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
  const wsRef = useRef(null)
  const reconnectTimeoutRef = useRef(null)
  const reconnectAttempts = useRef(0)
  const maxReconnectAttempts = 3
  const wsSessionKey = useRef(null) // WebSocket encryption key
  const encryptionEnabled = useRef(false)
  const isAuthenticatedRef = useRef(false) // Ref to avoid stale closure in useEffect
  const decryptionFailureCount = useRef(0) // Track consecutive decryption failures
  const MAX_DECRYPTION_FAILURES = 3 // Threshold before invalidating session

  useEffect(() => {
    let isSubscribed = true
    
    const connectWebSocket = () => {
      if (!isSubscribed) return
      // WebSocket URL from environment variable (supports ws:// and wss://)
      // DefinePlugin replaces process.env.REACT_APP_WS_URL at build time
      const wsUrl = process.env.REACT_APP_WS_URL || 'ws://localhost:5000'
      console.log('[WS] Connecting to:', wsUrl)

      const socket = new WebSocket(wsUrl)
      wsRef.current = socket

      socket.onopen = () => {
        console.log('[WS] ✅ Connected successfully')
        setIsConnected(true)
        setWs(socket)
        reconnectAttempts.current = 0
        
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
      
      function processMessage(data) {
        console.log('[WS] Received:', data)
        
        // Track authentication status
        if (data.includes('Authentication successful')) {
          setIsAuthenticated(true)
          isAuthenticatedRef.current = true // Update ref to avoid stale closure
          console.log('[WS] 🔐 Authentication confirmed')
        }
        
        // Detect timeout from server
        if (data.includes('Authentication timed out') || data.includes('Error: Authentication timed out')) {
          console.log('[WS] ⏱️ Server reported authentication timeout')
          setIsAuthenticated(false)
          isAuthenticatedRef.current = false // Update ref to avoid stale closure
        }
        
        setMessages(prev => [...prev, { data, timestamp: new Date() }])
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
    clearEncryptionError: () => setEncryptionError(null)
  }

  return (
    <WebSocketContext.Provider value={value}>
      {children}
    </WebSocketContext.Provider>
  )
}
