import { createContext, useContext, useState, useEffect, useMemo } from 'react'
import { useWebSocket } from './WebSocketContext'

const ChatContext = createContext(null)

export const useChat = () => {
  const context = useContext(ChatContext)
  if (!context) {
    throw new Error('useChat must be used within ChatProvider')
  }
  return context
}

export const ChatProvider = ({ children }) => {
  const { messages: wsMessages, presenceMap, presenceEnabled, getPresence } = useWebSocket()
  const [selectedContact, setSelectedContact] = useState(null)
  const [privateMessages, setPrivateMessages] = useState({})
  const [broadcastMessages, setBroadcastMessages] = useState([])
  const [contacts, setContacts] = useState([
    { id: 0, username: 'AI Assistant', online: true, lastSeen: null, isAI: true }
  ])
  const [historyLoaded, setHistoryLoaded] = useState({
    private: {},
    broadcast: false
  })

  // Fetch all users from the server
  const fetchUsers = async () => {
    try {
      const response = await fetch('/api/users')
      const data = await response.json()
      
      if (data.success && data.users) {
        const currentUser = sessionStorage.getItem('currentUser')
        
        // Convert usernames to contact objects, excluding current user
        const userContacts = data.users
          .filter(username => username.toLowerCase() !== currentUser?.toLowerCase())
          .map((username, index) => ({
            id: index + 1,
            username: username,
            online: false,
            lastSeen: null
          }))
        
        // Add AI Assistant at the beginning
        setContacts([
          { id: 0, username: 'AI Assistant', online: true, lastSeen: null, isAI: true },
          ...userContacts
        ])
        
        console.log('[ChatContext] Loaded users:', userContacts.map(c => c.username))
      }
    } catch (error) {
      console.error('[ChatContext] Error fetching users:', error)
      // Keep default contacts on error
    }
  }

  // Fetch users on mount and when user logs in
  useEffect(() => {
    const currentUser = sessionStorage.getItem('currentUser')
    if (currentUser) {
      fetchUsers()
    }
  }, [])

  useEffect(() => {
    if (!wsMessages.length) return

    const currentUser = sessionStorage.getItem('currentUser')
    if (!currentUser) return

    const lastMessage = wsMessages[wsMessages.length - 1]
    const data = lastMessage.data

    console.log('[ChatContext] Processing message:', data)

    // Handle private messages - try multiple formats
    // Format 1: [Private from username]: message
    let privateMatch = data.match(/\[Private from (\w+)\]: (.+)/)
    // Format 2: [username] (to you): message
    if (!privateMatch) {
      privateMatch = data.match(/\[(\w+)\] \(to you\): (.+)/)
    }
    // Format 3: Private message from username: message
    if (!privateMatch) {
      privateMatch = data.match(/Private message from (\w+): (.+)/)
    }
    
    if (privateMatch) {
      const [, sender, content] = privateMatch
      const contactKey = sender.toLowerCase()
      
      // Don't add our own sent messages (they're added by MessageInput)
      if (sender.toLowerCase() !== currentUser.toLowerCase()) {
        console.log('[ChatContext] Private message from:', sender)
        
        setPrivateMessages(prev => ({
          ...prev,
          [contactKey]: [
            ...(prev[contactKey] || []),
            {
              id: Date.now() + Math.random(), // Ensure unique ID
              sender,
              content,
              text: content,
              timestamp: new Date().toISOString(),
              read: false,
              isSent: false,
              status: 'received'
            }
          ]
        }))
      }
      return
    }

    // Handle broadcast messages - try multiple formats
    // Format 1: [Broadcast from username]: message
    let broadcastMatch = data.match(/\[Broadcast from (\w+)\]: (.+)/)
    // Format 2: [username]: message (regular format)
    if (!broadcastMatch) {
      broadcastMatch = data.match(/^\[(\w+)\]: (.+)/)
    }
    
    if (broadcastMatch) {
      const [, sender, content] = broadcastMatch
      
      // Don't add our own sent messages (they're added by MessageInput)
      // Also skip system messages
      if (sender.toLowerCase() !== currentUser.toLowerCase() && !data.includes('SYSTEM')) {
        console.log('[ChatContext] Broadcast message from:', sender)
        
        setBroadcastMessages(prev => [
          ...prev,
          {
            id: Date.now() + Math.random(), // Ensure unique ID
            sender,
            content,
            text: content,
            timestamp: new Date().toISOString(),
            isSent: false,
            status: 'received'
          }
        ])
      }
      return
    }

    // Handle system messages
    if (data.includes('joined the chat') || data.includes('left the chat')) {
      const usernameMatch = data.match(/(\w+) has (joined|left)/)
      if (usernameMatch) {
        const [, username, action] = usernameMatch
        console.log('[ChatContext] User', username, action)
        setContacts(prev =>
          prev.map(c =>
            c.username === username
              ? { ...c, online: action === 'joined', lastSeen: new Date().toISOString() }
              : c
          )
        )
      }
    }
  }, [wsMessages])

  const addPrivateMessage = (contact, content) => {
    const contactKey = contact.toLowerCase()
    const currentUser = sessionStorage.getItem('currentUser')
    
    setPrivateMessages(prev => ({
      ...prev,
      [contactKey]: [
        ...(prev[contactKey] || []),
        {
          id: Date.now(),
          sender: currentUser,
          content,
          text: content,
          timestamp: new Date().toISOString(),
          read: null,
          isSent: true,
          status: 'sent'
        }
      ]
    }))
  }

  const addBroadcastMessage = (content) => {
    const currentUser = sessionStorage.getItem('currentUser')
    
    setBroadcastMessages(prev => [
      ...prev,
      {
        id: Date.now(),
        sender: currentUser,
        content,
        text: content,
        timestamp: new Date().toISOString(),
        isSent: true,
        status: 'sent'
      }
    ])
  }

  const loadChatHistory = async (contact) => {
    const currentUser = sessionStorage.getItem('currentUser')
    if (!currentUser || !contact) return

    const contactKey = contact.toLowerCase()
    
    // Check if already loaded
    if (historyLoaded.private[contactKey]) {
      console.log('[ChatContext] History already loaded for', contact)
      return
    }

    try {
      console.log('[ChatContext] Loading chat history with', contact)
      const response = await fetch(`/api/history/${currentUser}/${contact}`)
      const data = await response.json()

      if (data.success && data.messages) {
        // Convert Supabase messages to app format
        const formattedMessages = data.messages.map(msg => ({
          id: msg.id,
          sender: msg.sender,
          content: msg.message,
          text: msg.message,
          timestamp: msg.timestamp,
          read: msg.is_read,
          isSent: msg.sender === currentUser,
          status: msg.sender === currentUser ? 'sent' : 'received'
        }))

        setPrivateMessages(prev => ({
          ...prev,
          [contactKey]: formattedMessages
        }))

        setHistoryLoaded(prev => ({
          ...prev,
          private: { ...prev.private, [contactKey]: true }
        }))

        console.log('[ChatContext] Loaded', formattedMessages.length, 'messages')
      }
    } catch (error) {
      console.error('[ChatContext] Error loading chat history:', error)
    }
  }

  const loadBroadcastHistory = async () => {
    // Check if already loaded
    if (historyLoaded.broadcast) {
      console.log('[ChatContext] Broadcast history already loaded')
      return
    }

    try {
      console.log('[ChatContext] Loading broadcast history')
      const response = await fetch('/api/history/broadcast')
      const data = await response.json()

      if (data.success && data.messages) {
        const currentUser = sessionStorage.getItem('currentUser')
        
        // Convert Supabase messages to app format
        const formattedMessages = data.messages.map(msg => ({
          id: msg.id,
          sender: msg.sender,
          content: msg.message,
          text: msg.message,
          timestamp: msg.timestamp,
          isSent: msg.sender === currentUser,
          status: msg.sender === currentUser ? 'sent' : 'received'
        }))

        setBroadcastMessages(formattedMessages)
        
        setHistoryLoaded(prev => ({
          ...prev,
          broadcast: true
        }))

        console.log('[ChatContext] Loaded', formattedMessages.length, 'broadcast messages')
      }
    } catch (error) {
      console.error('[ChatContext] Error loading broadcast history:', error)
    }
  }

  const markAsRead = async (sender) => {
    const currentUser = sessionStorage.getItem('currentUser')
    if (!currentUser || !sender) return

    try {
      await fetch('/api/messages/read', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sender, recipient: currentUser })
      })

      // Update local state to mark messages as read
      const contactKey = sender.toLowerCase()
      setPrivateMessages(prev => ({
        ...prev,
        [contactKey]: (prev[contactKey] || []).map(msg =>
          msg.sender === sender ? { ...msg, read: true } : msg
        )
      }))

      console.log('[ChatContext] Marked messages from', sender, 'as read')
    } catch (error) {
      console.error('[ChatContext] Error marking messages as read:', error)
    }
  }

  // ============================================================================
  // PRESENCE: Merge contacts with presence data
  // ============================================================================
  const contactsWithPresence = useMemo(() => {
    if (!presenceEnabled) return contacts
    
    return contacts.map(contact => {
      // AI Assistant is always online
      if (contact.isAI) return contact
      
      const presence = getPresence(contact.username)
      return {
        ...contact,
        online: presence.status === 'online',
        idle: presence.status === 'idle',
        lastSeen: presence.lastSeen || contact.lastSeen,
        presenceStatus: presence.status // 'online', 'offline', 'idle', 'unknown'
      }
    })
  }, [contacts, presenceMap, presenceEnabled, getPresence])

  const value = {
    selectedContact,
    setSelectedContact,
    privateMessages,
    broadcastMessages,
    contacts: contactsWithPresence, // Use contacts with presence data
    addPrivateMessage,
    addBroadcastMessage,
    loadChatHistory,
    loadBroadcastHistory,
    markAsRead,
    refreshContacts: fetchUsers,
    // Presence helpers
    presenceEnabled,
    getPresence
  }

  return <ChatContext.Provider value={value}>{children}</ChatContext.Provider>
}
