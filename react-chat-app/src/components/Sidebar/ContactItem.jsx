import { useNavigate } from 'react-router-dom'
import { useChat } from '../../context/ChatContext'
import { formatDistanceToNow } from 'date-fns'
import Lottie from 'lottie-react'
import notificationAnimation from '../../../public/animations/notification.json'
import './ContactItem.css'

const ContactItem = ({ contact }) => {
  const navigate = useNavigate()
  const { selectedContact, setSelectedContact, privateMessages, presenceEnabled } = useChat()
  const isSelected = selectedContact?.id === contact.id

  const messages = privateMessages[contact.username.toLowerCase()] || []
  const lastMessage = messages[messages.length - 1]
  const unreadCount = messages.filter((m) => !m.read && !m.isSent).length

  const handleClick = () => {
    setSelectedContact(contact)
    // Route to AI chat for AI Assistant, otherwise private chat
    if (contact.isAI) {
      navigate('/chat/ai')
    } else {
      navigate('/chat/private')
    }
  }

  const getLastMessagePreview = () => {
    if (!lastMessage) return 'No messages yet'
    
    const content = lastMessage.content || lastMessage.text
    if (lastMessage.type === 'file') {
      return `📎 ${content}`
    }
    return content.length > 30 ? content.substring(0, 30) + '...' : content
  }

  const getTimeAgo = () => {
    if (!lastMessage) return ''
    try {
      return formatDistanceToNow(new Date(lastMessage.timestamp), {
        addSuffix: false,
      })
    } catch (e) {
      return ''
    }
  }

  // Get presence indicator class
  const getPresenceClass = () => {
    if (contact.isAI) return 'online' // AI is always online
    if (!presenceEnabled) return contact.online ? 'online' : ''
    
    switch (contact.presenceStatus) {
      case 'online': return 'online'
      case 'idle': return 'idle'
      case 'offline': return 'offline'
      default: return ''
    }
  }

  // Get presence tooltip
  const getPresenceTooltip = () => {
    if (contact.isAI) return 'AI Assistant - Always available'
    if (!presenceEnabled) return contact.online ? 'Online' : 'Offline'
    
    switch (contact.presenceStatus) {
      case 'online': return 'Online'
      case 'idle': return 'Away'
      case 'offline': 
        if (contact.lastSeen) {
          try {
            return `Last seen ${formatDistanceToNow(new Date(contact.lastSeen), { addSuffix: true })}`
          } catch {
            return 'Offline'
          }
        }
        return 'Offline'
      default: return 'Unknown'
    }
  }

  return (
    <div
      className={`contact-item ${isSelected ? 'selected' : ''} ${contact.isAI ? 'ai-contact' : ''} transition-all hover-lift`}
      onClick={handleClick}
    >
      <div className={`contact-avatar ${contact.isAI ? 'ai-avatar' : ''}`}>
        {contact.isAI ? (
          <i className="fas fa-robot"></i>
        ) : (
          <i className="fas fa-user"></i>
        )}
        <span 
          className={`presence-indicator ${getPresenceClass()}`}
          title={getPresenceTooltip()}
        ></span>
      </div>
      
      <div className="contact-info">
        <div className="contact-header">
          <span className="contact-name">{contact.username}</span>
          {lastMessage && (
            <span className="message-time">{getTimeAgo()}</span>
          )}
        </div>
        
        <div className="contact-footer">
          <span className="last-message">{getLastMessagePreview()}</span>
          {unreadCount > 0 && (
            <div className="unread-container">
              <Lottie
                animationData={notificationAnimation}
                loop={true}
                style={{ width: 24, height: 24 }}
                className="notification-bell"
              />
              <span className="unread-badge">{unreadCount}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default ContactItem
