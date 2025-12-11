import { useEffect, useRef, useState } from 'react'
import { useChat } from '../../context/ChatContext'
import Lottie from 'lottie-react'
import MessageList from './MessageList'
import MessageInput from './MessageInput'
import userAnimation from '../../../public/animations/user.json'
import messageAnimation from '../../../public/animations/message.json'
import './PrivateChat.css'

const PrivateChat = () => {
  const { selectedContact, privateMessages, loadChatHistory, markAsRead } = useChat()
  const [showEmojiPicker, setShowEmojiPicker] = useState(false)
  const [showFilePreview, setShowFilePreview] = useState(false)
  const [selectedFile, setSelectedFile] = useState(null)

  // Load chat history when contact is selected
  useEffect(() => {
    if (selectedContact) {
      loadChatHistory(selectedContact.username)
      // Mark messages as read when viewing the chat
      markAsRead(selectedContact.username)
    }
  }, [selectedContact])

  const messages = selectedContact
    ? privateMessages[selectedContact.username.toLowerCase()] || []
    : []

  if (!selectedContact) {
    return (
      <div className="no-chat-selected private-glow">
        <div className="no-chat-animation">
          <Lottie 
            animationData={messageAnimation} 
            loop={true}
            style={{ width: 200, height: 200 }}
          />
        </div>
        <h2 className="glow-text">Select a contact to start chatting</h2>
        <p className="subtitle-text">Choose a conversation from the sidebar</p>
      </div>
    )
  }

  return (
    <div className="private-chat">
      <div className="encryption-banner">
        <i className="fas fa-lock"></i>
        <span>End-to-End Encryption</span>
      </div>
      <div className="chat-header private-header-glow">
        <div className="header-left">
          <div className="contact-avatar-container private-avatar-glow">
            <Lottie 
              animationData={userAnimation} 
              loop={true}
              style={{ width: 50, height: 50 }}
            />
            {selectedContact.online && (
              <span className="online-indicator private-pulse"></span>
            )}
          </div>
          <div className="contact-info">
            <h3 className="contact-name-glow">{selectedContact.username}</h3>
            <span className={`status ${selectedContact.online ? 'status-online' : 'status-offline'}`}>
              {selectedContact.online ? 'Online' : 'Offline'}
            </span>
          </div>
        </div>
        <div className="header-actions">
          <button className="icon-btn glow-btn">
            <i className="fas fa-phone"></i>
          </button>
          <button className="icon-btn glow-btn">
            <i className="fas fa-video"></i>
          </button>
          <button className="icon-btn glow-btn">
            <i className="fas fa-ellipsis-v"></i>
          </button>
        </div>
      </div>

      <MessageList messages={messages} />

      <MessageInput
        recipient={selectedContact.username}
        isPrivate={true}
        showEmojiPicker={showEmojiPicker}
        setShowEmojiPicker={setShowEmojiPicker}
        showFilePreview={showFilePreview}
        setShowFilePreview={setShowFilePreview}
        selectedFile={selectedFile}
        setSelectedFile={setSelectedFile}
      />
    </div>
  )
}

export default PrivateChat
