import { useState, useEffect } from 'react'
import { useChat } from '../../context/ChatContext'
import Lottie from 'lottie-react'
import MessageList from './MessageList'
import MessageInput from './MessageInput'
import broadcastAnimation from '../../../public/animations/broadcast.json'
import './PrivateChat.css'

const BroadcastChat = () => {
  const { broadcastMessages, loadBroadcastHistory } = useChat()
  const [showEmojiPicker, setShowEmojiPicker] = useState(false)
  const [showFilePreview, setShowFilePreview] = useState(false)
  const [selectedFile, setSelectedFile] = useState(null)

  // Load broadcast history on mount
  useEffect(() => {
    loadBroadcastHistory()
  }, [])

  return (
    <div className="broadcast-chat">
      <div className="encryption-banner">
        <i className="fas fa-lock"></i>
        <span>End-to-End Encryption</span>
      </div>
      <div className="chat-header broadcast-header-glow">
        <div className="header-left">
          <div className="contact-avatar-container broadcast-avatar-glow">
            <Lottie 
              animationData={broadcastAnimation} 
              loop={true}
              style={{ width: 50, height: 50 }}
            />
          </div>
          <div className="contact-info">
            <h3 className="broadcast-name-glow">Broadcast Channel</h3>
            <span className="status status-broadcast">Send to all users</span>
          </div>
        </div>
        <div className="header-actions">
          <button className="icon-btn glow-btn">
            <i className="fas fa-users"></i>
          </button>
          <button className="icon-btn glow-btn">
            <i className="fas fa-ellipsis-v"></i>
          </button>
        </div>
      </div>

      <MessageList messages={broadcastMessages} />

      <MessageInput
        recipient="broadcast"
        isPrivate={false}
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

export default BroadcastChat
