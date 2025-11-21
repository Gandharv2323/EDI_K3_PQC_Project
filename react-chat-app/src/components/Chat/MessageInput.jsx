import { useState, useRef, useEffect } from 'react'
import { useWebSocket } from '../../context/WebSocketContext'
import { useChat } from '../../context/ChatContext'
import EmojiPicker from '../Common/EmojiPicker'
import FilePreview from '../Common/FilePreview'
import Lottie from 'lottie-react'
import sendingAnimation from '../../../public/animations/sending.json'
import './MessageInput.css'

const MessageInput = ({
  recipient,
  isPrivate,
  showEmojiPicker,
  setShowEmojiPicker,
  showFilePreview,
  setShowFilePreview,
  selectedFile,
  setSelectedFile,
  onSend, // Custom send handler (for AI chat)
  disabled, // Disabled state (for AI chat)
  placeholder, // Custom placeholder (for AI chat)
  className, // Custom className (for AI chat)
}) => {
  const [message, setMessage] = useState('')
  const [showSendingAnimation, setShowSendingAnimation] = useState(false)
  const { sendMessage } = useWebSocket()
  const { addPrivateMessage, addBroadcastMessage } = useChat()
  const inputRef = useRef(null)
  const fileInputRef = useRef(null)

  useEffect(() => {
    inputRef.current?.focus()
  }, [recipient])

  const handleSend = () => {
    if (!message.trim() && !selectedFile) return

    // Show sending animation
    setShowSendingAnimation(true)
    setTimeout(() => setShowSendingAnimation(false), 1500)

    // If custom onSend is provided (AI chat), use it
    if (onSend) {
      onSend(message.trim())
      setMessage('')
      inputRef.current?.focus()
      return
    }

    if (selectedFile) {
      // Send file message
      const fileMsg = isPrivate
        ? `/msg ${recipient} [FILE] ${selectedFile.name}`
        : `/broadcast [FILE] ${selectedFile.name}`
      
      sendMessage(fileMsg)
      
      // Add to local state immediately for instant feedback
      if (isPrivate) {
        addPrivateMessage(recipient, `[FILE] ${selectedFile.name}`)
      } else {
        addBroadcastMessage(`[FILE] ${selectedFile.name}`)
      }
      
      setSelectedFile(null)
      setShowFilePreview(false)
    }

    if (message.trim()) {
      // Send text message with correct format
      const textMsg = isPrivate
        ? `/msg ${recipient} ${message.trim()}`
        : `/broadcast ${message.trim()}`
      
      sendMessage(textMsg)
      
      // Add to local state immediately for instant feedback
      if (isPrivate) {
        addPrivateMessage(recipient, message.trim())
      } else {
        addBroadcastMessage(message.trim())
      }
      
      setMessage('')
    }

    inputRef.current?.focus()
  }

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const handleEmojiSelect = (emoji) => {
    setMessage((prev) => prev + emoji)
    inputRef.current?.focus()
  }

  const handleFileSelect = (e) => {
    const file = e.target.files?.[0]
    if (file) {
      setSelectedFile(file)
      setShowFilePreview(true)
    }
  }

  const handleFileRemove = () => {
    setSelectedFile(null)
    setShowFilePreview(false)
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  return (
    <div className={`message-input-container ${className || ''}`}>
      {showSendingAnimation && (
        <div className="sending-animation-overlay">
          <Lottie
            animationData={sendingAnimation}
            loop={false}
            style={{ width: 150, height: 150 }}
          />
        </div>
      )}

      {showFilePreview && selectedFile && (
        <FilePreview file={selectedFile} onRemove={handleFileRemove} />
      )}

      {showEmojiPicker && (
        <EmojiPicker
          onSelect={handleEmojiSelect}
          onClose={() => setShowEmojiPicker(false)}
        />
      )}

      <div className="message-input">
        {!onSend && ( // Hide file/emoji buttons for AI chat
          <>
            <button
              className="input-btn"
              onClick={() => fileInputRef.current?.click()}
              title="Attach file"
            >
              <i className="fas fa-paperclip"></i>
            </button>

            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileSelect}
              style={{ display: 'none' }}
            />

            <button
              className="input-btn"
              onClick={() => setShowEmojiPicker(!showEmojiPicker)}
              title="Add emoji"
            >
              <i className="fas fa-smile"></i>
            </button>
          </>
        )}

        <input
          ref={inputRef}
          type="text"
          className="message-field"
          placeholder={placeholder || "Type a message..."}
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          onKeyPress={handleKeyPress}
          disabled={disabled}
        />

        <button
          className="send-btn"
          onClick={handleSend}
          disabled={disabled || (!message.trim() && !selectedFile)}
          title="Send message"
        >
          <i className="fas fa-paper-plane"></i>
        </button>
      </div>
    </div>
  )
}

export default MessageInput
