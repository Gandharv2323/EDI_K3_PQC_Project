import { useEffect, useRef } from 'react'
import Message from './Message'
import './MessageList.css'

const MessageList = ({ messages }) => {
  const messagesEndRef = useRef(null)
  const messageListRef = useRef(null)

  const scrollToBottom = () => {
    requestAnimationFrame(() => {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    })
  }

  useEffect(() => {
    // Scroll on initial load
    scrollToBottom()
  }, [])

  useEffect(() => {
    // Scroll when new messages arrive
    const timeoutId = setTimeout(scrollToBottom, 100)
    return () => clearTimeout(timeoutId)
  }, [messages])

  if (messages.length === 0) {
    return (
      <div className="message-list empty">
        <div className="empty-messages">
          <i className="fas fa-comment-slash"></i>
          <p>No messages yet</p>
          <span>Send a message to start the conversation</span>
        </div>
      </div>
    )
  }

  return (
    <div className="message-list" ref={messageListRef}>
      <div className="messages-container">
        {messages.map((message, index) => (
          <Message
            key={message.id || index}
            message={message}
            isFirst={
              index === 0 || messages[index - 1].sender !== message.sender
            }
          />
        ))}
        <div ref={messagesEndRef} />
      </div>
    </div>
  )
}

export default MessageList
