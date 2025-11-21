import { useState } from 'react'
import { format } from 'date-fns'
import './Message.css'

const Message = ({ message, isFirst }) => {
  const [showContextMenu, setShowContextMenu] = useState(false)
  const [contextMenuPos, setContextMenuPos] = useState({ x: 0, y: 0 })

  const currentUser = sessionStorage.getItem('currentUser')
  const isSent = message.isSent || message.sender === currentUser

  const handleContextMenu = (e) => {
    e.preventDefault()
    setContextMenuPos({ x: e.clientX, y: e.clientY })
    setShowContextMenu(true)
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(message.content || message.text)
    setShowContextMenu(false)
  }

  const handleDelete = () => {
    // TODO: Implement delete functionality
    setShowContextMenu(false)
  }

  const handleReply = () => {
    // TODO: Implement reply functionality
    setShowContextMenu(false)
  }

  const getTimeString = () => {
    try {
      return format(new Date(message.timestamp), 'HH:mm')
    } catch (e) {
      return ''
    }
  }

  const renderMessageContent = () => {
    if (message.type === 'file') {
      return (
        <div className="message-file">
          <i className="fas fa-file"></i>
          <span>{message.content || message.text}</span>
        </div>
      )
    }
    return <div className="message-text">{message.content || message.text}</div>
  }

  return (
    <>
      <div
        className={`message ${isSent ? 'sent' : 'received'} ${
          isFirst ? 'first' : ''
        } ${isSent ? 'animate-fade-in-right' : 'animate-fade-in-left'}`}
        onContextMenu={handleContextMenu}
      >
        {!isSent && isFirst && (
          <div className="message-sender">{message.sender}</div>
        )}
        
        <div className="message-bubble">
          {renderMessageContent()}
          
          <div className="message-footer">
            <span className="message-time">{getTimeString()}</span>
            {isSent && (
              <span className="message-status">
                {message.status === 'sent' && (
                  <i className="fas fa-check"></i>
                )}
                {message.status === 'delivered' && (
                  <>
                    <i className="fas fa-check"></i>
                    <i className="fas fa-check"></i>
                  </>
                )}
                {message.status === 'read' && (
                  <span className="read-status">
                    <i className="fas fa-check"></i>
                    <i className="fas fa-check"></i>
                  </span>
                )}
              </span>
            )}
          </div>
        </div>
      </div>

      {showContextMenu && (
        <>
          <div
            className="context-menu-overlay"
            onClick={() => setShowContextMenu(false)}
          />
          <div
            className="context-menu"
            style={{ top: contextMenuPos.y, left: contextMenuPos.x }}
          >
            <button onClick={handleReply}>
              <i className="fas fa-reply"></i>
              Reply
            </button>
            <button onClick={handleCopy}>
              <i className="fas fa-copy"></i>
              Copy
            </button>
            <button onClick={handleDelete} className="danger">
              <i className="fas fa-trash"></i>
              Delete
            </button>
          </div>
        </>
      )}
    </>
  )
}

export default Message
