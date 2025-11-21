import { useState, useEffect, useRef } from 'react'
import Lottie from 'lottie-react'
import Message from './Message'
import MessageInput from './MessageInput'
import './AIChat.css'
import botAnimation from '../../../public/animations/bot.json'
import typingAnimation from '../../../public/animations/typing.json'
import sparkleAnimation from '../../../public/animations/sparkle.json'

const AIChat = () => {
  const [messages, setMessages] = useState([])
  const [isLoading, setIsLoading] = useState(false)
  const [aiStatus, setAiStatus] = useState(null)
  const [showSparkle, setShowSparkle] = useState(false)
  const messagesEndRef = useRef(null)
  const currentUser = sessionStorage.getItem('currentUser')

  useEffect(() => {
    // Check AI status on mount
    checkAIStatus()
  }, [])

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  const checkAIStatus = async () => {
    try {
      const response = await fetch('/api/ai/status')
      const data = await response.json()
      setAiStatus(data)
      
      if (!data.enabled) {
        setMessages([{
          id: Date.now(),
          sender: 'AI Assistant',
          text: 'AI chatbot is not configured. Please set up your API key in the .env file to use this feature.',
          timestamp: new Date().toISOString(),
          isSent: false,
          status: 'received'
        }])
      } else {
        setMessages([{
          id: Date.now(),
          sender: 'AI Assistant',
          text: `Hello! I'm your AI assistant powered by ${data.provider === 'gemini' ? 'Google Gemini' : 'OpenRouter'}. How can I help you today?`,
          timestamp: new Date().toISOString(),
          isSent: false,
          status: 'received'
        }])
      }
    } catch (error) {
      console.error('[AI] Error checking status:', error)
      setMessages([{
        id: Date.now(),
        sender: 'AI Assistant',
        text: 'Error connecting to AI service. Please try again later.',
        timestamp: new Date().toISOString(),
        isSent: false,
        status: 'received'
      }])
    }
  }

  const handleSendMessage = async (content) => {
    if (!content.trim() || isLoading) return

    // Show sparkle effect
    setShowSparkle(true)
    setTimeout(() => setShowSparkle(false), 1000)

    // Add user message
    const userMessage = {
      id: Date.now(),
      sender: currentUser,
      text: content,
      timestamp: new Date().toISOString(),
      isSent: true,
      status: 'sent'
    }
    
    setMessages(prev => [...prev, userMessage])
    setIsLoading(true)

    try {
      // Prepare conversation history for context
      const conversationHistory = messages
        .slice(-10) // Last 10 messages for context
        .map(msg => ({
          role: msg.isSent ? 'user' : 'assistant',
          content: msg.text
        }))

      const response = await fetch('/api/ai/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          message: content,
          conversationHistory
        })
      })

      const data = await response.json()

      if (data.success) {
        // Add AI response
        const aiMessage = {
          id: Date.now() + 1,
          sender: 'AI Assistant',
          text: data.response,
          timestamp: new Date().toISOString(),
          isSent: false,
          status: 'received'
        }
        
        setMessages(prev => [...prev, aiMessage])
      } else {
        // Add error message
        const errorMessage = {
          id: Date.now() + 1,
          sender: 'AI Assistant',
          text: `Error: ${data.error || 'Failed to get AI response'}`,
          timestamp: new Date().toISOString(),
          isSent: false,
          status: 'error'
        }
        
        setMessages(prev => [...prev, errorMessage])
      }
    } catch (error) {
      console.error('[AI] Error sending message:', error)
      
      const errorMessage = {
        id: Date.now() + 1,
        sender: 'AI Assistant',
        text: 'Failed to send message. Please check your connection and try again.',
        timestamp: new Date().toISOString(),
        isSent: false,
        status: 'error'
      }
      
      setMessages(prev => [...prev, errorMessage])
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="ai-chat">
      <div className="encryption-banner">
        <i className="fas fa-lock"></i>
        <span>End-to-End Encryption</span>
      </div>
      <div className="chat-header ai-header">
        <div className="header-content">
          <div className="contact-info">
            <div className="contact-avatar ai-avatar-container">
              <Lottie 
                animationData={botAnimation} 
                loop={true}
                className="ai-avatar-animation"
              />
            </div>
            <div className="contact-details">
              <h2 className="ai-title">AI Assistant</h2>
              <span className={`status ${aiStatus?.enabled ? 'online ai-online' : 'offline'}`}>
                {aiStatus?.enabled ? (
                  <>
                    <span className="status-dot pulse"></span>
                    {aiStatus.provider} • Online
                  </>
                ) : 'Offline'}
              </span>
            </div>
          </div>
          {showSparkle && (
            <div className="sparkle-effect">
              <Lottie 
                animationData={sparkleAnimation} 
                loop={false}
                className="sparkle-animation"
              />
            </div>
          )}
        </div>
      </div>

      <div className="messages-container ai-messages">
        <div className="messages-list">
          {messages.map((message) => (
            <Message
              key={message.id}
              message={message}
              currentUser={currentUser}
            />
          ))}
          {isLoading && (
            <div className="ai-typing-container">
              <div className="typing-bubble">
                <Lottie 
                  animationData={typingAnimation} 
                  loop={true}
                  className="typing-animation"
                />
                <span className="typing-text">AI is thinking...</span>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>
      </div>

      <MessageInput 
        onSend={handleSendMessage} 
        disabled={isLoading || !aiStatus?.enabled}
        placeholder={
          !aiStatus?.enabled 
            ? "AI is not configured..." 
            : isLoading 
            ? "AI is thinking..." 
            : "Ask me anything..."
        }
        className="ai-input"
      />
    </div>
  )
}

export default AIChat
