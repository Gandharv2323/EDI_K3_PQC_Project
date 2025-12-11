import { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useWebSocket } from '../../context/WebSocketContext'
import { useChat } from '../../context/ChatContext'
import Lottie from 'lottie-react'
import LottieAnimation from '../Common/LottieAnimation'
import loadingAnimation from '../../animations/loading.json'
import loginAnimation from '../../../public/animations/login.json'
import './Auth.css'

const Login = () => {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()
  const { sendMessage, messages } = useWebSocket()
  const { refreshContacts } = useChat()

  // Listen for authentication messages from the decrypted message stream
  useEffect(() => {
    if (!loading || !messages || messages.length === 0) return

    // Get the most recent message
    const latestMessage = messages[messages.length - 1]
    if (!latestMessage) return
    
    const data = latestMessage.data || ''
    console.log('[LOGIN] Decrypted message received:', data)
    
    // Skip messages that are just prompts or not authentication responses
    // Only process messages that indicate success or failure
    if (data.includes('Authentication successful') || data.includes('Welcome')) {
      console.log('[LOGIN] ✅ Authentication successful!')
      sessionStorage.setItem('currentUser', username)
      sessionStorage.setItem('userPassword', password)
      setLoading(false)
      
      // Refresh contacts to include any new users
      if (refreshContacts) {
        refreshContacts().then(() => {
          navigate('/chat/private')
          window.location.reload()
        })
      } else {
        navigate('/chat/private')
        window.location.reload()
      }
    }
    else if (data.includes('Authentication failed') || data.includes('Invalid credentials')) {
      console.log('[LOGIN] ❌ Authentication failed')
      setError('Authentication failed. Check username/password')
      setLoading(false)
    }
    else if (data.includes('Authentication timed out') || (data.includes('timed out') && data.includes('Authentication'))) {
      console.log('[LOGIN] ⏱️ Server-side timeout')
      setError('Authentication timed out on server. Please try again.')
      setLoading(false)
    }
    // Ignore other messages like "Please reconnect" or "Choose option" - those are from signup
  }, [messages, loading, username, password, navigate, refreshContacts])

  // Fallback timeout
  useEffect(() => {
    if (!loading) return
    
    const timeoutId = setTimeout(() => {
      if (loading) {
        console.log('[LOGIN] ⏱️ Client-side timeout after 10s')
        setError('Authentication timed out. The server may be slow or unresponsive.')
        setLoading(false)
      }
    }, 10000)

    return () => clearTimeout(timeoutId)
  }, [loading])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')

    if (!username || !password) {
      setError('Please enter both username and password')
      return
    }

    setLoading(true)

    // Send LOGIN over WebSocket in format LOGIN:username:password
    const sent = sendMessage(`LOGIN:${username}:${password}`)
    if (!sent) {
      setError('Not connected to chat server')
      setLoading(false)
      return
    }
    
    console.log('[LOGIN] Login request sent, waiting for response...')
    // The useEffect hook above will handle the response
  }

  const handleTestLogin = (testUsername) => {
    // Default test passwords
    const testPasswords = {
      'alice': 'alice123',
      'bob': 'bob456',
      'charlie': 'charlie789'
    }
    
    sessionStorage.setItem('currentUser', testUsername)
    sessionStorage.setItem('userPassword', testPasswords[testUsername] || 'password123')
    navigate('/chat/private')
    window.location.reload()
  }

  return (
    <div className="auth-container animate-fade-in">
      <div className="auth-card animate-scale-in glow-card">
        <div className="auth-header">
          <div className="auth-logo-animation" style={{ width: '100px', height: '100px', margin: '0 auto 1rem' }}>
            <Lottie 
              animationData={loginAnimation} 
              loop={true}
              style={{ width: '100%', height: '100%', filter: 'drop-shadow(0 0 20px rgba(32, 178, 255, 0.4))' }}
            />
          </div>
          <h1 className="glow-title">
            <i className="fas fa-comments"></i>
            ChatBox
          </h1>
          <p className="subtitle-glow">Sign in to start messaging</p>
        </div>

        <form onSubmit={handleSubmit} className="auth-form">
          <div className="input-group glow-input-group">
            <i className="fas fa-user"></i>
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              disabled={loading}
            />
          </div>

          <div className="input-group glow-input-group">
            <i className="fas fa-lock"></i>
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={loading}
            />
          </div>

          {error && <div className="error-message glow-error">{error}</div>}

          <button type="submit" className="btn-primary glow-button" disabled={loading}>
            {loading ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', justifyContent: 'center' }}>
                <div style={{ width: '24px', height: '24px' }}>
                  <LottieAnimation 
                    animationData={loadingAnimation}
                    style={{ width: '100%', height: '100%' }}
                  />
                </div>
                <span>Signing in...</span>
              </div>
            ) : (
              <>
                <i className="fas fa-sign-in-alt"></i>
                Sign In
              </>
            )}
          </button>

          <div className="auth-footer">
            <p>
              Don't have an account?{' '}
              <Link to="/signup" className="link">
                Sign up
              </Link>
            </p>
          </div>
        </form>

        {/* <div className="test-accounts">
          <h4>
            <i className="fas fa-info-circle"></i>
            Test Accounts
          </h4>
          <div className="test-account">
            <div className="test-account-info">
              <span className="username">alice</span>
              <span className="password">alice123</span>
            </div>
            <button
              className="btn-use"
              onClick={() => handleTestLogin('alice')}
              type="button"
            >
              Use
            </button>
          </div>
          <div className="test-account">
            <div className="test-account-info">
              <span className="username">bob</span>
              <span className="password">bob456</span>
            </div>
            <button
              className="btn-use"
              onClick={() => handleTestLogin('bob')}
              type="button"
            >
              Use
            </button>
          </div>
          <div className="test-account">
            <div className="test-account-info">
              <span className="username">charlie</span>
              <span className="password">charlie789</span>
            </div>
            <button
              className="btn-use"
              onClick={() => handleTestLogin('charlie')}
              type="button"
            >
              Use
            </button>
          </div>
        </div> */}
      </div>
    </div>
  )
}

export default Login
