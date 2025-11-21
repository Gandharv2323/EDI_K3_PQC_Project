import { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useWebSocket } from '../../context/WebSocketContext'
import Lottie from 'lottie-react'
import LottieAnimation from '../Common/LottieAnimation'
import loadingAnimation from '../../animations/loading.json'
import successAnimation from '../../animations/success.json'
import loginAnimation from '../../../public/animations/login.json'
import './Auth.css'

const Signup = () => {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()
  const { sendMessage, messages } = useWebSocket()

  // Listen for registration messages from the decrypted message stream
  useEffect(() => {
    if (!loading || !messages || messages.length === 0) return

    // Get the most recent message
    const latestMessage = messages[messages.length - 1]
    if (!latestMessage) return
    
    const data = latestMessage.data || ''
    console.log('[SIGNUP] Decrypted message received:', data)
    
    // Check for success
    if (data.includes('Registration successful')) {
      console.log('[SIGNUP] ✅ Registration successful!')
      setSuccess('Account created successfully! Redirecting to login...')
      setLoading(false)
      setTimeout(() => navigate('/login'), 1500)
    }
    // Check for failure
    else if (data.includes('Registration failed') || data.includes('already exist')) {
      console.log('[SIGNUP] ❌ Registration failed')
      setError('Registration failed. Username may already exist or invalid credentials.')
      setLoading(false)
    }
    // Check for timeout
    else if (data.includes('timed out')) {
      console.log('[SIGNUP] ⏱️ Server-side timeout')
      setError('Registration timed out on server. Please try again.')
      setLoading(false)
    }
  }, [messages, loading, navigate])

  // Fallback timeout
  useEffect(() => {
    if (!loading) return
    
    const timeoutId = setTimeout(() => {
      if (loading) {
        console.log('[SIGNUP] ⏱️ Client-side timeout after 10s')
        setError('Registration timed out. The server may be slow or unresponsive.')
        setLoading(false)
      }
    }, 10000)

    return () => clearTimeout(timeoutId)
  }, [loading])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess('')

    if (!username || !password || !confirmPassword) {
      setError('Please fill in all fields')
      return
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match')
      return
    }

    if (password.length < 6) {
      setError('Password must be at least 6 characters')
      return
    }

    setLoading(true)

    // Send REGISTER over WebSocket in format REGISTER:username:password
    const sent = sendMessage(`REGISTER:${username}:${password}`)
    if (!sent) {
      setError('Not connected to chat server')
      setLoading(false)
      return
    }
    
    console.log('[SIGNUP] Registration request sent, waiting for response...')
    // The useEffect hook above will handle the response from the decrypted messages
  }

  return (
    <div className="auth-container animate-fade-in">
      <div className="auth-card animate-scale-in glow-card">
        <div className="auth-header">
          {success ? (
            <div style={{ width: '100px', height: '100px', margin: '0 auto 1rem', filter: 'drop-shadow(0 0 20px rgba(0, 217, 163, 0.6))' }}>
              <LottieAnimation 
                animationData={successAnimation} 
                loop={false}
                style={{ width: '100%', height: '100%' }}
              />
            </div>
          ) : (
            <div style={{ width: '100px', height: '100px', margin: '0 auto 1rem' }}>
              <Lottie 
                animationData={loginAnimation} 
                loop={true}
                style={{ width: '100%', height: '100%', filter: 'drop-shadow(0 0 20px rgba(32, 178, 255, 0.4))' }}
              />
            </div>
          )}
          <h1 className="glow-title">
            <i className="fas fa-user-plus"></i>
            Create Account
          </h1>
          <p className="subtitle-glow">Join ChatBox today</p>
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

          <div className="input-group glow-input-group">
            <i className="fas fa-lock"></i>
            <input
              type="password"
              placeholder="Confirm Password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              disabled={loading}
            />
          </div>

          {error && <div className="error-message glow-error">{error}</div>}
          {success && <div className="success-message glow-success">{success}</div>}

          <button type="submit" className="btn-primary glow-button" disabled={loading}>
            {loading ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', justifyContent: 'center' }}>
                <div style={{ width: '24px', height: '24px' }}>
                  <LottieAnimation 
                    animationData={loadingAnimation}
                    style={{ width: '100%', height: '100%' }}
                  />
                </div>
                <span>Creating account...</span>
              </div>
            ) : (
              <>
                <i className="fas fa-user-plus"></i>
                Create Account
              </>
            )}
          </button>

          <div className="auth-footer">
            <p>
              Already have an account?{' '}
              <Link to="/login" className="link">
                Sign in
              </Link>
            </p>
          </div>
        </form>
      </div>
    </div>
  )
}

export default Signup
