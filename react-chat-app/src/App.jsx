import { useState, useEffect } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import Login from './components/Auth/Login'
import Signup from './components/Auth/Signup'
import ChatLayout from './components/ChatLayout'
import PrivateChat from './components/Chat/PrivateChat'
import BroadcastChat from './components/Chat/BroadcastChat'
import AIChat from './components/Chat/AIChat'
import { WebSocketProvider } from './context/WebSocketContext'
import { ChatProvider } from './context/ChatContext'
import { useLenis } from './hooks/useLenis'
import './animations.css'
import './App.css'

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  
  // Initialize Lenis smooth scrolling
  useLenis()

  useEffect(() => {
    // Check for stored auth
    const storedUser = sessionStorage.getItem('currentUser')
    if (storedUser) {
      setIsAuthenticated(true)
    }
  }, [])

  return (
    <Router>
      <WebSocketProvider>
        <ChatProvider>
          <Routes>
            <Route
              path="/login"
              element={
                isAuthenticated ? (
                  <Navigate to="/chat/private" replace />
                ) : (
                  <Login />
                )
              }
            />
            <Route
              path="/signup"
              element={
                isAuthenticated ? (
                  <Navigate to="/chat/private" replace />
                ) : (
                  <Signup />
                )
              }
            />
            <Route
              path="/chat"
              element={
                isAuthenticated ? (
                  <ChatLayout />
                ) : (
                  <Navigate to="/login" replace />
                )
              }
            >
              <Route path="private" element={<PrivateChat />} />
              <Route path="broadcast" element={<BroadcastChat />} />
              <Route path="ai" element={<AIChat />} />
              <Route index element={<Navigate to="private" replace />} />
            </Route>
            <Route path="*" element={<Navigate to="/login" replace />} />
          </Routes>
        </ChatProvider>
      </WebSocketProvider>
    </Router>
  )
}

export default App

