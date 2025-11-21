import { useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { useChat } from '../../context/ChatContext'
import ContactList from './ContactList'
import './Sidebar.css'

const Sidebar = ({ isOpen, onToggle }) => {
  const navigate = useNavigate()
  const location = useLocation()
  const { contacts } = useChat()
  const [searchQuery, setSearchQuery] = useState('')
  const [activeTab, setActiveTab] = useState(() => {
    if (location.pathname.includes('broadcast')) return 'broadcast'
    if (location.pathname.includes('ai')) return 'ai'
    return 'private'
  })

  const handleLogout = () => {
    sessionStorage.removeItem('currentUser')
    sessionStorage.removeItem('userPassword')
    navigate('/login')
  }

  const handleTabChange = (tab) => {
    setActiveTab(tab)
    if (tab === 'broadcast') {
      navigate('/chat/broadcast')
    } else if (tab === 'ai') {
      navigate('/chat/ai')
    } else {
      navigate('/chat/private')
    }
  }

  const filteredContacts = contacts.filter((contact) =>
    contact.username.toLowerCase().includes(searchQuery.toLowerCase())
  )

  return (
    <div className={`sidebar ${isOpen ? 'open' : 'closed'} animate-slide-in-left`}>
      <div className="sidebar-header">
        <div className="sidebar-title">
          <i className="fas fa-comments"></i>
          <h2>ChatBox</h2>
        </div>
        <button className="toggle-btn" onClick={onToggle}>
          <i className={`fas fa-${isOpen ? 'angle-left' : 'angle-right'}`}></i>
        </button>
      </div>

      {isOpen && (
        <>
          <div className="sidebar-user">
            <div className="user-avatar">
              <i className="fas fa-user"></i>
            </div>
            <div className="user-info">
              <span className="user-name">
                {sessionStorage.getItem('currentUser')}
              </span>
              <span className="user-status">
                <i className="fas fa-circle"></i>
                Online
              </span>
            </div>
            <button className="logout-btn" onClick={handleLogout}>
              <i className="fas fa-sign-out-alt"></i>
            </button>
          </div>

          <div className="chat-tabs">
            <button
              className={`tab ${activeTab === 'private' ? 'active' : ''}`}
              onClick={() => handleTabChange('private')}
            >
              <i className="fas fa-user"></i>
              Private
            </button>
            <button
              className={`tab ${activeTab === 'broadcast' ? 'active' : ''}`}
              onClick={() => handleTabChange('broadcast')}
            >
              <i className="fas fa-users"></i>
              Broadcast
            </button>
            <button
              className={`tab ${activeTab === 'ai' ? 'active' : ''}`}
              onClick={() => handleTabChange('ai')}
            >
              <i className="fas fa-robot"></i>
              AI Chat
            </button>
          </div>

          <div className="search-bar">
            <i className="fas fa-search"></i>
            <input
              type="text"
              placeholder="Search contacts..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            {searchQuery && (
              <button
                className="clear-search"
                onClick={() => setSearchQuery('')}
              >
                <i className="fas fa-times"></i>
              </button>
            )}
          </div>

          {activeTab === 'private' ? (
            <ContactList contacts={filteredContacts} />
          ) : activeTab === 'broadcast' ? (
            <div className="broadcast-info">
              <i className="fas fa-bullhorn"></i>
              <h3>Broadcast Channel</h3>
              <p>Send messages to all users</p>
            </div>
          ) : (
            <div className="broadcast-info">
              <i className="fas fa-robot"></i>
              <h3>AI Assistant</h3>
              <p>Chat with your AI helper</p>
            </div>
          )}
        </>
      )}
    </div>
  )
}

export default Sidebar
