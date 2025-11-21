import { useState } from 'react'
import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar/Sidebar'
import AnimatedBackground from './Common/AnimatedBackground'
import './ChatLayout.css'

const ChatLayout = () => {
  const [sidebarOpen, setSidebarOpen] = useState(true)

  const toggleSidebar = () => {
    setSidebarOpen(!sidebarOpen)
  }

  return (
    <div className="chat-layout">
      <AnimatedBackground />
      <Sidebar isOpen={sidebarOpen} onToggle={toggleSidebar} />
      <div className={`main-content ${!sidebarOpen ? 'sidebar-closed' : ''}`}>
        <Outlet />
      </div>
    </div>
  )
}

export default ChatLayout
