import { useEffect, useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { api, clearToken, clearUser, getUser } from '../api/client'
import Sidebar from './Sidebar'

export default function Layout() {
  const [labs, setLabs] = useState({ categories: [], labs: [] })
  const [user, setUser] = useState(getUser())
  const navigate = useNavigate()

  useEffect(() => {
    api('/api/labs').then((res) => {
      if (res.ok && res.data) setLabs(res.data)
    })
  }, [])

  function handleLogout() {
    clearToken()
    clearUser()
    setUser(null)
    navigate('/login')
  }

  return (
    <div className="app-shell">
      <Sidebar labs={labs} />
      <div className="main-pane">
        <header className="topbar">
          <div className="brand">
            <span className="brand-mark">SB</span>
            <span className="brand-name">SecureBank</span>
            <span className="brand-tag">Labs</span>
          </div>
          <div className="topbar-right">
            {user && (
              <span className="who">
                {user.username}
                <em className={`role role-${user.role}`}>{user.role}</em>
              </span>
            )}
            <button className="btn btn-ghost" onClick={handleLogout}>
              Sign out
            </button>
          </div>
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
