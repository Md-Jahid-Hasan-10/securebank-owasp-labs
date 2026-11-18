import { useEffect, useState } from 'react'
import { api } from '../../api/client'

export default function AdminConsolePage() {
  const [token, setToken] = useState(sessionStorage.getItem('securebank_admin_token') ?? '')
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('admin')
  const [error, setError] = useState(null)
  const [data, setData] = useState(null)

  useEffect(() => {
    if (!token) return
    load()
  }, [])

  function load() {
    api('/api/a02/admin/users', {
      headers: { Authorization: `Bearer ${token}` },
    }).then((res) => {
      if (res.ok) {
        setData(res.data)
        setError(null)
      } else {
        setError(res.data?.error ?? 'Could not load admin data')
      }
    })
  }

  async function signIn(event) {
    event.preventDefault()
    setError(null)

    const res = await api('/api/a02/admin/login', {
      method: 'POST',
      body: { username, password },
    })

    if (res.ok && res.data?.token) {
      sessionStorage.setItem('securebank_admin_token', res.data.token)
      setToken(res.data.token)
      load()
    } else {
      setError(res.data?.error ?? 'Sign in failed')
    }
  }

  return (
    <div className="page">
      <h1 className="page-title">Admin Console</h1>
      <p className="page-sub">Internal back-office tools.</p>

      {!token && (
        <form className="card" onSubmit={signIn}>
          <label className="field">
            <span>Username</span>
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
            />
          </label>
          <label className="field">
            <span>Password</span>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
            />
          </label>
          {error && <p className="form-error">{error}</p>}
          <button className="btn btn-primary">Sign in</button>
        </form>
      )}

      {token && data && (
        <>
          {error && <p className="form-error">{error}</p>}
          <h2 className="section-title">Users</h2>
          <table className="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Email</th>
                <th>Role</th>
              </tr>
            </thead>
            <tbody>
              {data.users.map((user) => (
                <tr key={user.id}>
                  <td>{user.id}</td>
                  <td>{user.username}</td>
                  <td>{user.email}</td>
                  <td>
                    <span className={`role role-${user.role}`}>{user.role}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  )
}
