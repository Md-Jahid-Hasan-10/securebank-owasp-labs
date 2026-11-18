import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, setToken, setUser } from '../../api/client'

export default function LoginPage() {
  const [username, setUsername] = useState('alice')
  const [password, setPassword] = useState('password123')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const navigate = useNavigate()

  async function handleSubmit(event) {
    event.preventDefault()
    setBusy(true)
    setError(null)

    const res = await api('/api/auth/login', {
      method: 'POST',
      body: { username, password },
    })

    setBusy(false)

    if (res.ok && res.data?.token) {
      setToken(res.data.token)
      setUser(res.data.user)
      navigate('/banking')
      return
    }

    setError(res.data?.error ?? 'Login failed')
  }

  return (
    <div className="login-shell">
      <div className="login-card">
        <div className="login-brand">
          <span className="brand-mark">SB</span>
          <div>
            <h1>SecureBank</h1>
            <p>Internet Banking</p>
          </div>
        </div>

        <form onSubmit={handleSubmit}>
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

          <button className="btn btn-primary btn-block" disabled={busy}>
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        <div className="login-hint">
          <p className="login-hint-title">Training accounts</p>
          <ul>
            <li><code>alice / password123</code> — customer · ACC-1001</li>
            <li><code>bob / qwerty</code> — customer · ACC-1002</li>
            <li><code>admin / admin</code> — administrator</li>
          </ul>
        </div>
      </div>
    </div>
  )
}
