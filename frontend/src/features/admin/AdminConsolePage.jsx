import { useEffect, useState } from 'react'
import { api } from '../../api/client'

const ADMIN_TOKEN_KEY = 'securebank_admin_token'

export default function AdminConsolePage() {
  const [token, setToken] = useState(sessionStorage.getItem(ADMIN_TOKEN_KEY) ?? '')
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('admin')
  const [error, setError] = useState(null)
  const [tab, setTab] = useState('users')
  const [data, setData] = useState(null)
  const [newAdmin, setNewAdmin] = useState({ username: '', email: '', password: '' })
  const [notice, setNotice] = useState(null)

  useEffect(() => {
    if (!token) return
    load()
  }, [])

  // The admin console keeps its own token in sessionStorage. It must be passed
  // explicitly, otherwise the api() helper would also attach the customer's
  // token from localStorage and the request would be made as the customer.
  function adminApi(path, options = {}) {
    return api(path, { ...options, token })
  }

  function load() {
    adminApi('/api/a02/admin/users')
      .then((res) => {
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
      sessionStorage.setItem(ADMIN_TOKEN_KEY, res.data.token)
      setToken(res.data.token)
      setNotice(null)
      load()
    } else {
      setError(res.data?.error ?? 'Sign in failed')
    }
  }

  function signOut() {
    sessionStorage.removeItem(ADMIN_TOKEN_KEY)
    setToken('')
    setData(null)
    setError(null)
    setNotice(null)
  }

  async function createAdmin(event) {
    event.preventDefault()
    setError(null)
    setNotice(null)

    const res = await adminApi('/api/a02/admin/users', {
      method: 'POST',
      body: newAdmin,
    })

    if (res.ok) {
      setNotice(`Created administrator "${res.data.username}" (id ${res.data.id}).`)
      setNewAdmin({ username: '', email: '', password: '' })
      load()
    } else {
      setError(res.data?.error ?? 'Could not create administrator')
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

      {token && (
        <>
          {error && <p className="form-error">{error}</p>}
          {notice && <p className="form-notice">{notice}</p>}

          <div className="tabs">
            {[
              { key: 'users', label: 'Users' },
              { key: 'accounts', label: 'Accounts' },
              { key: 'transfers', label: 'Transfers' },
              { key: 'create', label: 'Create admin' },
            ].map((entry) => (
              <button
                key={entry.key}
                className={`tab${tab === entry.key ? ' active' : ''}`}
                onClick={() => setTab(entry.key)}
              >
                {entry.label}
              </button>
            ))}
            <button className="btn" onClick={signOut}>
              Sign out
            </button>
          </div>

          {tab === 'users' && (
            <>
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
                  {(data?.users ?? []).map((user) => (
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

          {tab === 'accounts' && <AccountsPanel token={token} />}
          {tab === 'transfers' && <TransfersPanel token={token} />}

          {tab === 'create' && (
            <form className="card" onSubmit={createAdmin}>
              <h2 className="section-title">Create administrator</h2>
              <label className="field">
                <span>Username</span>
                <input
                  value={newAdmin.username}
                  onChange={(e) => setNewAdmin({ ...newAdmin, username: e.target.value })}
                  autoComplete="off"
                />
              </label>
              <label className="field">
                <span>Email</span>
                <input
                  value={newAdmin.email}
                  onChange={(e) => setNewAdmin({ ...newAdmin, email: e.target.value })}
                  autoComplete="off"
                />
              </label>
              <label className="field">
                <span>Password</span>
                <input
                  type="password"
                  value={newAdmin.password}
                  onChange={(e) => setNewAdmin({ ...newAdmin, password: e.target.value })}
                  autoComplete="new-password"
                />
              </label>
              <button className="btn btn-primary">Create administrator</button>
            </form>
          )}
        </>
      )}
    </div>
  )
}

function AccountsPanel({ token }) {
  const [accounts, setAccounts] = useState(null)

  useEffect(() => {
    api('/api/a02/admin/accounts', { token }).then((res) => {
      if (res.ok) setAccounts(res.data?.accounts ?? [])
    })
  }, [token])

  if (!accounts) return <div className="card">Loading accounts…</div>

  return (
    <>
      <h2 className="section-title">Accounts</h2>
      <table className="table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Account number</th>
            <th>Sort code</th>
            <th>Balance</th>
            <th>Currency</th>
          </tr>
        </thead>
        <tbody>
          {accounts.map((account) => (
            <tr key={account.id}>
              <td>{account.id}</td>
              <td>{account.account_number}</td>
              <td>{account.sort_code}</td>
              <td>{account.balance}</td>
              <td>{account.currency}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  )
}

function TransfersPanel({ token }) {
  const [transfers, setTransfers] = useState(null)

  useEffect(() => {
    api('/api/a02/admin/transfers', { token }).then((res) => {
      if (res.ok) setTransfers(res.data?.transfers ?? [])
    })
  }, [token])

  if (!transfers) return <div className="card">Loading transfers…</div>

  return (
    <>
      <h2 className="section-title">Transfers</h2>
      <table className="table">
        <thead>
          <tr>
            <th>ID</th>
            <th>From</th>
            <th>To</th>
            <th>Amount</th>
            <th>Note</th>
          </tr>
        </thead>
        <tbody>
          {transfers.map((transfer) => (
            <tr key={transfer.id}>
              <td>{transfer.id}</td>
              <td>{transfer.from_account_id}</td>
              <td>{transfer.to_account_id}</td>
              <td>{transfer.amount}</td>
              <td>{transfer.note}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  )
}
