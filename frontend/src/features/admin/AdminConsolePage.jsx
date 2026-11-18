import { useCallback, useEffect, useState } from 'react'
import { api } from '../../api/client'

const ADMIN_TOKEN_KEY = 'securebank_admin_token'

export default function AdminConsolePage() {
  const [token, setToken] = useState(() => sessionStorage.getItem(ADMIN_TOKEN_KEY) ?? '')
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('admin')
  const [error, setError] = useState(null)
  const [tab, setTab] = useState('users')
  const [data, setData] = useState(null)
  const [newAdmin, setNewAdmin] = useState({ username: '', email: '', password: '' })
  const [notice, setNotice] = useState(null)

  // FIXED: [A02-Lab5] the seeded administrator is flagged for a mandatory password
  // change, so it is refused a session until the password has been replaced. The
  // console has to offer that change, otherwise the operator has no way in at all.
  const [mustChange, setMustChange] = useState(false)
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [passwordError, setPasswordError] = useState(null)

  // The admin console keeps its own token in sessionStorage. It must be passed
  // explicitly, otherwise the api() helper would also attach the customer's
  // token from localStorage and the request would be made as the customer.
  const adminApi = useCallback(
    (path, options = {}) => api(path, { ...options, token }),
    [token],
  )

  const load = useCallback(async () => {
    const res = await adminApi('/api/a02/admin/users')
    if (res.ok) {
      setData(res.data)
      setError(null)
    } else {
      setError(res.data?.error ?? 'Could not load admin data')
    }
  }, [adminApi])

  // Runs on mount and whenever the token changes, so a reload with a token
  // already in sessionStorage restores the console straight away.
  useEffect(() => {
    if (!token) return
    load()
  }, [token, load])

  async function signIn(event) {
    event.preventDefault()
    setError(null)
    setNotice(null)

    const res = await api('/api/a02/admin/login', {
      method: 'POST',
      body: { username, password },
    })

    if (res.ok && res.data?.token) {
      sessionStorage.setItem(ADMIN_TOKEN_KEY, res.data.token)
      setToken(res.data.token)
    } else if (res.status === 403 && res.data?.must_change_password) {
      // The account exists and the password is right, but it has to be changed
      // first. Show the change form instead of a bare error.
      setMustChange(true)
      setCurrentPassword(password)
      setError(res.data?.error ?? 'Password must be changed before this account can be used')
    } else {
      setError(res.data?.error ?? 'Sign in failed')
    }
  }

  async function changePassword(event) {
    event.preventDefault()
    setPasswordError(null)

    if (newPassword !== confirmPassword) {
      setPasswordError('The new passwords do not match')
      return
    }
    if (newPassword.length < 12) {
      setPasswordError('The new password must be at least 12 characters')
      return
    }

    // FIXED: [A02-Lab5] this endpoint proves identity with the username and the
    // current password rather than with a session, because the account has no
    // session yet - that is the whole point of the flag.
    const res = await api('/api/a02/admin/password', {
      method: 'POST',
      body: {
        username,
        current_password: currentPassword,
        new_password: newPassword,
      },
    })

    if (res.ok) {
      setNotice('Password changed - you can sign in now.')
      setMustChange(false)
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
      setPassword(newPassword)
    } else {
      setPasswordError(res.data?.error ?? 'Could not change the password')
    }
  }

  function signOut() {
    sessionStorage.removeItem(ADMIN_TOKEN_KEY)
    setToken('')
    setData(null)
    setError(null)
    setNotice(null)
    setTab('users')
    setMustChange(false)
    setPasswordError(null)
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

      {!token && !mustChange && (
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
          <button className="btn btn-primary" type="submit">Sign in</button>
        </form>
      )}

      {mustChange && (
        <form className="card" onSubmit={changePassword}>
          <h2 className="section-title">Change your password</h2>
          <p className="page-sub">
            This account is still using its factory password. Replace it before the
            account can be used.
          </p>
          <label className="field">
            <span>Current password</span>
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              autoComplete="current-password"
            />
          </label>
          <label className="field">
            <span>New password (at least 12 characters)</span>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              autoComplete="new-password"
            />
          </label>
          <label className="field">
            <span>Confirm new password</span>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              autoComplete="new-password"
            />
          </label>
          {passwordError && <p className="form-error">{passwordError}</p>}
          <button className="btn btn-primary" type="submit">Change password</button>
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
                type="button"
                className={`tab${tab === entry.key ? ' active' : ''}`}
                onClick={() => setTab(entry.key)}
              >
                {entry.label}
              </button>
            ))}
            <button className="btn" type="button" onClick={signOut}>
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
              {(data?.users ?? []).length === 0 && !error && (
                <p className="form-error">No users loaded. The request may have failed - try Sign out and back in.</p>
              )}
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
              <button className="btn btn-primary" type="submit">Create administrator</button>
            </form>
          )}
        </>
      )}
    </div>
  )
}

function AccountsPanel({ token }) {
  const [accounts, setAccounts] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    api('/api/a02/admin/accounts', { token }).then((res) => {
      if (res.ok) {
        setAccounts(res.data?.accounts ?? [])
        setError(null)
      } else {
        setError(res.data?.error ?? 'Could not load accounts')
      }
    })
  }, [token])

  if (error) return <p className="form-error">{error}</p>
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
  const [error, setError] = useState(null)

  useEffect(() => {
    api('/api/a02/admin/transfers', { token }).then((res) => {
      if (res.ok) {
        setTransfers(res.data?.transfers ?? [])
        setError(null)
      } else {
        setError(res.data?.error ?? 'Could not load transfers')
      }
    })
  }, [token])

  if (error) return <p className="form-error">{error}</p>
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
