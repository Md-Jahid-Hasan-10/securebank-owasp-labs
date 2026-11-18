import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, getUser } from '../../api/client'

export default function DashboardPage() {
  const [accounts, setAccounts] = useState([])
  const [error, setError] = useState(null)
  const user = getUser()

  useEffect(() => {
    // The dashboard lists the signed-in customer's own accounts. Lab 1 shows that the
    // account detail endpoint does not actually enforce this ownership rule.
    api('/api/a01/accounts/mine').then((res) => {
      if (res.ok) {
        setAccounts(res.data?.accounts ?? [])
      } else {
        setError(res.data?.error ?? 'Could not load accounts')
      }
    })
  }, [])

  return (
    <div className="page">
      <h1 className="page-title">My Accounts</h1>
      <p className="page-sub">Welcome back{user ? `, ${user.username}` : ''}.</p>

      {error && <p className="form-error">{error}</p>}

      <div className="account-grid">
        {accounts.map((account) => (
          <Link key={account.id} to={`/banking/accounts/${account.id}`} className="account-card">
            <div className="account-card-top">
              <span className="account-number">{account.account_number}</span>
              <span className="account-currency">{account.currency}</span>
            </div>
            <p className="account-balance">
              £{Number(account.balance).toLocaleString('en-GB', {
                minimumFractionDigits: 2,
              })}
            </p>
            <p className="account-meta">Sort code {account.sort_code}</p>
            <p className="account-cta">View details →</p>
          </Link>
        ))}
      </div>

      {accounts.length === 0 && !error && (
        <p className="empty">No accounts found for this user.</p>
      )}
    </div>
  )
}
