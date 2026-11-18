import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { api } from '../../api/client'

export default function AccountDetailPage() {
  const { id } = useParams()
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    api(`/api/a01/accounts/${id}`).then((res) => {
      if (res.ok) {
        setData(res.data)
      } else {
        setError(res.data?.error ?? 'Could not load account')
      }
    })
  }, [id])

  if (error) {
    return (
      <div className="page">
        <h1 className="page-title">Account</h1>
        <p className="form-error">{error}</p>
      </div>
    )
  }

  if (!data) {
    return <div className="page">Loading…</div>
  }

  const account = data.account

  return (
    <div className="page">
      <h1 className="page-title">Account Detail</h1>
      <p className="page-sub">{account.account_number}</p>

      <div className="balance-panel">
        <span className="balance-label">Current balance</span>
        <span className="balance-value">
          £{Number(account.balance).toLocaleString('en-GB', { minimumFractionDigits: 2 })}
        </span>
        <span className="balance-meta">
          Sort code {account.sort_code} · {account.currency}
        </span>
      </div>

      <h2 className="section-title">Transactions</h2>
      <table className="table">
        <thead>
          <tr>
            <th>Date</th>
            <th>Direction</th>
            <th>Counterparty account</th>
            <th className="num">Amount</th>
            <th>Note</th>
          </tr>
        </thead>
        <tbody>
          {(data.transactions ?? []).map((txn) => {
            const outgoing = txn.from_account_id === account.id
            return (
              <tr key={txn.id}>
                <td>{formatDate(txn.created_at)}</td>
                <td>
                  <span className={`dir ${outgoing ? 'dir-out' : 'dir-in'}`}>
                    {outgoing ? 'Out' : 'In'}
                  </span>
                </td>
                <td>{outgoing ? txn.to_account_id : txn.from_account_id}</td>
                <td className="num">
                  {outgoing ? '−' : '+'}£{Number(txn.amount).toFixed(2)}
                </td>
                <td>{txn.note}</td>
              </tr>
            )
          })}
        </tbody>
      </table>

      {(data.transactions ?? []).length === 0 && (
        <p className="empty">No transactions on this account.</p>
      )}
    </div>
  )
}

function formatDate(value) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
}
