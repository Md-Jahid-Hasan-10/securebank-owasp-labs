import { useEffect, useState } from 'react'
import { api } from '../../api/client'

export default function TransfersPage() {
  const [transfers, setTransfers] = useState([])
  const [accounts, setAccounts] = useState([])
  const [form, setForm] = useState({ from_account_id: 1, to_account_id: 2, amount: 1, note: '' })
  const [status, setStatus] = useState(null)

  function reload() {
    api('/api/a05/transfers').then((res) => {
      if (res.ok) setTransfers(res.data?.transfers ?? [])
    })
    api('/api/a01/accounts/mine').then((res) => {
      if (res.ok) setAccounts(res.data?.accounts ?? [])
    })
  }

  useEffect(reload, [])

  async function send(event) {
    event.preventDefault()
    setStatus(null)

    const res = await api('/api/a05/transfers/send', {
      method: 'POST',
      body: {
        from_account_id: Number(form.from_account_id),
        to_account_id: Number(form.to_account_id),
        amount: Number(form.amount),
        note: form.note,
      },
    })

    if (res.ok) {
      setStatus({ ok: true, text: `Transfer sent (id ${res.data.transfer_id}).` })
      setForm((current) => ({ ...current, note: '' }))
      reload()
    } else {
      setStatus({ ok: false, text: res.data?.error ?? 'Transfer failed' })
    }
  }

  return (
    <div className="page">
      <h1 className="page-title">Transfers</h1>
      <p className="page-sub">Send money between accounts.</p>

      <form className="card transfer-form" onSubmit={send}>
        <h2 className="section-title">New transfer</h2>

        <label className="field">
          <span>From account</span>
          <select
            value={form.from_account_id}
            onChange={(e) => setForm({ ...form, from_account_id: e.target.value })}
          >
            {accounts.map((account) => (
              <option key={account.id} value={account.id}>
                {account.account_number} — £{Number(account.balance).toFixed(2)}
              </option>
            ))}
          </select>
        </label>

        <label className="field">
          <span>To account</span>
          <input
            type="number"
            value={form.to_account_id}
            onChange={(e) => setForm({ ...form, to_account_id: e.target.value })}
          />
        </label>

        <label className="field">
          <span>Amount</span>
          <input
            type="number"
            step="0.01"
            value={form.amount}
            onChange={(e) => setForm({ ...form, amount: e.target.value })}
          />
        </label>

        <label className="field">
          <span>Note</span>
          <input
            value={form.note}
            onChange={(e) => setForm({ ...form, note: e.target.value })}
            placeholder="Reference for the recipient"
          />
        </label>

        {status && (
          <p className={status.ok ? 'form-ok' : 'form-error'}>{status.text}</p>
        )}

        <button className="btn btn-primary">Send transfer</button>
      </form>

      <h2 className="section-title">Recent transfers</h2>
      <table className="table">
        <thead>
          <tr>
            <th>Date</th>
            <th>From</th>
            <th>To</th>
            <th className="num">Amount</th>
            <th>Note</th>
          </tr>
        </thead>
        <tbody>
          {transfers.map((txn) => (
            <tr key={txn.id}>
              <td>{formatDate(txn.created_at)}</td>
              <td>{txn.from_account_id}</td>
              <td>{txn.to_account_id}</td>
              <td className="num">£{Number(txn.amount).toFixed(2)}</td>
              {/* VULN: [A05-Lab13] Stored XSS - the note is rendered as raw HTML.
                  A note of <img src=x onerror=alert(document.cookie)> executes for every
                  user who loads this page. The Fix tab shows the sanitised version. */}
              <td
                className="note-cell"
                dangerouslySetInnerHTML={{ __html: txn.note ?? '' }}
              />
            </tr>
          ))}
        </tbody>
      </table>

      {transfers.length === 0 && <p className="empty">No transfers yet.</p>}
    </div>
  )
}

function formatDate(value) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
}
