import { useEffect, useState } from 'react'
import { api } from '../../api/client'

export default function ProfilePage() {
  const [profile, setProfile] = useState(null)
  const [form, setForm] = useState({ username: '', email: '', role: '' })
  const [status, setStatus] = useState(null)

  useEffect(() => {
    api('/api/a06/profile').then((res) => {
      if (res.ok) {
        setProfile(res.data)
        setForm({
          username: res.data.username ?? '',
          email: res.data.email ?? '',
          role: res.data.role ?? '',
        })
      }
    })
  }, [])

  async function save(event) {
    event.preventDefault()
    setStatus(null)

    // VULN: [A06-Lab15] Mass Assignment - the form sends the role field straight back
    // to the server, and the server binds it. A trainee can edit the role field in
    // devtools to "admin" and elevate their own account. The Fix tab shows the
    // correct request shape.
    const res = await api('/api/a06/profile', {
      method: 'PATCH',
      body: form,
    })

    if (res.ok) {
      setProfile(res.data)
      setStatus({ ok: true, text: 'Profile updated.' })
    } else {
      setStatus({ ok: false, text: res.data?.error ?? 'Update failed' })
    }
  }

  if (!profile) {
    return <div className="page">Loading…</div>
  }

  return (
    <div className="page">
      <h1 className="page-title">Profile</h1>
      <p className="page-sub">Manage your personal details.</p>

      <form className="card" onSubmit={save}>
        <label className="field">
          <span>Username</span>
          <input
            value={form.username}
            onChange={(e) => setForm({ ...form, username: e.target.value })}
          />
        </label>

        <label className="field">
          <span>Email</span>
          <input
            type="email"
            value={form.email}
            onChange={(e) => setForm({ ...form, email: e.target.value })}
          />
        </label>

        <label className="field">
          <span>Role</span>
          <input
            value={form.role}
            onChange={(e) => setForm({ ...form, role: e.target.value })}
          />
        </label>

        {status && (
          <p className={status.ok ? 'form-ok' : 'form-error'}>{status.text}</p>
        )}

        <button className="btn btn-primary">Save changes</button>
      </form>
    </div>
  )
}
