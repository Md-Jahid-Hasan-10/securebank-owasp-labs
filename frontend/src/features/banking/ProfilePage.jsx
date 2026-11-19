import { useEffect, useState } from 'react'
import { api } from '../../api/client'

export default function ProfilePage() {
  const [profile, setProfile] = useState(null)
  const [form, setForm] = useState({ email: '' })
  const [status, setStatus] = useState(null)

  useEffect(() => {
    api('/api/a06/profile').then((res) => {
      if (res.ok) {
        setProfile(res.data)
        setForm({ email: res.data.email ?? '' })
      }
    })
  }, [])

  async function save(event) {
    event.preventDefault()
    setStatus(null)

    // FIXED: [A06-Lab15] Mass Assignment - the form used to send the role field
    // straight back to the server, and the server bound it. A trainee could edit the
    // role field in devtools to "admin" and elevate their own account.
    //
    // The client now sends only the email address. The server decides which fields a
    // client may change, so the role is not part of the request at all.
    const res = await api('/api/a06/profile', {
      method: 'PATCH',
      body: { email: form.email },
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
          <input value={profile.username} readOnly disabled />
        </label>

        <label className="field">
          <span>Email</span>
          <input
            type="email"
            value={form.email}
            onChange={(e) => setForm({ ...form, email: e.target.value })}
          />
        </label>

        {/* FIXED: [A06-Lab15] the role is shown read-only. It is not editable by the
            customer, and it is not sent to the server on save. */}
        <label className="field">
          <span>Role</span>
          <input value={profile.role} readOnly disabled />
        </label>

        {status && (
          <p className={status.ok ? 'form-ok' : 'form-error'}>{status.text}</p>
        )}

        <button className="btn btn-primary">Save changes</button>
      </form>
    </div>
  )
}
