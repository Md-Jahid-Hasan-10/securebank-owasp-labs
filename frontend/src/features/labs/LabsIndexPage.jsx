import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../../api/client'

export default function LabsIndexPage() {
  const [labs, setLabs] = useState([])

  useEffect(() => {
    api('/api/labs').then((res) => {
      if (res.ok) setLabs(res.data?.labs ?? [])
    })
  }, [])

  return (
    <div className="page">
      <h1 className="page-title">Security Labs</h1>
      <p className="page-sub">
        25 intentionally vulnerable scenarios across the OWASP Top 10 (2025).
      </p>

      <div className="lab-index-grid">
        {labs.map((lab) => (
          <Link key={lab.id} to={`/lab/${lab.id}`} className="lab-index-card">
            <div className="lab-index-top">
              <span className="cat-code">{lab.category}</span>
              <span className={`sev-badge sev-${lab.severity.toLowerCase()}`}>
                {lab.severity}
              </span>
            </div>
            <h3>
              <span className="lab-num">Lab {lab.id}</span> {lab.title}
            </h3>
            <p>{lab.objective}</p>
          </Link>
        ))}
      </div>
    </div>
  )
}
