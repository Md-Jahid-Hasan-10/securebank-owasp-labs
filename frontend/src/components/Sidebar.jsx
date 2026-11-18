import { NavLink } from 'react-router-dom'

const SEVERITY_CLASS = {
  Low: 'sev-low',
  Medium: 'sev-medium',
  High: 'sev-high',
}

export default function Sidebar({ labs }) {
  const categories = labs?.categories ?? []
  const byId = new Map((labs?.labs ?? []).map((lab) => [lab.id, lab]))

  return (
    <aside className="sidebar">
      <nav className="side-section">
        <p className="side-heading">BANKING</p>
        <SideLink to="/banking" label="Dashboard" end />
        <SideLink to="/banking/transfers" label="Transfers" />
        <SideLink to="/banking/profile" label="Profile" />
        <SideLink to="/admin-console" label="Admin Console" />
      </nav>

      <nav className="side-section side-labs">
        <p className="side-heading">OWASP LABS</p>
        {categories.length === 0 && (
          <p className="side-empty">Loading labs…</p>
        )}
        {categories.map((category) => (
          <div key={category.code} className="lab-group">
            <p className="lab-group-title">
              <span className="cat-code">{category.code}</span>
              {category.name}
            </p>
            <ul>
              {category.labs.map((id) => {
                const lab = byId.get(id)
                if (!lab) return null
                return (
                  <li key={id}>
                    <NavLink to={`/lab/${id}`} className="lab-link">
                      <span className="lab-num">{String(id).padStart(2, '0')}</span>
                      <span className="lab-title">{lab.title}</span>
                      <span
                        className={`sev ${SEVERITY_CLASS[lab.severity] ?? ''}`}
                        title={`${lab.severity} severity`}
                      >
                        {lab.severity.charAt(0)}
                      </span>
                    </NavLink>
                  </li>
                )
              })}
            </ul>
          </div>
        ))}
      </nav>
    </aside>
  )
}

function SideLink({ to, label, end }) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) => `side-link${isActive ? ' active' : ''}`}
    >
      {label}
    </NavLink>
  )
}
