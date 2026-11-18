import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { api } from '../../api/client'
import Markdown from './Markdown'

const TABS = [
  { key: 'exploit', label: 'Exploit Steps' },
  { key: 'code', label: 'Affected Code' },
  { key: 'hint', label: 'Hint' },
  { key: 'fix', label: 'Fix' },
]

export default function LabDetailPage() {
  const { labId } = useParams()
  const [lab, setLab] = useState(null)
  const [tab, setTab] = useState('exploit')

  useEffect(() => {
    api(`/api/labs/${labId}`).then((res) => {
      if (res.ok) {
        setLab(res.data)
        setTab('exploit')
      }
    })
  }, [labId])

  if (!lab) {
    return <div className="card">Loading lab…</div>
  }

  return (
    <div className="lab-page">
      <header className="lab-header">
        <div>
          <p className="lab-eyebrow">
            <span className="cat-code">{lab.category}</span>
            {lab.categoryName}
          </p>
          <h1>
            <span className="lab-num-lg">Lab {lab.id}</span> {lab.title}
          </h1>
          <p className="lab-objective">{lab.objective}</p>
        </div>
        <span className={`sev-badge ${sevClass(lab.severity)}`}>{lab.severity}</span>
      </header>

      <div className="tabs">
        {TABS.map((entry) => (
          <button
            key={entry.key}
            className={`tab${tab === entry.key ? ' active' : ''}`}
            onClick={() => setTab(entry.key)}
          >
            {entry.label}
          </button>
        ))}
      </div>

      <div className="tab-body">
        {tab === 'exploit' && <Markdown source={lab.exploit} />}
        {tab === 'code' && (
          <>
            <p className="code-path">{lab.source}</p>
            {lab.vulnTags?.length > 0 && (
              <p className="vuln-tags">
                {lab.vulnTags.map((tag) => (
                  <span key={tag} className="vuln-tag">
                    VULN: [{tag}]
                  </span>
                ))}
              </p>
            )}
            <pre className="code-block">
              <code>{lab.code}</code>
            </pre>
          </>
        )}
        {tab === 'hint' && <Markdown source={lab.hint} />}
        {tab === 'fix' && <Markdown source={lab.fix} />}
      </div>
    </div>
  )
}

function sevClass(severity) {
  return `sev-${severity.toLowerCase()}`
}
