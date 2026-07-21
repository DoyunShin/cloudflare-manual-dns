import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { apiGet } from '../api/client.js'
import { Badge, Button, EmptyState, PageHeader, Panel, Spinner, Table, useToast } from '../ui/ui.jsx'

/**
 * Format an ISO timestamp compactly for the console.
 */
function fmtTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

/**
 * Instrument-style stat readout.
 */
function Stat({ label, value, tone }) {
  return (
    <div className="stat">
      <span className="label stat-label">{label}</span>
      <span className="stat-value mono" style={tone ? { color: `var(--${tone})` } : undefined}>{value}</span>
    </div>
  )
}

/**
 * Overview: live counts across credentials/tokens and recent audit activity.
 */
export default function Dashboard() {
  const toast = useToast()
  const [loading, setLoading] = useState(true)
  const [creds, setCreds] = useState([])
  const [tokens, setTokens] = useState([])
  const [audit, setAudit] = useState([])

  useEffect(() => {
    let alive = true
    ;(async () => {
      try {
        const [c, t, a] = await Promise.all([
          apiGet('/api/v1/upstream-credentials'),
          apiGet('/api/v1/scoped-tokens'),
          apiGet('/api/v1/audit-logs?per_page=8'),
        ])
        if (!alive) return
        setCreds(c || [])
        setTokens(t || [])
        setAudit((a && a.items) || [])
      } catch (err) {
        if (alive) toast.error(err.message)
      } finally {
        if (alive) setLoading(false)
      }
    })()
    return () => { alive = false }
  }, [toast])

  const active = tokens.filter((t) => t.status === 'active').length
  const revoked = tokens.filter((t) => t.status === 'revoked').length
  const allows = audit.filter((a) => a.decision === 'allow').length
  const denies = audit.filter((a) => a.decision === 'deny').length

  return (
    <div className="reveal">
      <PageHeader
        title="Overview"
        subtitle="Signal summary across credentials, tokens, and proxied traffic."
        actions={
          <>
            <Link to="/credentials"><Button variant="ghost">Credentials</Button></Link>
            <Link to="/tokens"><Button variant="accent">New token</Button></Link>
          </>
        }
      />
      {loading ? (
        <Panel><Spinner label="Loading console" /></Panel>
      ) : (
        <>
          <div className="stat-grid">
            <Panel><Stat label="Upstream credentials" value={creds.length} /></Panel>
            <Panel><Stat label="Active tokens" value={active} tone="ok" /></Panel>
            <Panel><Stat label="Revoked tokens" value={revoked} tone={revoked ? 'bad' : undefined} /></Panel>
            <Panel><Stat label="Recent allow / deny" value={`${allows} / ${denies}`} tone="accent" /></Panel>
          </div>
          <Panel title="Recent activity" style={{ marginTop: 18 }}
            actions={<Link to="/audit"><Button variant="ghost">Full log</Button></Link>}>
            {audit.length === 0 ? (
              <EmptyState message="No proxied requests recorded yet." />
            ) : (
              <Table
                columns={[
                  { key: 'ts', header: 'Time', render: (r) => <span className="mono">{fmtTime(r.ts)}</span> },
                  { key: 'method', header: 'Method', render: (r) => <span className="mono">{r.method}</span> },
                  { key: 'decision', header: 'Decision', render: (r) => (
                    <Badge variant={r.decision === 'allow' ? 'ok' : 'bad'}>{r.decision}</Badge>
                  ) },
                  { key: 'record_name', header: 'Record', render: (r) => (
                    <span className="mono">{r.record_name || r.zone_id || '—'}</span>
                  ) },
                  { key: 'upstream_status', header: 'Status', render: (r) => (
                    <span className="mono">{r.upstream_status ?? '—'}</span>
                  ) },
                ]}
                rows={audit}
                rowKey={(r) => r.id}
              />
            )}
          </Panel>
        </>
      )}
    </div>
  )
}
