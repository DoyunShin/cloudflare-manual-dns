import { useEffect, useState } from 'react'
import { apiGet } from '../api/client.js'
import {
  Badge, Button, EmptyState, Field, Input, PageHeader, Panel, Select, Spinner, Table, useToast,
} from '../ui/ui.jsx'

function fmtTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

/**
 * Filterable, paginated audit log of every allow/deny decision the proxy made.
 */
export default function Audit() {
  const toast = useToast()
  const [tokens, setTokens] = useState([])
  const [tokenId, setTokenId] = useState('')
  const [zoneId, setZoneId] = useState('')
  const [since, setSince] = useState('')
  const [page, setPage] = useState(1)
  const perPage = 25
  const [loading, setLoading] = useState(true)
  const [items, setItems] = useState([])
  const [info, setInfo] = useState({ page: 1, per_page: perPage, count: 0, total_count: 0 })

  useEffect(() => {
    apiGet('/api/v1/scoped-tokens').then((t) => setTokens(t || [])).catch(() => {})
  }, [])

  useEffect(() => {
    let alive = true
    setLoading(true)
    const qs = new URLSearchParams({ page: String(page), per_page: String(perPage) })
    if (tokenId) qs.set('token_id', tokenId)
    if (zoneId) qs.set('zone_id', zoneId)
    if (since) qs.set('since', new Date(since).toISOString())
    ;(async () => {
      try {
        const data = await apiGet(`/api/v1/audit-logs?${qs.toString()}`)
        if (!alive) return
        setItems((data && data.items) || [])
        setInfo((data && data.result_info) || { page, per_page: perPage, count: 0, total_count: 0 })
      } catch (err) {
        if (alive) toast.error(err.message)
      } finally {
        if (alive) setLoading(false)
      }
    })()
    return () => { alive = false }
  }, [tokenId, zoneId, since, page, toast])

  const totalPages = Math.max(1, Math.ceil((info.total_count || 0) / perPage))

  function applyFilters(e) {
    e.preventDefault()
    setPage(1)
  }

  return (
    <div className="reveal">
      <PageHeader title="Audit" subtitle="Every record-level decision, durably logged before the response." />

      <Panel title="Filters">
        <form className="filter-bar" onSubmit={applyFilters}>
          <Field label="Token">
            <Select value={tokenId} onChange={(e) => { setTokenId(e.target.value); setPage(1) }}>
              <option value="">All tokens</option>
              {tokens.map((t) => <option key={t.id} value={t.id}>{t.name} · {t.token_prefix}</option>)}
            </Select>
          </Field>
          <Field label="Zone id">
            <Input value={zoneId} onChange={(e) => setZoneId(e.target.value)} placeholder="zone id" />
          </Field>
          <Field label="Since">
            <Input type="datetime-local" value={since} onChange={(e) => setSince(e.target.value)} />
          </Field>
          <div className="filter-actions">
            <Button variant="accent" type="submit">Apply</Button>
            <Button variant="ghost" type="button" onClick={() => { setTokenId(''); setZoneId(''); setSince(''); setPage(1) }}>Reset</Button>
          </div>
        </form>
      </Panel>

      <Panel style={{ marginTop: 18 }}
        actions={<span className="mono muted-text">{info.total_count || 0} entries</span>}>
        {loading ? (
          <Spinner label="Loading log" />
        ) : (
          <>
            <Table
              empty={<EmptyState message="No audit entries match these filters." />}
              className="audit-table"
              columns={[
                { key: 'ts', header: 'Time', render: (r) => <span className="mono">{fmtTime(r.ts)}</span> },
                { key: 'method', header: 'Method', render: (r) => <span className="mono">{r.method}</span> },
                { key: 'decision', header: 'Decision', render: (r) => (
                  <Badge variant={r.decision === 'allow' ? 'ok' : 'bad'}>{r.decision}</Badge>
                ) },
                { key: 'record_name', header: 'Record', render: (r) => (
                  <span className="mono">{r.record_name || '—'}{r.record_type ? ` (${r.record_type})` : ''}</span>
                ) },
                { key: 'path', header: 'Path', render: (r) => (
                  <span className="mono path-cell" title={r.path}>{r.path}</span>
                ) },
                { key: 'upstream_status', header: 'CF', render: (r) => <span className="mono">{r.upstream_status ?? '—'}</span> },
                { key: 'latency_ms', header: 'ms', render: (r) => <span className="mono">{r.latency_ms ?? '—'}</span> },
                { key: 'deny_reason', header: 'Reason', render: (r) => (
                  <span className="mono muted-text" title={r.deny_reason || ''}>{r.deny_reason || ''}</span>
                ) },
              ]}
              rows={items}
              rowKey={(r) => r.id}
            />
            <div className="pager">
              <Button variant="ghost" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>Prev</Button>
              <span className="mono">page {info.page || page} / {totalPages}</span>
              <Button variant="ghost" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>Next</Button>
            </div>
          </>
        )}
      </Panel>
    </div>
  )
}
