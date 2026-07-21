import { useEffect, useState } from 'react'
import { apiDelete, apiGet, apiPost } from '../api/client.js'
import {
  Badge, Button, Code, CopyButton, EmptyState, Field, Input, Modal, PageHeader, Panel, Select, Spinner, Table, Toggle, useToast,
} from '../ui/ui.jsx'

const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'NS', 'SRV', 'CAA']

function fmtTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

function statusVariant(s) {
  return s === 'active' ? 'ok' : 'bad'
}

/**
 * Scoped-token management: list, detail (rules), rotate, revoke, and the
 * mint wizard with the record-level scope-rule builder.
 */
export default function Tokens() {
  const toast = useToast()
  const [loading, setLoading] = useState(true)
  const [tokens, setTokens] = useState([])
  const [mintOpen, setMintOpen] = useState(false)
  const [reveal, setReveal] = useState(null)
  const [detail, setDetail] = useState(null)
  const [confirmRevoke, setConfirmRevoke] = useState(null)

  async function load() {
    setLoading(true)
    try {
      setTokens((await apiGet('/api/v1/scoped-tokens')) || [])
    } catch (err) {
      toast.error(err.message)
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => { load() }, []) // eslint-disable-line react-hooks/exhaustive-deps

  async function rotate(id) {
    try {
      const data = await apiPost(`/api/v1/scoped-tokens/${id}/rotate`)
      setReveal({ token: data.token, prefix: data.token_prefix, title: 'Rotated token' })
      load()
    } catch (err) {
      toast.error(err.message)
    }
  }

  async function revoke(id) {
    try {
      await apiDelete(`/api/v1/scoped-tokens/${id}`)
      toast.success('Token revoked')
      setConfirmRevoke(null)
      load()
    } catch (err) {
      toast.error(err.message)
    }
  }

  async function openDetail(id) {
    setDetail({ loading: true })
    try {
      setDetail({ loading: false, data: await apiGet(`/api/v1/scoped-tokens/${id}`) })
    } catch (err) {
      toast.error(err.message)
      setDetail(null)
    }
  }

  return (
    <div className="reveal">
      <PageHeader
        title="Tokens"
        subtitle="Service tokens scoped to specific DNS records. Hand these to Cloudflare clients."
        actions={<Button variant="accent" onClick={() => setMintOpen(true)}>New token</Button>}
      />

      <Panel>
        {loading ? (
          <Spinner label="Loading tokens" />
        ) : (
          <Table
            empty={<EmptyState message="No scoped tokens yet. Mint one to grant record-level access." />}
            columns={[
              { key: 'name', header: 'Name', render: (r) => <strong>{r.name}</strong> },
              { key: 'token_prefix', header: 'Prefix', render: (r) => <span className="mono">{r.token_prefix}</span> },
              { key: 'status', header: 'Status', render: (r) => <Badge variant={statusVariant(r.status)}>{r.status}</Badge> },
              { key: 'version', header: 'Ver', render: (r) => <span className="mono">{r.version}</span> },
              { key: 'last_used_at', header: 'Last used', render: (r) => <span className="mono">{fmtTime(r.last_used_at)}</span> },
              { key: 'expires_at', header: 'Expires', render: (r) => <span className="mono">{r.expires_at ? fmtTime(r.expires_at) : 'never'}</span> },
              { key: 'actions', header: '', render: (r) => (
                <div className="row-actions">
                  <Button variant="ghost" onClick={() => openDetail(r.id)}>Detail</Button>
                  <Button variant="ghost" disabled={r.status !== 'active'} onClick={() => rotate(r.id)}>Rotate</Button>
                  <Button variant="danger" disabled={r.status !== 'active'} onClick={() => setConfirmRevoke(r)}>Revoke</Button>
                </div>
              ) },
            ]}
            rows={tokens}
            rowKey={(r) => r.id}
          />
        )}
      </Panel>

      {mintOpen && (
        <MintModal
          onClose={() => setMintOpen(false)}
          onMinted={(data) => { setMintOpen(false); setReveal({ token: data.token, prefix: data.token_prefix, title: 'New token' }); load() }}
        />
      )}

      <RevealTokenModal reveal={reveal} onClose={() => setReveal(null)} />

      <Modal open={!!detail} onClose={() => setDetail(null)} title="Token detail">
        {detail?.loading ? <Spinner label="Loading" /> : detail?.data ? <TokenDetail token={detail.data} /> : null}
      </Modal>

      <Modal
        open={!!confirmRevoke}
        onClose={() => setConfirmRevoke(null)}
        title="Revoke token"
        actions={
          <>
            <Button variant="ghost" onClick={() => setConfirmRevoke(null)}>Cancel</Button>
            <Button variant="danger" onClick={() => revoke(confirmRevoke.id)}>Revoke now</Button>
          </>
        }
      >
        {confirmRevoke && <p>Revoke <strong>{confirmRevoke.name}</strong> (<span className="mono">{confirmRevoke.token_prefix}</span>)? It stops working immediately.</p>}
      </Modal>
    </div>
  )
}

/**
 * One-time reveal of a raw token secret with copy + a do-not-lose warning.
 */
function RevealTokenModal({ reveal, onClose }) {
  if (!reveal) return null
  return (
    <Modal open onClose={onClose} title={reveal.title}
      actions={<Button variant="accent" onClick={onClose}>Done</Button>}>
      <p style={{ color: 'var(--accent)' }} className="label">Shown once — copy it now</p>
      <Code>{reveal.token}</Code>
      <div className="row-actions" style={{ marginTop: 10 }}>
        <CopyButton text={reveal.token} label="Copy token" />
        <span className="mono muted-text">prefix {reveal.prefix}</span>
      </div>
      <p className="field-hint">Store it securely. It cannot be retrieved again — rotate to issue a new one.</p>
    </Modal>
  )
}

/**
 * Read-only detail view: token metadata + its scope rules.
 */
function TokenDetail({ token }) {
  return (
    <div>
      <div className="detail-meta">
        <span><span className="label">status</span> <Badge variant={statusVariant(token.status)}>{token.status}</Badge></span>
        <span><span className="label">version</span> <span className="mono">{token.version}</span></span>
        <span><span className="label">prefix</span> <span className="mono">{token.token_prefix}</span></span>
        <span><span className="label">created</span> <span className="mono">{fmtTime(token.created_at)}</span></span>
      </div>
      <p className="label" style={{ marginTop: 16 }}>Scope rules ({token.rules?.length || 0})</p>
      {(token.rules || []).map((r) => (
        <div key={r.id} className="rule-view">
          <div className="rule-view-head">
            <span className="mono">{r.name_pattern || '(record-id scoped)'}</span>
            <Badge variant="muted">{r.name_match}</Badge>
          </div>
          <div className="rule-view-body mono">
            <span>zone {r.zone_id}</span>
            <span>types {(r.record_types || []).join(', ')}</span>
            {r.record_ids && r.record_ids.length > 0 && <span>ids {r.record_ids.join(', ')}</span>}
          </div>
          <div className="row-actions">
            <Badge variant={r.allow_read ? 'ok' : 'muted'}>read</Badge>
            <Badge variant={r.allow_create ? 'ok' : 'muted'}>create</Badge>
            <Badge variant={r.allow_write ? 'ok' : 'muted'}>write</Badge>
            <Badge variant={r.allow_delete ? 'ok' : 'muted'}>delete</Badge>
          </div>
        </div>
      ))}
    </div>
  )
}

function emptyRule() {
  return {
    zone_id: '', name_match: 'exact', name_pattern: '', anyType: false,
    record_types: ['A'], record_ids: [], allow_read: true, allow_create: false, allow_write: false, allow_delete: false,
  }
}

/**
 * Mint wizard: pick a credential, build one or more record-scope rules, submit.
 */
function MintModal({ onClose, onMinted }) {
  const toast = useToast()
  const [creds, setCreds] = useState([])
  const [name, setName] = useState('')
  const [credId, setCredId] = useState('')
  const [zones, setZones] = useState([])
  const [rules, setRules] = useState([emptyRule()])
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    apiGet('/api/v1/upstream-credentials').then((c) => setCreds(c || [])).catch((e) => toast.error(e.message))
  }, [toast])

  useEffect(() => {
    if (!credId) { setZones([]); return }
    apiGet(`/api/v1/upstream-credentials/${credId}/zones`).then((z) => setZones(z || [])).catch(() => setZones([]))
  }, [credId])

  function patchRule(i, patch) {
    setRules((rs) => rs.map((r, idx) => (idx === i ? { ...r, ...patch } : r)))
  }

  async function submit(e) {
    e.preventDefault()
    for (const r of rules) {
      const hasName = r.name_pattern.trim() !== ''
      const hasIds = r.record_ids.length > 0
      if (!r.zone_id) { toast.error('Each rule needs a zone'); return }
      if (!hasName && !hasIds) { toast.error('Each rule needs a name pattern or record ids'); return }
    }
    const body = {
      name,
      upstream_credential_id: credId,
      scope_rules: rules.map((r) => ({
        zone_id: r.zone_id,
        name_pattern: r.name_pattern.trim() || null,
        name_match: r.name_match,
        record_types: r.anyType ? ['*'] : r.record_types,
        record_ids: r.record_ids.length > 0 ? r.record_ids : null,
        allow_read: r.allow_read,
        allow_create: r.allow_create,
        allow_write: r.allow_write,
        allow_delete: r.allow_delete,
      })),
    }
    setBusy(true)
    try {
      onMinted(await apiPost('/api/v1/scoped-tokens', body))
    } catch (err) {
      toast.error(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal open onClose={onClose} title="Mint scoped token">
      <form onSubmit={submit}>
        <div className="mint-top">
          <Field label="Token name">
            <Input value={name} required onChange={(e) => setName(e.target.value)} placeholder="staging-acme-dns" />
          </Field>
          <Field label="Upstream credential" hint="The broad credential this token forwards through.">
            <Select value={credId} required onChange={(e) => setCredId(e.target.value)}>
              <option value="">Select credential…</option>
              {creds.map((c) => <option key={c.id} value={c.id}>{c.label} · {c.cred_type}</option>)}
            </Select>
          </Field>
        </div>

        <div className="rules-head">
          <p className="label">Scope rules</p>
          <Button type="button" variant="ghost" onClick={() => setRules((rs) => [...rs, emptyRule()])}>+ Add rule</Button>
        </div>

        {rules.map((rule, i) => (
          <RuleEditor
            key={i}
            index={i}
            rule={rule}
            zones={zones}
            credId={credId}
            onPatch={(patch) => patchRule(i, patch)}
            onRemove={rules.length > 1 ? () => setRules((rs) => rs.filter((_, idx) => idx !== i)) : null}
          />
        ))}

        <div className="modal-actions">
          <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="accent" disabled={busy || !credId}>{busy ? <Spinner label="Minting" /> : 'Mint token'}</Button>
        </div>
      </form>
    </Modal>
  )
}

/**
 * Editor for a single scope rule inside the mint wizard.
 */
function RuleEditor({ index, rule, zones, credId, onPatch, onRemove }) {
  const toast = useToast()
  const [records, setRecords] = useState(null)
  const [picker, setPicker] = useState(false)

  async function loadRecords() {
    setPicker(true)
    if (records !== null) return
    try {
      setRecords((await apiGet(`/api/v1/upstream-credentials/${credId}/zones/${rule.zone_id}/records`)) || [])
    } catch (err) {
      toast.error(err.message)
      setRecords([])
    }
  }

  function toggleType(t) {
    const has = rule.record_types.includes(t)
    onPatch({ record_types: has ? rule.record_types.filter((x) => x !== t) : [...rule.record_types, t] })
  }

  function addId(id) {
    if (id && !rule.record_ids.includes(id)) onPatch({ record_ids: [...rule.record_ids, id] })
  }

  return (
    <div className="rule-editor">
      <div className="rule-editor-head">
        <span className="label">Rule {index + 1}</span>
        {onRemove && <button type="button" className="copy-btn" onClick={onRemove}>remove</button>}
      </div>

      <div className="rule-grid">
        <Field label="Zone">
          <Select value={rule.zone_id} onChange={(e) => onPatch({ zone_id: e.target.value })}>
            <option value="">Select zone…</option>
            {zones.map((z) => <option key={z.id} value={z.id}>{z.name}</option>)}
          </Select>
        </Field>
        <Field label="Name match">
          <Select value={rule.name_match} onChange={(e) => onPatch({ name_match: e.target.value })}>
            <option value="exact">exact</option>
            <option value="wildcard">wildcard</option>
          </Select>
        </Field>
        <Field label="Name pattern" hint="wildcard = single label, e.g. *.example.com. Empty = scope by record ids only.">
          <Input value={rule.name_pattern} onChange={(e) => onPatch({ name_pattern: e.target.value })}
            placeholder={rule.name_match === 'wildcard' ? '*.example.com' : 'home.example.com'} />
        </Field>
      </div>

      <div className="rule-types">
        <span className="label">Record types</span>
        <div className="type-chips">
          <Toggle checked={rule.anyType} onChange={(v) => onPatch({ anyType: v })} label="any (*)" />
          {RECORD_TYPES.map((t) => (
            <button type="button" key={t} disabled={rule.anyType}
              className={`type-chip ${rule.record_types.includes(t) && !rule.anyType ? 'type-chip-on' : ''}`}
              onClick={() => toggleType(t)}>{t}</button>
          ))}
        </div>
      </div>

      <div className="rule-ids">
        <div className="rules-head">
          <span className="label">Record ids (optional pin)</span>
          <button type="button" className="copy-btn" disabled={!rule.zone_id} onClick={loadRecords}>pick from zone</button>
        </div>
        <div className="id-chips">
          {rule.record_ids.map((id) => (
            <span key={id} className="id-chip mono">{id}
              <button type="button" onClick={() => onPatch({ record_ids: rule.record_ids.filter((x) => x !== id) })}>×</button>
            </span>
          ))}
          <input className="input id-input" placeholder="record id + Enter"
            onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addId(e.target.value.trim()); e.target.value = '' } }} />
        </div>
        {picker && (
          <div className="record-picker">
            {records === null ? <Spinner label="Loading records" /> : records.length === 0 ? (
              <span className="muted-text">No records in this zone.</span>
            ) : records.map((rec) => (
              <button type="button" key={rec.id} className="record-pick" onClick={() => addId(rec.id)}>
                <span className="mono">{rec.name}</span>
                <span className="mono muted-text">{rec.type}</span>
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="rule-perms">
        <span className="label">Permissions</span>
        <div className="perm-row">
          <Toggle checked={rule.allow_read} onChange={(v) => onPatch({ allow_read: v })} label="read" />
          <Toggle checked={rule.allow_create} onChange={(v) => onPatch({ allow_create: v })} label="create" />
          <Toggle checked={rule.allow_write} onChange={(v) => onPatch({ allow_write: v })} label="write" />
          <Toggle checked={rule.allow_delete} onChange={(v) => onPatch({ allow_delete: v })} label="delete" />
        </div>
      </div>
    </div>
  )
}
