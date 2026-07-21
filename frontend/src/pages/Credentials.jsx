import { useEffect, useState } from 'react'
import { apiDelete, apiGet, apiPost } from '../api/client.js'
import {
  Badge, Button, CopyButton, EmptyState, Field, Input, Modal, PageHeader, Panel, Select, Spinner, Table, useToast,
} from '../ui/ui.jsx'

function fmtTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

function verifyVariant(status) {
  if (status === 'active') return 'ok'
  if (status === 'invalid') return 'bad'
  return 'muted'
}

/**
 * Upstream Cloudflare credential management: list, register, verify,
 * delete, and browse the zones/records a credential can see.
 */
export default function Credentials() {
  const toast = useToast()
  const [loading, setLoading] = useState(true)
  const [creds, setCreds] = useState([])
  const [addOpen, setAddOpen] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(null)
  const [browse, setBrowse] = useState(null)

  async function load() {
    setLoading(true)
    try {
      setCreds((await apiGet('/api/v1/upstream-credentials')) || [])
    } catch (err) {
      toast.error(err.message)
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => { load() }, []) // eslint-disable-line react-hooks/exhaustive-deps

  async function verify(id) {
    try {
      const updated = await apiPost(`/api/v1/upstream-credentials/${id}/verify`)
      toast.success(`Credential ${updated.verify_status}`)
      load()
    } catch (err) {
      toast.error(err.message)
    }
  }

  async function doDelete(id) {
    try {
      await apiDelete(`/api/v1/upstream-credentials/${id}`)
      toast.success('Credential deleted; dependent tokens revoked')
      setConfirmDelete(null)
      load()
    } catch (err) {
      toast.error(err.message)
    }
  }

  return (
    <div className="reveal">
      <PageHeader
        title="Credentials"
        subtitle="Broad upstream Cloudflare credentials the proxy forwards through."
        actions={<Button variant="accent" onClick={() => setAddOpen(true)}>Add credential</Button>}
      />

      <Panel>
        {loading ? (
          <Spinner label="Loading credentials" />
        ) : (
          <Table
            empty={<EmptyState message="No upstream credentials yet. Add a Cloudflare API token to begin." />}
            columns={[
              { key: 'label', header: 'Label', render: (r) => <strong>{r.label}</strong> },
              { key: 'cred_type', header: 'Type', render: (r) => (
                <Badge variant={r.cred_type === 'global_key' ? 'accent' : 'muted'}>{r.cred_type}</Badge>
              ) },
              { key: 'cf_account_email', header: 'CF account', render: (r) => (
                <span className="mono">{r.cf_account_email || '—'}</span>
              ) },
              { key: 'verify_status', header: 'Verified', render: (r) => (
                <Badge variant={verifyVariant(r.verify_status)}>{r.verify_status || 'unverified'}</Badge>
              ) },
              { key: 'created_at', header: 'Created', render: (r) => <span className="mono">{fmtTime(r.created_at)}</span> },
              { key: 'actions', header: '', render: (r) => (
                <div className="row-actions">
                  <Button variant="ghost" onClick={() => verify(r.id)}>Verify</Button>
                  <Button variant="ghost" onClick={() => setBrowse(r)}>Zones</Button>
                  <Button variant="danger" onClick={() => setConfirmDelete(r)}>Delete</Button>
                </div>
              ) },
            ]}
            rows={creds}
            rowKey={(r) => r.id}
          />
        )}
      </Panel>

      <AddCredentialModal open={addOpen} onClose={() => setAddOpen(false)} onCreated={() => { setAddOpen(false); load() }} />

      <Modal
        open={!!confirmDelete}
        onClose={() => setConfirmDelete(null)}
        title="Delete credential"
        actions={
          <>
            <Button variant="ghost" onClick={() => setConfirmDelete(null)}>Cancel</Button>
            <Button variant="danger" onClick={() => doDelete(confirmDelete.id)}>Delete and revoke tokens</Button>
          </>
        }
      >
        {confirmDelete && (
          <p>Delete <strong>{confirmDelete.label}</strong>? Every scoped token bound to it will be revoked. This cannot be undone.</p>
        )}
      </Modal>

      {browse && <BrowseZonesModal credential={browse} onClose={() => setBrowse(null)} />}
    </div>
  )
}

/**
 * Modal for registering a new upstream credential (token or global key).
 */
function AddCredentialModal({ open, onClose, onCreated }) {
  const toast = useToast()
  const [label, setLabel] = useState('')
  const [credType, setCredType] = useState('token')
  const [apiToken, setApiToken] = useState('')
  const [globalKey, setGlobalKey] = useState('')
  const [email, setEmail] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    try {
      const body = { label, cred_type: credType }
      if (credType === 'token') body.api_token = apiToken
      else { body.global_key = globalKey; body.cf_account_email = email }
      await apiPost('/api/v1/upstream-credentials', body)
      toast.success('Credential registered')
      setLabel(''); setApiToken(''); setGlobalKey(''); setEmail('')
      onCreated()
    } catch (err) {
      toast.error(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal open={open} onClose={onClose} title="Add upstream credential">
      <form onSubmit={submit}>
        <Field label="Label">
          <Input value={label} required onChange={(e) => setLabel(e.target.value)} placeholder="prod-dns-token" />
        </Field>
        <Field label="Credential type">
          <Select value={credType} onChange={(e) => setCredType(e.target.value)}>
            <option value="token">API Token (recommended)</option>
            <option value="global_key">Global API Key</option>
          </Select>
        </Field>
        {credType === 'token' ? (
          <Field label="Cloudflare API token" hint="Stored encrypted; never shown again.">
            <Input value={apiToken} required onChange={(e) => setApiToken(e.target.value)} placeholder="cloudflare API token" />
          </Field>
        ) : (
          <>
            <Field label="Cloudflare account email">
              <Input type="email" value={email} required onChange={(e) => setEmail(e.target.value)} placeholder="operator@example.com" />
            </Field>
            <Field label="Global API key" hint="Legacy full-access key; prefer a scoped API token.">
              <Input value={globalKey} required onChange={(e) => setGlobalKey(e.target.value)} placeholder="global API key" />
            </Field>
          </>
        )}
        <div className="modal-actions">
          <Button variant="ghost" type="button" onClick={onClose}>Cancel</Button>
          <Button variant="accent" type="submit" disabled={busy}>{busy ? <Spinner label="Saving" /> : 'Register'}</Button>
        </div>
      </form>
    </Modal>
  )
}

/**
 * Modal that browses a credential's zones and, on selection, its records.
 */
function BrowseZonesModal({ credential, onClose }) {
  const toast = useToast()
  const [zones, setZones] = useState(null)
  const [zone, setZone] = useState(null)
  const [records, setRecords] = useState(null)

  useEffect(() => {
    ;(async () => {
      try {
        setZones((await apiGet(`/api/v1/upstream-credentials/${credential.id}/zones`)) || [])
      } catch (err) {
        toast.error(err.message)
        setZones([])
      }
    })()
  }, [credential, toast])

  async function openZone(z) {
    setZone(z)
    setRecords(null)
    try {
      setRecords((await apiGet(`/api/v1/upstream-credentials/${credential.id}/zones/${z.id}/records`)) || [])
    } catch (err) {
      toast.error(err.message)
      setRecords([])
    }
  }

  return (
    <Modal open onClose={onClose} title={`Zones — ${credential.label}`}>
      {zones === null ? (
        <Spinner label="Loading zones" />
      ) : zones.length === 0 ? (
        <EmptyState message="This credential can see no zones (or verification failed)." />
      ) : (
        <div className="browse-grid">
          <div>
            <p className="label">Zones</p>
            <ul className="zone-list">
              {zones.map((z) => (
                <li key={z.id}>
                  <button className={`zone-item ${zone && zone.id === z.id ? 'zone-item-active' : ''}`} onClick={() => openZone(z)}>
                    <span>{z.name}</span>
                    <span className="mono zone-id">{z.id}</span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <p className="label">Records{zone ? ` — ${zone.name}` : ''}</p>
            {!zone ? (
              <EmptyState message="Select a zone to list its records." />
            ) : records === null ? (
              <Spinner label="Loading records" />
            ) : (
              <Table
                empty={<EmptyState message="No records in this zone." />}
                columns={[
                  { key: 'name', header: 'Name', render: (r) => <span className="mono">{r.name}</span> },
                  { key: 'type', header: 'Type', render: (r) => <Badge variant="muted">{r.type}</Badge> },
                  { key: 'content', header: 'Content', render: (r) => <span className="mono">{r.content}</span> },
                  { key: 'id', header: 'ID', render: (r) => (
                    <span className="row-actions"><span className="mono zone-id">{r.id}</span><CopyButton text={r.id} label="id" /></span>
                  ) },
                ]}
                rows={records}
                rowKey={(r) => r.id}
              />
            )}
          </div>
        </div>
      )}
    </Modal>
  )
}
