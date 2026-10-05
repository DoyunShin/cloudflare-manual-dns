import { useEffect, useState } from 'react'
import { apiGet, apiPost, apiPut } from '../api/client.js'
import {
  Badge, Button, Field, Input, PageHeader, Panel, Spinner, TextArea, Toggle, useToast,
} from '../ui/ui.jsx'

const EMPTY_CONFIG = {
  enabled: false,
  label: 'OIDC',
  issuer: '',
  client_id: '',
  client_secret: '',
  scopes: 'openid profile email',
  allowed_endpoint_origins: '',
  allow_private_network: false,
  has_secret: false,
}

function toForm(config) {
  return {
    ...EMPTY_CONFIG,
    ...config,
    client_secret: '',
    allowed_endpoint_origins: (config?.allowed_endpoint_origins || []).join('\n'),
  }
}

function toPayload(form) {
  const payload = {
    enabled: form.enabled,
    label: form.label.trim(),
    issuer: form.issuer.trim(),
    client_id: form.client_id.trim(),
    scopes: form.scopes.trim(),
    allowed_endpoint_origins: form.allowed_endpoint_origins
      .split(/\r?\n/)
      .map((value) => value.trim())
      .filter(Boolean),
    allow_private_network: form.allow_private_network,
  }
  if (form.client_secret) payload.client_secret = form.client_secret
  return payload
}

/**
 * Administrator-managed generic OIDC provider configuration.
 */
export default function OidcSettings() {
  const toast = useToast()
  const [form, setForm] = useState(EMPTY_CONFIG)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)

  useEffect(() => {
    let alive = true
    apiGet('/api/v1/admin/oidc')
      .then((data) => { if (alive) setForm(toForm(data)) })
      .catch((err) => { if (alive) toast.error(err.message) })
      .finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [toast])

  function patch(field, value) {
    setForm((current) => ({ ...current, [field]: value }))
  }

  async function save(event) {
    event.preventDefault()
    setSaving(true)
    try {
      const saved = await apiPut('/api/v1/admin/oidc', toPayload(form))
      setForm(toForm(saved))
      toast.success('OIDC configuration saved')
    } catch (err) {
      toast.error(err.message)
    } finally {
      setSaving(false)
    }
  }

  async function testConnection() {
    setTesting(true)
    try {
      await apiPost('/api/v1/admin/oidc/test', toPayload(form))
      toast.success('Discovery and JWKS validation succeeded')
    } catch (err) {
      toast.error(err.message)
    } finally {
      setTesting(false)
    }
  }

  return (
    <div className="reveal">
      <PageHeader
        title="OIDC"
        subtitle="Configure the identity provider used for sign-in. Service permissions remain local."
        actions={<Badge variant={form.enabled ? 'ok' : 'muted'}>{form.enabled ? 'enabled' : 'disabled'}</Badge>}
      />
      <Panel>
        {loading ? <Spinner label="Loading OIDC configuration" /> : (
          <form onSubmit={save}>
            <div className="settings-grid">
              <Field label="Provider label">
                <Input value={form.label} required maxLength={255}
                  onChange={(e) => patch('label', e.target.value)} placeholder="Corporate SSO" />
              </Field>
              <Field label="Issuer URL">
                <Input type="url" value={form.issuer} required
                  onChange={(e) => patch('issuer', e.target.value)} placeholder="https://id.example.com/tenant" />
              </Field>
              <Field label="Client ID">
                <Input value={form.client_id} required
                  onChange={(e) => patch('client_id', e.target.value)} placeholder="cfproxy" />
              </Field>
              <Field label="Client secret" hint={form.has_secret
                ? 'A secret is stored. Leave blank to keep it unchanged.'
                : 'Required before the provider can be enabled.'}>
                <Input type="password" value={form.client_secret} autoComplete="new-password"
                  onChange={(e) => patch('client_secret', e.target.value)} placeholder={form.has_secret ? 'stored' : 'client secret'} />
              </Field>
              <Field label="Scopes" hint="Space-separated. openid is required.">
                <Input value={form.scopes} required
                  onChange={(e) => patch('scopes', e.target.value)} placeholder="openid profile email" />
              </Field>
              <Field label="Additional endpoint origins"
                hint="One HTTPS origin per line. The issuer origin is always allowed.">
                <TextArea value={form.allowed_endpoint_origins}
                  onChange={(e) => patch('allowed_endpoint_origins', e.target.value)}
                  placeholder={'https://login.example.com\nhttps://userinfo.example.com'} />
              </Field>
            </div>
            <div className="settings-switches">
              <Toggle checked={form.allow_private_network}
                onChange={(value) => patch('allow_private_network', value)}
                label="Allow private network endpoints" />
              <Toggle checked={form.enabled}
                onChange={(value) => patch('enabled', value)}
                label="Enable OIDC sign-in" />
            </div>
            <p className="field-hint">
              The connection test validates provider discovery and signing keys. It does not validate the client secret.
            </p>
            <div className="form-actions">
              <Button type="button" variant="ghost" disabled={testing || saving} onClick={testConnection}>
                {testing ? <Spinner label="Testing" /> : 'Test connection'}
              </Button>
              <Button type="submit" variant="accent" disabled={saving || testing}>
                {saving ? <Spinner label="Saving" /> : 'Save configuration'}
              </Button>
            </div>
          </form>
        )}
      </Panel>
    </div>
  )
}
