import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { apiGet } from '../api/client.js'
import { Button, Spinner } from '../ui/ui.jsx'

/**
 * Public OIDC sign-in page. Local recovery login is kept on /admin/login.
 */
export default function Login() {
  const [searchParams] = useSearchParams()
  const [provider, setProvider] = useState(null)
  const [loading, setLoading] = useState(true)
  const oidcError = searchParams.get('oidc_error')

  useEffect(() => {
    let alive = true
    apiGet('/api/v1/auth/oidc')
      .then((data) => { if (alive) setProvider(data) })
      .catch(() => { if (alive) setProvider(null) })
      .finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [])

  return (
    <div className="auth-split">
      <AuthBrand />
      <div className="auth-form-side">
        <section className="panel auth-card reveal">
          <div className="panel-body">
            <p className="label" style={{ color: 'var(--accent)' }}>Operator sign-in</p>
            <h2 className="auth-heading">Access the console</h2>
            {oidcError && (
              <p className="auth-error">OIDC sign-in could not be completed. Try again or contact an administrator.</p>
            )}
            {loading ? (
              <Spinner label="Loading sign-in options" />
            ) : provider?.enabled ? (
              <Button type="button" variant="accent" style={{ width: '100%' }}
                onClick={() => window.location.assign('/api/v1/auth/oidc/login')}>
                Continue with {provider.label || 'OIDC'}
              </Button>
            ) : (
              <p className="auth-notice">OIDC sign-in is not configured. Ask a local administrator to configure a provider.</p>
            )}
            <p className="auth-alt">
              Administrator recovery? <Link to="/admin/login">Use local sign-in</Link>
            </p>
          </div>
        </section>
      </div>
    </div>
  )
}

export function AuthBrand() {
  return (
    <aside className="auth-brand">
      <div className="auth-brand-grid" aria-hidden="true" />
      <div className="auth-brand-inner">
        <div className="brand" style={{ marginBottom: 28 }}>
          <span className="brand-dot" />
          <span className="brand-name" style={{ fontSize: 20 }}>cfproxy</span>
        </div>
        <h1 className="auth-brand-title">Record-scoped<br />Cloudflare DNS.</h1>
        <p className="auth-brand-sub">
          A Cloudflare-compatible proxy that mints tokens scoped to individual
          DNS records — the record-level authorization Cloudflare itself does not offer.
        </p>
        <div className="auth-brand-meta mono">
          <span>// signal control</span>
          <span>/client/v4 compatible</span>
        </div>
      </div>
    </aside>
  )
}
