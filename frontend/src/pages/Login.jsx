import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext.jsx'
import { Button, Field, Input, Spinner, useToast } from '../ui/ui.jsx'

/**
 * Split-screen login: branded Signal Control panel + credential form,
 * with a secondary Cloudflare OAuth entry point.
 */
export default function Login() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const toast = useToast()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)

  async function onSubmit(event) {
    event.preventDefault()
    setBusy(true)
    try {
      await login(email, password)
      navigate('/')
    } catch (err) {
      toast.error(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="auth-split">
      <AuthBrand />
      <div className="auth-form-side">
        <form className="panel auth-card reveal" onSubmit={onSubmit}>
          <div className="panel-body">
            <p className="label" style={{ color: 'var(--accent)' }}>Operator sign-in</p>
            <h2 className="auth-heading">Access the console</h2>
            <Field label="Email">
              <Input type="email" autoComplete="username" value={email} required
                onChange={(e) => setEmail(e.target.value)} placeholder="operator@example.com" />
            </Field>
            <Field label="Password">
              <Input type="password" autoComplete="current-password" value={password} required
                onChange={(e) => setPassword(e.target.value)} placeholder="password" />
            </Field>
            <Button type="submit" variant="accent" disabled={busy} style={{ width: '100%', marginTop: 6 }}>
              {busy ? <Spinner label="Signing in" /> : 'Sign in'}
            </Button>
            <div className="auth-divider"><span>or</span></div>
            <Button type="button" variant="ghost" style={{ width: '100%' }}
              onClick={() => { window.location.href = '/api/v1/auth/cf/login' }}>
              Continue with Cloudflare
            </Button>
            <p className="auth-alt">
              No account? <Link to="/register">Create one</Link>
            </p>
          </div>
        </form>
      </div>
    </div>
  )
}

/**
 * Shared branded panel rendered on the left of the auth screens.
 */
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
