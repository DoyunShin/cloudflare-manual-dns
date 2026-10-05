import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext.jsx'
import { Button, Field, Input, Spinner, useToast } from '../ui/ui.jsx'
import { AuthBrand } from './Login.jsx'

/**
 * Local administrator sign-in for bootstrap and recovery.
 */
export default function AdminLogin() {
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
            <p className="label" style={{ color: 'var(--accent)' }}>Recovery access</p>
            <h2 className="auth-heading">Local administrator</h2>
            <Field label="Email">
              <Input type="email" autoComplete="username" value={email} required maxLength={255}
                onChange={(e) => setEmail(e.target.value)} placeholder="admin@example.com" />
            </Field>
            <Field label="Password">
              <Input type="password" autoComplete="current-password" value={password} required minLength={8} maxLength={128}
                onChange={(e) => setPassword(e.target.value)} placeholder="password" />
            </Field>
            <Button type="submit" variant="accent" disabled={busy} style={{ width: '100%', marginTop: 6 }}>
              {busy ? <Spinner label="Signing in" /> : 'Sign in'}
            </Button>
            <p className="auth-alt"><Link to="/login">Back to OIDC sign-in</Link></p>
          </div>
        </form>
      </div>
    </div>
  )
}
