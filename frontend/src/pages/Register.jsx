import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext.jsx'
import { Button, Field, Input, Spinner, useToast } from '../ui/ui.jsx'
import { AuthBrand } from './Login.jsx'

/**
 * Split-screen registration: creates a local operator account, then signs in.
 */
export default function Register() {
  const { register, login } = useAuth()
  const navigate = useNavigate()
  const toast = useToast()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)

  async function onSubmit(event) {
    event.preventDefault()
    if (password !== confirm) {
      toast.error('Passwords do not match')
      return
    }
    setBusy(true)
    try {
      await register(email, password)
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
            <p className="label" style={{ color: 'var(--accent)' }}>New operator</p>
            <h2 className="auth-heading">Create an account</h2>
            <Field label="Email">
              <Input type="email" autoComplete="username" value={email} required
                onChange={(e) => setEmail(e.target.value)} placeholder="operator@example.com" />
            </Field>
            <Field label="Password">
              <Input type="password" autoComplete="new-password" value={password} required minLength={8}
                onChange={(e) => setPassword(e.target.value)} placeholder="at least 8 characters" />
            </Field>
            <Field label="Confirm password">
              <Input type="password" autoComplete="new-password" value={confirm} required
                onChange={(e) => setConfirm(e.target.value)} placeholder="repeat password" />
            </Field>
            <Button type="submit" variant="accent" disabled={busy} style={{ width: '100%', marginTop: 6 }}>
              {busy ? <Spinner label="Creating" /> : 'Create account'}
            </Button>
            <p className="auth-alt">
              Already have one? <Link to="/login">Sign in</Link>
            </p>
          </div>
        </form>
      </div>
    </div>
  )
}
