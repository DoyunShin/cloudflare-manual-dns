import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { apiGet, apiPost, setCsrfToken } from '../api/client.js'

const AuthContext = createContext(null)

async function fetchCurrentSession() {
  return apiGet('/api/v1/auth/me')
}

/**
 * Provide cookie-backed authentication state and actions.
 */
export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(async () => {
    try {
      const session = await fetchCurrentSession()
      setCsrfToken(session?.csrf_token)
      setUser(session?.user || null)
      return session?.user || null
    } catch {
      setCsrfToken(null)
      setUser(null)
      return null
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  const login = useCallback(async (email, password) => {
    await apiPost('/api/v1/auth/login', { email, password })
    const session = await fetchCurrentSession()
    setCsrfToken(session?.csrf_token)
    setUser(session?.user || null)
    return session?.user || null
  }, [])

  const logout = useCallback(async () => {
    await apiPost('/api/v1/auth/logout')
    setCsrfToken(null)
    setUser(null)
  }, [])

  const value = useMemo(
    () => ({ user, loading, login, logout, refresh }),
    [user, loading, login, logout, refresh],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider')
  return ctx
}

export function ProtectedRoute({ children }) {
  const { user, loading } = useAuth()
  const location = useLocation()

  if (loading) return null
  if (!user) return <Navigate to="/login" replace state={{ from: location }} />
  return children
}

export function AdminRoute({ children }) {
  const { user } = useAuth()
  if (!user?.is_admin) return <Navigate to="/" replace />
  return children
}
