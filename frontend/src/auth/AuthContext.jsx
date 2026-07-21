import { createContext, useContext, useEffect, useState, useCallback } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { apiGet, apiPost, getToken, setToken, clearToken } from '../api/client.js'

const AuthContext = createContext(null)

/**
 * Fetch the current authenticated user from the management API.
 *
 * Return:
 *     user(object): UserResponse payload
 */
function fetchCurrentUser() {
  return apiGet('/api/v1/auth/me')
}

/**
 * Provide authentication state (current user, loading flag) and the
 * login/register/logout/refresh actions to the component tree.
 *
 * Args:
 *     children(ReactNode): wrapped application tree
 */
export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(async () => {
    if (!getToken()) {
      setUser(null)
      setLoading(false)
      return
    }
    try {
      const me = await fetchCurrentUser()
      setUser(me)
    } catch {
      clearToken()
      setUser(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  const login = useCallback(async (email, password) => {
    const data = await apiPost('/api/v1/auth/login', { email, password })
    setToken(data.access_token)
    const me = await fetchCurrentUser()
    setUser(me)
    return me
  }, [])

  const register = useCallback(async (email, password) => {
    return apiPost('/api/v1/auth/register', { email, password })
  }, [])

  const logout = useCallback(() => {
    clearToken()
    setUser(null)
  }, [])

  const value = { user, loading, login, register, logout, refresh }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

/**
 * Access the current authentication state and actions.
 *
 * Return:
 *     ctx(object): {user, loading, login, register, logout, refresh}
 */
export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return ctx
}

/**
 * Route guard that redirects to /login when there is no authenticated
 * user once the initial auth check has finished.
 *
 * Args:
 *     children(ReactNode): protected route tree
 */
export function ProtectedRoute({ children }) {
  const { user, loading } = useAuth()
  const location = useLocation()

  if (loading) {
    return null
  }

  if (!user) {
    return <Navigate to="/login" replace state={{ from: location }} />
  }

  return children
}
