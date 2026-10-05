import { Routes, Route } from 'react-router-dom'
import { AdminRoute, AuthProvider, ProtectedRoute } from './auth/AuthContext.jsx'
import { ToastProvider } from './ui/ui.jsx'
import Layout from './components/Layout.jsx'
import Login from './pages/Login.jsx'
import AdminLogin from './pages/AdminLogin.jsx'
import OidcSettings from './pages/OidcSettings.jsx'
import Users from './pages/Users.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Credentials from './pages/Credentials.jsx'
import Tokens from './pages/Tokens.jsx'
import Audit from './pages/Audit.jsx'

/**
 * Root application component: providers + route table.
 */
export default function App() {
  return (
    <ToastProvider>
      <AuthProvider>
        <span className="status-line" aria-hidden="true" />
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/admin/login" element={<AdminLogin />} />
          <Route
            element={
              <ProtectedRoute>
                <Layout />
              </ProtectedRoute>
            }
          >
            <Route index element={<Dashboard />} />
            <Route path="/credentials" element={<Credentials />} />
            <Route path="/tokens" element={<Tokens />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/admin/oidc" element={<AdminRoute><OidcSettings /></AdminRoute>} />
            <Route path="/admin/users" element={<AdminRoute><Users /></AdminRoute>} />
          </Route>
        </Routes>
      </AuthProvider>
    </ToastProvider>
  )
}
