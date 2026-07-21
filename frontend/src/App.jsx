import { Routes, Route } from 'react-router-dom'
import { AuthProvider, ProtectedRoute } from './auth/AuthContext.jsx'
import { ToastProvider } from './ui/ui.jsx'
import Layout from './components/Layout.jsx'
import Login from './pages/Login.jsx'
import Register from './pages/Register.jsx'
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
          <Route path="/register" element={<Register />} />
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
          </Route>
        </Routes>
      </AuthProvider>
    </ToastProvider>
  )
}
