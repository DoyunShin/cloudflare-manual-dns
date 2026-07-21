import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext.jsx'
import { Button } from '../ui/ui.jsx'

const NAV_ITEMS = [
  { to: '/', label: 'Overview', end: true },
  { to: '/credentials', label: 'Credentials' },
  { to: '/tokens', label: 'Tokens' },
  { to: '/audit', label: 'Audit' },
]

/**
 * Application shell: left sidebar navigation, top status bar with the
 * current user and logout, and a scrollable main outlet.
 */
export default function Layout() {
  const { user, logout } = useAuth()

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-dot" aria-hidden="true" />
          <span className="brand-name label">cfproxy</span>
        </div>
        <nav className="nav">
          {NAV_ITEMS.map((item, i) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) => `nav-link reveal${isActive ? ' nav-link-active' : ''}`}
              style={{ animationDelay: `${i * 40}ms` }}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <div className="shell-main">
        <header className="topbar">
          <span className="topbar-user mono">{user?.email}</span>
          <Button variant="ghost" onClick={logout}>
            Logout
          </Button>
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
