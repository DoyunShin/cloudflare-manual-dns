import { useEffect, useState } from 'react'
import { apiGet, apiPatch } from '../api/client.js'
import { useAuth } from '../auth/AuthContext.jsx'
import { Badge, Button, EmptyState, PageHeader, Panel, Spinner, Table, Toggle, useToast } from '../ui/ui.jsx'

const PER_PAGE = 25

/**
 * Service-local user status and administrator management.
 */
export default function Users() {
  const toast = useToast()
  const { user: currentUser, refresh } = useAuth()
  const [users, setUsers] = useState([])
  const [info, setInfo] = useState({ page: 1, per_page: PER_PAGE, total_count: 0 })
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [pending, setPending] = useState(null)

  async function load(targetPage = page) {
    setLoading(true)
    try {
      const data = await apiGet(`/api/v1/admin/users?page=${targetPage}&per_page=${PER_PAGE}`)
      setUsers(data?.items || [])
      setInfo(data?.result_info || { page: targetPage, per_page: PER_PAGE, total_count: 0 })
    } catch (err) {
      toast.error(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load(page)
  }, [page]) // eslint-disable-line react-hooks/exhaustive-deps

  async function updateUser(user, patch) {
    setPending(user.id)
    try {
      const updated = await apiPatch(`/api/v1/admin/users/${user.id}`, patch)
      setUsers((current) => current.map((item) => (item.id === user.id ? { ...item, ...updated } : item)))
      if (user.id === currentUser.id) await refresh()
      toast.success('User updated')
    } catch (err) {
      toast.error(err.message)
    } finally {
      setPending(null)
    }
  }

  const totalPages = Math.max(1, Math.ceil((info.total_count || 0) / PER_PAGE))

  return (
    <div className="reveal">
      <PageHeader title="Users" subtitle="Manage access and administrator rights inside this service." />
      <Panel actions={<span className="mono muted-text">{info.total_count || 0} users</span>}>
        {loading ? <Spinner label="Loading users" /> : (
          <>
            <Table
              empty={<EmptyState message="No users found." />}
              columns={[
                { key: 'identity', header: 'User', render: (user) => (
                  <div className="user-identity">
                    <strong>{user.display_name || user.email || 'Unnamed user'}</strong>
                    {user.display_name && user.email && <span className="muted-text">{user.email}</span>}
                  </div>
                ) },
                { key: 'auth_provider', header: 'Source', render: (user) => (
                  <Badge variant={user.auth_provider === 'local' ? 'accent' : 'muted'}>{user.auth_provider}</Badge>
                ) },
                { key: 'is_admin', header: 'Administrator', render: (user) => (
                  <Toggle checked={user.is_admin} disabled={pending === user.id}
                    onChange={(value) => updateUser(user, { is_admin: value })} />
                ) },
                { key: 'is_active', header: 'Active', render: (user) => (
                  <Toggle checked={user.is_active} disabled={pending === user.id}
                    onChange={(value) => updateUser(user, { is_active: value })} />
                ) },
              ]}
              rows={users}
              rowKey={(user) => user.id}
            />
            <div className="pager">
              <Button variant="ghost" disabled={page <= 1 || pending !== null}
                onClick={() => setPage((value) => Math.max(1, value - 1))}>Prev</Button>
              <span className="mono">page {info.page || page} / {totalPages}</span>
              <Button variant="ghost" disabled={page >= totalPages || pending !== null}
                onClick={() => setPage((value) => value + 1)}>Next</Button>
            </div>
          </>
        )}
      </Panel>
    </div>
  )
}
