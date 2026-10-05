let csrfToken = null

/**
 * Update the in-memory CSRF token returned by /auth/me.
 *
 * Args:
 *     token(string|null): token for authenticated mutation requests
 */
export function setCsrfToken(token) {
  csrfToken = token || null
}

/**
 * Perform a fetch against the same-origin management API and unwrap the
 * standard {status, message, data} envelope.
 */
async function request(path, options = {}) {
  const method = (options.method || 'GET').toUpperCase()
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  }
  if (csrfToken && !['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    headers['X-CSRF-Token'] = csrfToken
  }

  const response = await fetch(path, {
    ...options,
    method,
    credentials: 'same-origin',
    headers,
  })

  let envelope = null
  try {
    envelope = await response.json()
  } catch {
    envelope = null
  }

  if (!response.ok) {
    const message = envelope?.message
      || (typeof envelope?.detail === 'string' ? envelope.detail : null)
      || `Request failed with status ${response.status}`
    const error = new Error(message)
    error.status = response.status
    throw error
  }

  return envelope?.data
}

export function apiGet(path) {
  return request(path, { method: 'GET' })
}

export function apiPost(path, body) {
  return request(path, {
    method: 'POST',
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
}

export function apiPut(path, body) {
  return request(path, {
    method: 'PUT',
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
}

export function apiPatch(path, body) {
  return request(path, {
    method: 'PATCH',
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
}

export function apiDelete(path, body) {
  return request(path, {
    method: 'DELETE',
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
}
