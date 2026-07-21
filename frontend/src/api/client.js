const TOKEN_KEY = 'cfproxy_jwt'

/**
 * Read the stored JWT from localStorage.
 *
 * Return:
 *     token(string|null): stored access token, or null if absent
 */
export function getToken() {
  return localStorage.getItem(TOKEN_KEY)
}

/**
 * Persist the JWT to localStorage.
 *
 * Args:
 *     token(string): access token returned by /auth/login
 */
export function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token)
}

/**
 * Remove the stored JWT from localStorage.
 */
export function clearToken() {
  localStorage.removeItem(TOKEN_KEY)
}

/**
 * Perform a fetch against the same-origin management API and unwrap the
 * standard {status, message, data} envelope.
 *
 * Args:
 *     path(string): request path, e.g. "/api/v1/auth/me"
 *     options(object, optional): fetch options (method, body, etc.)
 *
 * Return:
 *     data(any): the envelope's data field on success
 */
async function request(path, options = {}) {
  const token = getToken()
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  }
  if (token) {
    headers.Authorization = `Bearer ${token}`
  }

  const response = await fetch(path, {
    ...options,
    headers,
  })

  let envelope = null
  try {
    envelope = await response.json()
  } catch {
    envelope = null
  }

  if (!response.ok) {
    const message = envelope?.message || `Request failed with status ${response.status}`
    throw new Error(message)
  }

  return envelope?.data
}

/**
 * Issue a GET request against the management API.
 *
 * Args:
 *     path(string): request path
 *
 * Return:
 *     data(any): unwrapped response data
 */
export function apiGet(path) {
  return request(path, { method: 'GET' })
}

/**
 * Issue a POST request against the management API.
 *
 * Args:
 *     path(string): request path
 *     body(object, optional): JSON-serializable request body
 *
 * Return:
 *     data(any): unwrapped response data
 */
export function apiPost(path, body) {
  return request(path, {
    method: 'POST',
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
}

/**
 * Issue a DELETE request against the management API.
 *
 * Args:
 *     path(string): request path
 *     body(object, optional): JSON-serializable request body
 *
 * Return:
 *     data(any): unwrapped response data
 */
export function apiDelete(path, body) {
  return request(path, {
    method: 'DELETE',
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
}
