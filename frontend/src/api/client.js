const TOKEN_KEY = 'securebank_token'

export function getToken() {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token)
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY)
}

export function getUser() {
  const raw = localStorage.getItem('securebank_user')
  return raw ? JSON.parse(raw) : null
}

export function setUser(user) {
  localStorage.setItem('securebank_user', JSON.stringify(user))
}

export function clearUser() {
  localStorage.removeItem('securebank_user')
}

/**
 * Makes an API call with the stored bearer token attached.
 *
 * The token is kept in localStorage on purpose: Lab 13's stored XSS is only
 * meaningful because script running in the page can read it.
 *
 * Pass `token` to use a different credential than the stored one. The admin
 * console keeps its own session token in sessionStorage, and sending both
 * would mean two Authorization headers - the server reads only the first, so
 * the request would be made as the customer rather than as the admin.
 */
export async function api(path, options = {}) {
  const { method = 'GET', body, headers = {}, token: explicitToken } = options

  const token = explicitToken ?? getToken()
  const requestHeaders = { ...headers }

  if (token) {
    requestHeaders.Authorization = `Bearer ${token}`
  }
  if (body !== undefined && !requestHeaders['Content-Type']) {
    requestHeaders['Content-Type'] = 'application/json'
  }

  const response = await fetch(path, {
    method,
    headers: requestHeaders,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'include',
  })

  const text = await response.text()
  let payload
  try {
    payload = text ? JSON.parse(text) : null
  } catch {
    payload = text
  }

  return { ok: response.ok, status: response.status, data: payload }
}
