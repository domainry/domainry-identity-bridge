/** Reuses an existing login authority. No token persistence or local sessions. */
export class ExternalIdentityError extends Error {
  constructor(status, code, message, params, requestID = '') {
    super(message)
    this.name = 'ExternalIdentityError'
    this.status = status
    this.code = code
    this.params = params
    this.requestID = requestID
  }
}

function parseHTTPErrorResponse(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  if (typeof value.code !== 'string' || !value.code.trim() || typeof value.message !== 'string' || !value.message.trim() || typeof value.request_id !== 'string') return null
  if (value.params !== undefined && (!value.params || typeof value.params !== 'object' || Array.isArray(value.params) || Object.values(value.params).some(item => typeof item !== 'string'))) return null
  return {
    code: value.code,
    message: value.message,
    ...(value.params === undefined ? {} : { params: value.params }),
    request_id: value.request_id,
  }
}

async function errorFrom(response, fallbackCode, fallbackMessage) {
  const value = parseHTTPErrorResponse(await response.json().catch(() => undefined))
  return value
    ? new ExternalIdentityError(response.status, value.code, value.message, value.params, value.request_id)
    : new ExternalIdentityError(response.status, fallbackCode, fallbackMessage)
}

export class ExternalIdentityClient {
  #options
  #fetch
  #base
  #config
  constructor(options) {
    this.#options = options
    this.#fetch = options.fetch || globalThis.fetch.bind(globalThis)
    this.#base = new URL(options.runtimeURL, globalThis.location?.href)
    if (!['http:', 'https:'].includes(this.#base.protocol) || this.#base.username || this.#base.password || this.#base.search || this.#base.hash) throw new Error('invalid Runtime URL')
    this.#base.pathname = this.#base.pathname.replace(/\/$/, '') + '/'
  }
  async configuration() {
    if (this.#config) return this.#config
    const response = await this.#fetch(new URL('auth/external/config', this.#base), { credentials: 'omit', redirect: 'error', cache: 'no-store' })
    if (!response.ok) throw await errorFrom(response, 'identity.external.configuration_unavailable', 'external login configuration unavailable')
    const config = await response.json()
    if (config.mode !== 'external' || config.session_path !== '/auth/external/session') throw new Error('unsupported external login configuration')
    for (const key of ['login_url', 'logout_url']) {
      if (key === 'logout_url' && !config[key]) continue
      const value = new URL(config[key])
      if (value.protocol !== 'https:' || value.username || value.password || value.hash) throw new Error('invalid external login URL')
    }
    if (!['header', 'cookie'].includes(config.credential?.location)) throw new Error('external browser credential is not configured')
    if (config.credential.location === 'header' && !this.#options.credential) throw new Error('existing login credential callback is required')
    this.#config = config
    return config
  }
  async authorizedFetch(path, init = {}) {
    const config = await this.configuration()
    if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || path.includes('\\')) throw new Error('Runtime request must use an absolute path')
    const url = new URL(path.slice(1), this.#base)
    if (url.origin !== this.#base.origin || !url.pathname.startsWith(this.#base.pathname)) throw new Error('Runtime request escaped configured endpoint')
    const headers = new Headers(init.headers)
    if (config.credential.location === 'header') {
      const credential = await this.#options.credential()
      if (!credential) throw new Error('external login is required')
      headers.set(config.credential.name, (config.credential.prefix || '') + credential)
    }
    // Reauthentication/refresh remains with the provider; never replay a write.
    return this.#fetch(url, { ...init, headers, credentials: config.credential.location === 'cookie' ? 'include' : 'omit', redirect: 'error' })
  }
  async session() {
    const response = await this.authorizedFetch('/auth/external/session', { cache: 'no-store' })
    if (!response.ok) {
      throw await errorFrom(
        response,
        response.status === 401 ? 'identity.external.login_required' : 'identity.external.session_unavailable',
        response.status === 401 ? 'external login is required' : 'external session unavailable',
      )
    }
    return response.json()
  }
  async login() {
    const config = await this.configuration()
    ;(this.#options.redirect || ((url) => globalThis.location.assign(url)))(config.login_url)
  }
  async logout() {
    const config = await this.configuration()
    if (!config.logout_url) throw new Error('external logout URL is not configured')
    await this.#options.clearCredential?.()
    ;(this.#options.redirect || ((url) => globalThis.location.assign(url)))(config.logout_url)
  }
}
