export interface ExternalIdentityOptions {
  runtimeURL: string
  fetch?: typeof globalThis.fetch
  credential?: () => string | Promise<string>
  clearCredential?: () => void | Promise<void>
  redirect?: (url: string) => void
}
export interface ExternalSession {
  workspace_id: string
  subject_id: string
  user: { id: string; name: string; email?: string }
  roles: Array<{ id: string; key: string; label: string }>
  permissions: string[]
  authorization_revision: string
  expires_at: string
  access_bundle: Record<string, unknown>
}
export interface ExternalBrowserConfiguration {
  mode: 'external'
  application_key: string
  display_name: string
  session_path: '/auth/external/session'
  login_url: string
  logout_url?: string
  credential: { location: 'cookie' | 'header'; name?: string; prefix?: string }
}
export declare class ExternalIdentityClient {
  constructor(options: ExternalIdentityOptions)
  configuration(): Promise<ExternalBrowserConfiguration>
  authorizedFetch(path: string, init?: RequestInit): Promise<Response>
  session(): Promise<ExternalSession>
  login(): Promise<void>
  logout(): Promise<void>
}
