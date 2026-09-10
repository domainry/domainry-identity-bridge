import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ExternalIdentityClient } from './client.js'
const configuration = { mode: 'external', session_path: '/auth/external/session', display_name: 'Accounts', login_url: 'https://accounts.example.com/login', logout_url: 'https://accounts.example.com/logout', credential: { location: 'header', name: 'Authorization', prefix: 'Bearer ' } }
test('existing credential authenticates Runtime without storage or write retries', async () => {
  const calls = []
  const client = new ExternalIdentityClient({ runtimeURL: 'https://app.example.com', credential: () => 'existing-token', fetch: async (url, init) => { calls.push([url, init]); return url.pathname.endsWith('/config') ? Response.json(configuration) : new Response('', { status: 401 }) } })
  const response = await client.authorizedFetch('/records/note', { method: 'POST', body: '{}' })
  assert.equal(response.status, 401)
  assert.equal(calls.length, 2)
  assert.equal(calls[1][1].headers.get('Authorization'), 'Bearer existing-token')
  assert.equal(calls[1][1].credentials, 'omit')
  assert.equal(calls[1][1].redirect, 'error')
  for (const path of ['https://evil.example.com', '//evil.example.com', '/\\evil.example.com']) await assert.rejects(client.authorizedFetch(path))
  assert.equal(calls.length, 2)
})
test('cookie mode never exposes cookie and redirects login/logout to configured authority', async () => {
  const redirects = []
  let request
  let cleared = false
  const client = new ExternalIdentityClient({ runtimeURL: 'https://app.example.com', clearCredential: () => { cleared = true }, redirect: url => redirects.push(url), fetch: async (url, init) => { if (url.pathname.endsWith('/config')) return Response.json({ ...configuration, credential: { location: 'cookie' } }); request = init; return Response.json({ workspace_id: 'personal', subject_id: 'opaque-user' }) } })
  assert.equal((await client.session()).workspace_id, 'personal')
  assert.equal(request.credentials, 'include')
  assert.equal(request.headers.has('Authorization'), false)
  await client.login(); await client.logout()
  assert.deepEqual(redirects, [configuration.login_url, configuration.logout_url])
  assert.equal(cleared, true)
})

test('login works without a logout page and logout fails before changing credentials', async () => {
  let cleared = false
  const client = new ExternalIdentityClient({ runtimeURL: 'https://app.example.com',
    fetch: async () => Response.json({ ...configuration, logout_url: '', credential: { location: 'cookie' } }),
    clearCredential: async () => { cleared = true }
  })
  assert.equal((await client.configuration()).login_url, configuration.login_url)
  await assert.rejects(client.logout(), /not configured/)
  assert.equal(cleared, false)
})
