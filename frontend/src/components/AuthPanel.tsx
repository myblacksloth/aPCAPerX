import { useState } from 'react'
import { KeyRound, LogIn, ShieldCheck, Smartphone, UserRound } from 'lucide-react'
import type { UserProfile } from '../types/analysis'

interface AuthPanelProps {
  user: UserProfile | null
  onUserChange: (user: UserProfile | null) => void
}

function bufferToBase64url(buffer: ArrayBuffer): string {
  // WebAuthn uses ArrayBuffers; the API transports them as base64url strings.
  const bytes = new Uint8Array(buffer)
  let binary = ''
  bytes.forEach((byte) => { binary += String.fromCharCode(byte) })
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function base64urlToBuffer(value: string): ArrayBuffer {
  // Browser APIs require ArrayBuffers for challenge and credential ids.
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(normalized + '='.repeat((4 - normalized.length % 4) % 4))
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index)
  return bytes.buffer
}

function serializeCredential(credential: PublicKeyCredential): Record<string, unknown> {
  // Convert a browser WebAuthn credential into JSON accepted by the backend.
  const response = credential.response as AuthenticatorAttestationResponse | AuthenticatorAssertionResponse
  const payload: Record<string, unknown> = {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
    },
  }
  if ('attestationObject' in response) {
    ;(payload.response as Record<string, unknown>).attestationObject = bufferToBase64url(response.attestationObject)
  }
  if ('authenticatorData' in response) {
    ;(payload.response as Record<string, unknown>).authenticatorData = bufferToBase64url(response.authenticatorData)
    ;(payload.response as Record<string, unknown>).signature = bufferToBase64url(response.signature)
    ;(payload.response as Record<string, unknown>).userHandle = response.userHandle ? bufferToBase64url(response.userHandle) : null
  }
  return payload
}

function normalizePublicKeyOptions(options: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions) {
  // Decode WebAuthn options produced by the backend before calling navigator.credentials.
  const normalized: any = { ...options, challenge: base64urlToBuffer(String(options.challenge)) }
  if ('user' in normalized && normalized.user?.id) normalized.user.id = base64urlToBuffer(normalized.user.id)
  if (Array.isArray(normalized.excludeCredentials)) {
    normalized.excludeCredentials = normalized.excludeCredentials.map((item: any) => ({ ...item, id: base64urlToBuffer(item.id) }))
  }
  if (Array.isArray(normalized.allowCredentials)) {
    normalized.allowCredentials = normalized.allowCredentials.map((item: any) => ({ ...item, id: base64urlToBuffer(item.id) }))
  }
  return normalized
}

export default function AuthPanel({ user, onUserChange }: AuthPanelProps) {
  const [username, setUsername] = useState('demo')
  const [password, setPassword] = useState('demo')
  const [mfaCode, setMfaCode] = useState('')
  const [recoveryCode, setRecoveryCode] = useState('')
  const [totpSetup, setTotpSetup] = useState<{ secret: string; otpauth_url: string } | null>(null)
  const [totpVerifyCode, setTotpVerifyCode] = useState('')
  const [error, setError] = useState<string | null>(null)

  const login = async () => {
    setError(null)
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, mfa_code: mfaCode || null, recovery_code: recoveryCode || null }),
    })
    if (!response.ok) {
      const data = await response.json().catch(() => ({}))
      setError(data.detail ?? 'Login failed')
      return
    }
    onUserChange(await response.json() as UserProfile)
  }

  const logout = async () => {
    await fetch('/api/auth/logout', { method: 'POST' })
    onUserChange(null)
  }

  const setupTotp = async () => {
    const response = await fetch('/api/auth/totp/setup', { method: 'POST' })
    if (response.ok) setTotpSetup(await response.json())
  }

  const enableTotp = async () => {
    const response = await fetch('/api/auth/totp/enable', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: totpVerifyCode }),
    })
    if (response.ok) {
      onUserChange(await response.json() as UserProfile)
      setTotpSetup(null)
    }
  }

  const registerPasskey = async () => {
    setError(null)
    const optionsResponse = await fetch('/api/auth/passkeys/register/options', { method: 'POST' })
    if (!optionsResponse.ok) return
    const options = normalizePublicKeyOptions(await optionsResponse.json())
    const credential = await navigator.credentials.create({ publicKey: options })
    if (!credential) return
    const verifyResponse = await fetch('/api/auth/passkeys/register/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ credential: serializeCredential(credential as PublicKeyCredential), label: 'Browser passkey' }),
    })
    if (verifyResponse.ok) onUserChange(await verifyResponse.json() as UserProfile)
  }

  const loginWithPasskey = async () => {
    setError(null)
    const optionsResponse = await fetch('/api/auth/passkeys/login/options', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username }),
    })
    if (!optionsResponse.ok) return
    const options = normalizePublicKeyOptions(await optionsResponse.json())
    const credential = await navigator.credentials.get({ publicKey: options })
    if (!credential) return
    const verifyResponse = await fetch('/api/auth/passkeys/login/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ credential: serializeCredential(credential as PublicKeyCredential) }),
    })
    if (verifyResponse.ok) onUserChange(await verifyResponse.json() as UserProfile)
  }

  if (!user) {
    return (
      <main className="flex min-h-[calc(100vh-96px)] items-center justify-center px-4">
        <section className="w-full max-w-sm rounded-lg border border-slate-700 bg-slate-800 p-5">
          <div className="mb-5 flex items-center gap-2 text-white">
            <LogIn className="h-5 w-5 text-brand-300" />
            <h1 className="text-lg font-semibold">Accesso</h1>
          </div>
          <div className="space-y-3">
            <input className="w-full rounded-md border border-slate-600 bg-slate-900 px-3 py-2 text-sm" value={username} onChange={(event) => setUsername(event.target.value)} placeholder="Username" />
            <input className="w-full rounded-md border border-slate-600 bg-slate-900 px-3 py-2 text-sm" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Password" type="password" />
            <input className="w-full rounded-md border border-slate-600 bg-slate-900 px-3 py-2 text-sm" value={mfaCode} onChange={(event) => setMfaCode(event.target.value)} placeholder="TOTP code" />
            <input className="w-full rounded-md border border-slate-600 bg-slate-900 px-3 py-2 text-sm" value={recoveryCode} onChange={(event) => setRecoveryCode(event.target.value)} placeholder="Recovery code" />
            {error && <p className="text-sm text-red-300">{error}</p>}
            <button onClick={login} className="w-full rounded-md bg-brand-500 px-3 py-2 text-sm font-semibold text-white">Login</button>
            <button onClick={loginWithPasskey} className="flex w-full items-center justify-center gap-2 rounded-md border border-slate-600 px-3 py-2 text-sm text-slate-200">
              <KeyRound className="h-4 w-4" />
              Login with passkey
            </button>
          </div>
        </section>
      </main>
    )
  }

  return (
    <section className="border-b border-slate-700 bg-slate-800 px-4 py-3">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 text-sm">
        <div className="flex items-center gap-2 text-slate-200">
          <UserRound className="h-4 w-4 text-brand-300" />
          <span>{user.display_name}</span>
          <span className="text-slate-500">({user.username})</span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button onClick={setupTotp} className="inline-flex items-center gap-1 rounded-md border border-slate-600 px-2 py-1 text-xs text-slate-200">
            <Smartphone className="h-3.5 w-3.5" />
            {user.totp_enabled ? 'Reconfigure TOTP' : 'Enable TOTP'}
          </button>
          <button onClick={registerPasskey} className="inline-flex items-center gap-1 rounded-md border border-slate-600 px-2 py-1 text-xs text-slate-200">
            <KeyRound className="h-3.5 w-3.5" />
            Add passkey
          </button>
          <button onClick={logout} className="rounded-md border border-slate-600 px-2 py-1 text-xs text-slate-200">Logout</button>
        </div>
      </div>
      {totpSetup && (
        <div className="mx-auto mt-3 grid max-w-7xl gap-2 rounded-lg border border-slate-700 bg-slate-900 p-3 text-xs text-slate-300 md:grid-cols-[1fr_auto]">
          <div>
            <div className="mb-1 flex items-center gap-1 text-slate-100"><ShieldCheck className="h-3.5 w-3.5" /> TOTP setup</div>
            <p>Secret: <code>{totpSetup.secret}</code></p>
            <p className="break-all">URI: <code>{totpSetup.otpauth_url}</code></p>
            <p className="mt-2 text-slate-400">Recovery codes visible for this user:</p>
            <div className="mt-1 flex flex-wrap gap-1">
              {user.recovery_codes.map((item) => <code key={item.code} className={item.used_at ? 'text-slate-600 line-through' : 'text-slate-200'}>{item.code}</code>)}
            </div>
          </div>
          <div className="flex items-end gap-2">
            <input className="rounded-md border border-slate-600 bg-slate-950 px-2 py-1" value={totpVerifyCode} onChange={(event) => setTotpVerifyCode(event.target.value)} placeholder="123456" />
            <button onClick={enableTotp} className="rounded-md bg-brand-500 px-3 py-1 text-white">Verify</button>
          </div>
        </div>
      )}
      <details className="mx-auto mt-2 max-w-7xl rounded-lg border border-slate-700 bg-slate-900 p-3 text-xs text-slate-300">
        <summary className="cursor-pointer text-slate-100">User recovery codes and passkeys</summary>
        <div className="mt-3 grid gap-4 md:grid-cols-2">
          <div>
            <div className="mb-2 font-medium text-slate-200">Recovery codes</div>
            <div className="flex flex-wrap gap-1">
              {user.recovery_codes.map((item) => (
                <code key={item.code} className={item.used_at ? 'text-slate-600 line-through' : 'text-slate-200'}>
                  {item.code}
                </code>
              ))}
            </div>
          </div>
          <div>
            <div className="mb-2 font-medium text-slate-200">Passkeys</div>
            <div className="space-y-1">
              {user.passkeys.length === 0 && <p className="text-slate-500">No passkeys registered.</p>}
              {user.passkeys.map((item) => (
                <div key={item.id} className="rounded border border-slate-700 px-2 py-1">
                  <div className="text-slate-100">{item.label}</div>
                  <div className="text-slate-500">Created {new Date(item.created_at).toLocaleString()}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </details>
    </section>
  )
}
