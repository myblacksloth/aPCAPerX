import { FormEvent, useState } from 'react'
import { Fingerprint, KeyRound, LogIn, LogOut, ShieldCheck, UserCog, UserPlus, UserRound } from 'lucide-react'
import type { UserProfile } from '../types/analysis'
import { assertWebAuthnAvailable, extractPublicKeyOptions, normalizePublicKeyOptions, serializeCredential } from '../utils/webauthn'

type AuthMode = 'login' | 'register' | 'recover' | 'mfa'

interface AuthPanelProps {
  user: UserProfile | null
  onUserChange: (user: UserProfile | null) => void
  onOpenProfile: () => void
}

export default function AuthPanel({ user, onUserChange, onOpenProfile }: AuthPanelProps) {
  const [mode, setMode] = useState<AuthMode>('login')
  const [username, setUsername] = useState('demo')
  const [password, setPassword] = useState('demo')
  const [displayName, setDisplayName] = useState('')
  const [mfaCode, setMfaCode] = useState('')
  const [recoveryCode, setRecoveryCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const readApiError = async (response: Response, fallback: string) => {
    // Normalize FastAPI error payloads so every auth flow can show one message.
    const data = await response.json().catch(() => ({}))
    return typeof data.detail === 'string' ? data.detail : fallback
  }

  const submitPasswordLogin = async (event?: FormEvent) => {
    // Password login is intentionally staged: the first valid password attempt reveals whether OTP is required.
    event?.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, mfa_code: mode === 'mfa' ? mfaCode : null }),
      })
      if (!response.ok) {
        const detail = await readApiError(response, 'Login failed.')
        // The backend only asks for MFA after the password is correct.
        if (detail.includes('MFA code') && mode !== 'mfa') {
          setMode('mfa')
          setMfaCode('')
          return
        }
        setError(detail)
        return
      }
      onUserChange(await response.json() as UserProfile)
    } finally {
      setBusy(false)
    }
  }

  const submitRegister = async (event: FormEvent) => {
    // Registration creates the user and immediately receives the recovery codes through the profile response.
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, display_name: displayName || null }),
      })
      if (!response.ok) {
        setError(await readApiError(response, 'Registration failed.'))
        return
      }
      onUserChange(await response.json() as UserProfile)
    } finally {
      setBusy(false)
    }
  }

  const submitRecovery = async (event: FormEvent) => {
    // Account recovery is kept out of the normal login form and consumes exactly one recovery code.
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const response = await fetch('/api/auth/recover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, recovery_code: recoveryCode }),
      })
      if (!response.ok) {
        setError(await readApiError(response, 'Account recovery failed.'))
        return
      }
      onUserChange(await response.json() as UserProfile)
    } finally {
      setBusy(false)
    }
  }

  const loginWithPasskey = async () => {
    // WebAuthn login uses the browser credential API and sends only the signed assertion to the backend.
    setBusy(true)
    setError(null)
    try {
      assertWebAuthnAvailable()
      const optionsResponse = await fetch('/api/auth/passkeys/login/options', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),
      })
      if (!optionsResponse.ok) throw new Error(await readApiError(optionsResponse, 'Passkey login is not available.'))
      const publicKey = normalizePublicKeyOptions(extractPublicKeyOptions(await optionsResponse.json()))
      const credential = await navigator.credentials.get({ publicKey })
      if (!credential) throw new Error('Passkey login was cancelled.')
      const verifyResponse = await fetch('/api/auth/passkeys/login/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential: serializeCredential(credential as PublicKeyCredential) }),
      })
      if (!verifyResponse.ok) throw new Error(await readApiError(verifyResponse, 'Passkey verification failed.'))
      onUserChange(await verifyResponse.json() as UserProfile)
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Passkey login failed.')
    } finally {
      setBusy(false)
    }
  }

  const logout = async () => {
    // The backend deletes the HTTP-only session token hash, then the frontend drops local profile state.
    await fetch('/api/auth/logout', { method: 'POST' })
    onUserChange(null)
  }

  if (!user) {
    return (
      <main className="flex min-h-[calc(100vh-96px)] items-center justify-center px-4 py-8">
        <section className="grid w-full max-w-5xl overflow-hidden rounded-lg border border-slate-700 bg-slate-800 shadow-2xl md:grid-cols-[1fr_420px]">
          <div className="flex min-h-[420px] flex-col justify-between bg-slate-950 p-8">
            <div>
              <div className="mb-6 inline-flex items-center gap-2 rounded-md border border-slate-700 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-brand-200">
                <ShieldCheck className="h-4 w-4" />
                Secure workspace
              </div>
              <h1 className="max-w-md text-3xl font-semibold text-white">Accedi a PCAPCaper</h1>
              <p className="mt-3 max-w-md text-sm leading-6 text-slate-400">
                Entra con credenziali, passkey o recupera l'account da una pagina dedicata. Le analisi salvate restano associate al tuo utente.
              </p>
            </div>
            <div className="grid gap-3 text-sm text-slate-300 sm:grid-cols-3 md:grid-cols-1">
              <div className="rounded-md border border-slate-800 bg-slate-900 px-3 py-2">Sessioni HTTP-only</div>
              <div className="rounded-md border border-slate-800 bg-slate-900 px-3 py-2">MFA TOTP a due step</div>
              <div className="rounded-md border border-slate-800 bg-slate-900 px-3 py-2">Passkeys WebAuthn</div>
            </div>
          </div>

          <div className="p-6">
            <div className="mb-5 flex items-center justify-between">
              <div className="flex items-center gap-2 text-white">
                <LogIn className="h-5 w-5 text-brand-300" />
                <h2 className="text-lg font-semibold">
                  {mode === 'register' ? 'Nuovo utente' : mode === 'recover' ? 'Recupero account' : mode === 'mfa' ? 'Verifica MFA' : 'Accesso'}
                </h2>
              </div>
              {mode !== 'login' && (
                <button onClick={() => { setMode('login'); setError(null) }} className="text-xs font-medium text-brand-200 hover:text-brand-100">
                  Torna al login
                </button>
              )}
            </div>

            {mode === 'register' ? (
              <form className="space-y-3" onSubmit={submitRegister}>
                <input className="w-full rounded-md border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-white" value={username} onChange={(event) => setUsername(event.target.value)} placeholder="Username" autoComplete="username" />
                <input className="w-full rounded-md border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-white" value={displayName} onChange={(event) => setDisplayName(event.target.value)} placeholder="Nome visualizzato" autoComplete="name" />
                <input className="w-full rounded-md border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-white" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Password" type="password" autoComplete="new-password" />
                {error && <p className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</p>}
                <button disabled={busy} className="inline-flex w-full items-center justify-center gap-2 rounded-md bg-brand-500 px-3 py-2 text-sm font-semibold text-white disabled:opacity-60">
                  <UserPlus className="h-4 w-4" />
                  Crea utente
                </button>
              </form>
            ) : mode === 'recover' ? (
              <form className="space-y-3" onSubmit={submitRecovery}>
                <input className="w-full rounded-md border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-white" value={username} onChange={(event) => setUsername(event.target.value)} placeholder="Username" autoComplete="username" />
                <input className="w-full rounded-md border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-white" value={recoveryCode} onChange={(event) => setRecoveryCode(event.target.value)} placeholder="Recovery code" autoComplete="one-time-code" />
                {error && <p className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</p>}
                <button disabled={busy} className="inline-flex w-full items-center justify-center gap-2 rounded-md bg-brand-500 px-3 py-2 text-sm font-semibold text-white disabled:opacity-60">
                  <KeyRound className="h-4 w-4" />
                  Recupera account
                </button>
              </form>
            ) : mode === 'mfa' ? (
              <form className="space-y-3" onSubmit={submitPasswordLogin}>
                <p className="rounded-md border border-brand-400/30 bg-brand-500/10 px-3 py-2 text-sm text-brand-100">
                  Inserisci il codice OTP generato dalla tua app authenticator.
                </p>
                <input className="w-full rounded-md border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-white" value={mfaCode} onChange={(event) => setMfaCode(event.target.value)} placeholder="Codice OTP" autoComplete="one-time-code" inputMode="numeric" />
                {error && <p className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</p>}
                <button disabled={busy} className="inline-flex w-full items-center justify-center gap-2 rounded-md bg-brand-500 px-3 py-2 text-sm font-semibold text-white disabled:opacity-60">
                  <ShieldCheck className="h-4 w-4" />
                  Verifica e accedi
                </button>
              </form>
            ) : (
              <form className="space-y-3" onSubmit={submitPasswordLogin}>
                <input className="w-full rounded-md border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-white" value={username} onChange={(event) => setUsername(event.target.value)} placeholder="Username" autoComplete="username" />
                <input className="w-full rounded-md border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-white" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Password" type="password" autoComplete="current-password" />
                {error && <p className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</p>}
                <button disabled={busy} className="inline-flex w-full items-center justify-center gap-2 rounded-md bg-brand-500 px-3 py-2 text-sm font-semibold text-white disabled:opacity-60">
                  <LogIn className="h-4 w-4" />
                  Accedi
                </button>
                <button type="button" disabled={busy} onClick={loginWithPasskey} className="inline-flex w-full items-center justify-center gap-2 rounded-md border border-slate-600 px-3 py-2 text-sm font-semibold text-slate-100 hover:border-slate-400 disabled:opacity-60">
                  <Fingerprint className="h-4 w-4" />
                  Accedi con passkey
                </button>
              </form>
            )}

            <div className="mt-5 flex flex-wrap items-center justify-between gap-3 text-xs">
              <button onClick={() => { setMode('register'); setError(null) }} className="font-medium text-brand-200 hover:text-brand-100">Registra nuovo utente</button>
              <button onClick={() => { setMode('recover'); setError(null) }} className="font-medium text-slate-300 hover:text-white">Recupera account</button>
            </div>
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
        <div className="flex items-center gap-2">
          <button title="Profilo utente" aria-label="Profilo utente" onClick={onOpenProfile} className="rounded-md border border-slate-600 p-2 text-slate-200 hover:border-slate-400 hover:text-white">
            <UserCog className="h-4 w-4" />
          </button>
          <button title="Logout" aria-label="Logout" onClick={logout} className="rounded-md border border-slate-600 p-2 text-slate-200 hover:border-slate-400 hover:text-white">
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </section>
  )
}
