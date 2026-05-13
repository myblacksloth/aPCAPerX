import { useState } from 'react'
import { LogIn, UserRound } from 'lucide-react'
import type { UserProfile } from '../types/analysis'

interface AuthPanelProps {
  user: UserProfile | null
  onUserChange: (user: UserProfile | null) => void
  onOpenProfile: () => void
}

export default function AuthPanel({ user, onUserChange, onOpenProfile }: AuthPanelProps) {
  const [username, setUsername] = useState('demo')
  const [password, setPassword] = useState('demo')
  const [mfaCode, setMfaCode] = useState('')
  const [recoveryCode, setRecoveryCode] = useState('')
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
          <button onClick={onOpenProfile} className="rounded-md border border-slate-600 px-2 py-1 text-xs text-slate-200">Profilo</button>
          <button onClick={logout} className="rounded-md border border-slate-600 px-2 py-1 text-xs text-slate-200">Logout</button>
        </div>
      </div>
    </section>
  )
}
