import { useEffect, useState } from 'react'
import QRCode from 'qrcode'
import { ArrowLeft, KeyRound, QrCode, ShieldCheck, Smartphone, UserRound } from 'lucide-react'
import type { UserProfile } from '../types/analysis'
import { assertWebAuthnAvailable, extractPublicKeyOptions, normalizePublicKeyOptions, serializeCredential } from '../utils/webauthn'

interface UserProfilePageProps {
  user: UserProfile
  onBack: () => void
  onUserChange: (user: UserProfile) => void
}

export default function UserProfilePage({ user, onBack, onUserChange }: UserProfilePageProps) {
  const [totpSetup, setTotpSetup] = useState<{ secret: string; otpauth_url: string } | null>(null)
  const [totpQr, setTotpQr] = useState<string | null>(null)
  const [totpCode, setTotpCode] = useState('')
  const [passkeyStatus, setPasskeyStatus] = useState<string | null>(null)
  const [totpStatus, setTotpStatus] = useState<string | null>(null)

  useEffect(() => {
    if (!totpSetup) {
      setTotpQr(null)
      return
    }
    // Generate the QR locally from the otpauth URI; no external QR service is used.
    QRCode.toDataURL(totpSetup.otpauth_url, { margin: 1, width: 220 })
      .then(setTotpQr)
      .catch(() => setTotpQr(null))
  }, [totpSetup])

  const refreshProfile = async () => {
    const response = await fetch('/api/auth/me')
    if (response.ok) onUserChange(await response.json() as UserProfile)
  }

  const setupTotp = async () => {
    setTotpStatus(null)
    const response = await fetch('/api/auth/totp/setup', { method: 'POST' })
    if (!response.ok) {
      const data = await response.json().catch(() => ({}))
      setTotpStatus(data.detail ?? 'Unable to start TOTP setup.')
      return
    }
    setTotpSetup(await response.json())
  }

  const enableTotp = async () => {
    setTotpStatus(null)
    const response = await fetch('/api/auth/totp/enable', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: totpCode }),
    })
    if (!response.ok) {
      const data = await response.json().catch(() => ({}))
      setTotpStatus(data.detail ?? 'Invalid TOTP code.')
      return
    }
    onUserChange(await response.json() as UserProfile)
    setTotpSetup(null)
    setTotpStatus('TOTP enabled.')
  }

  const disableTotp = async () => {
    const response = await fetch('/api/auth/totp/disable', { method: 'POST' })
    if (response.ok) onUserChange(await response.json() as UserProfile)
  }

  const registerPasskey = async () => {
    setPasskeyStatus(null)
    try {
      assertWebAuthnAvailable()
      const optionsResponse = await fetch('/api/auth/passkeys/register/options', { method: 'POST' })
      if (!optionsResponse.ok) {
        const data = await optionsResponse.json().catch(() => ({}))
        throw new Error(data.detail ?? 'Unable to create passkey options.')
      }
      const publicKey = normalizePublicKeyOptions(extractPublicKeyOptions(await optionsResponse.json()))
      const credential = await navigator.credentials.create({ publicKey })
      if (!credential) throw new Error('Passkey registration was cancelled.')
      const verifyResponse = await fetch('/api/auth/passkeys/register/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential: serializeCredential(credential as PublicKeyCredential), label: 'Browser passkey' }),
      })
      if (!verifyResponse.ok) {
        const data = await verifyResponse.json().catch(() => ({}))
        throw new Error(data.detail ?? 'Passkey verification failed.')
      }
      onUserChange(await verifyResponse.json() as UserProfile)
      setPasskeyStatus('Passkey registered.')
      refreshProfile()
    } catch (error) {
      setPasskeyStatus(error instanceof Error ? error.message : 'Passkey registration failed.')
    }
  }

  return (
    <main className="mx-auto w-full max-w-6xl px-4 py-6">
      <button onClick={onBack} className="mb-4 inline-flex items-center gap-2 rounded-md border border-slate-700 px-3 py-1.5 text-sm text-slate-200 hover:border-slate-500">
        <ArrowLeft className="h-4 w-4" />
        Torna alla dashboard
      </button>

      <div className="mb-6 flex items-center gap-3">
        <div className="rounded-lg bg-brand-500 p-2">
          <UserRound className="h-5 w-5 text-white" />
        </div>
        <div>
          <h1 className="text-xl font-semibold text-white">Profilo utente</h1>
          <p className="text-sm text-slate-400">{user.display_name} ({user.username})</p>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <section className="rounded-lg border border-slate-700 bg-slate-800 p-4">
          <div className="mb-4 flex items-center gap-2 text-white">
            <Smartphone className="h-5 w-5 text-brand-300" />
            <h2 className="text-sm font-semibold">TOTP MFA</h2>
          </div>
          <p className="mb-3 text-sm text-slate-400">Stato: {user.totp_enabled ? 'abilitato' : 'non configurato'}</p>
          <div className="flex gap-2">
            <button onClick={setupTotp} className="rounded-md bg-brand-500 px-3 py-2 text-sm font-semibold text-white">
              {user.totp_enabled ? 'Rigenera TOTP' : 'Configura TOTP'}
            </button>
            {user.totp_enabled && (
              <button onClick={disableTotp} className="rounded-md border border-slate-600 px-3 py-2 text-sm text-slate-200">Disabilita</button>
            )}
          </div>
          {totpSetup && (
            <div className="mt-4 grid gap-4 md:grid-cols-[auto_1fr]">
              <div className="rounded-md bg-white p-2">
                {totpQr ? <img src={totpQr} alt="TOTP QR code" className="h-44 w-44" /> : <QrCode className="h-44 w-44 text-slate-900" />}
              </div>
              <div className="space-y-2 text-sm text-slate-300">
                <div className="flex items-center gap-2 text-slate-100"><ShieldCheck className="h-4 w-4" /> Scansiona il QR con l'app authenticator</div>
                <p>Secret: <code className="break-all text-slate-100">{totpSetup.secret}</code></p>
                <input value={totpCode} onChange={(event) => setTotpCode(event.target.value)} placeholder="Codice 6 cifre" className="w-full rounded-md border border-slate-600 bg-slate-900 px-3 py-2" />
                <button onClick={enableTotp} className="rounded-md bg-brand-500 px-3 py-2 text-sm font-semibold text-white">Verifica e abilita</button>
              </div>
            </div>
          )}
          {totpStatus && <p className="mt-3 text-sm text-amber-300">{totpStatus}</p>}
        </section>

        <section className="rounded-lg border border-slate-700 bg-slate-800 p-4">
          <div className="mb-4 flex items-center gap-2 text-white">
            <KeyRound className="h-5 w-5 text-brand-300" />
            <h2 className="text-sm font-semibold">Passkeys</h2>
          </div>
          <button onClick={registerPasskey} className="rounded-md bg-brand-500 px-3 py-2 text-sm font-semibold text-white">Registra passkey</button>
          {passkeyStatus && <p className="mt-3 text-sm text-amber-300">{passkeyStatus}</p>}
          <div className="mt-4 space-y-2">
            {user.passkeys.length === 0 && <p className="text-sm text-slate-500">Nessuna passkey registrata.</p>}
            {user.passkeys.map((item) => (
              <div key={item.id} className="rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm">
                <div className="font-medium text-slate-100">{item.label}</div>
                <div className="text-xs text-slate-500">Creata {new Date(item.created_at).toLocaleString()}</div>
              </div>
            ))}
          </div>
        </section>
      </div>

      <section className="mt-4 rounded-lg border border-slate-700 bg-slate-800 p-4">
        <h2 className="mb-3 text-sm font-semibold text-white">Recovery codes</h2>
        <div className="flex flex-wrap gap-2">
          {user.recovery_codes.map((item) => (
            <code key={item.code} className={item.used_at ? 'rounded bg-slate-900 px-2 py-1 text-slate-600 line-through' : 'rounded bg-slate-900 px-2 py-1 text-slate-200'}>
              {item.code}
            </code>
          ))}
        </div>
      </section>
    </main>
  )
}
