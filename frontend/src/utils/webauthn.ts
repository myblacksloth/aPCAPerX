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

export function assertWebAuthnAvailable() {
  // Passkeys only work in secure contexts: HTTPS or localhost.
  if (!window.isSecureContext) {
    throw new Error('Passkeys require HTTPS or localhost. Configure HTTPS for this host before registering a passkey.')
  }
  if (!navigator.credentials || !window.PublicKeyCredential) {
    throw new Error('This browser does not expose WebAuthn/passkey APIs.')
  }
}

export function serializeCredential(credential: PublicKeyCredential): Record<string, unknown> {
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

export function extractPublicKeyOptions(response: unknown) {
  // Some WebAuthn helpers return { publicKey }, others return the publicKey object.
  const data = response as { publicKey?: unknown }
  return (data.publicKey ?? response) as PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions
}

export function normalizePublicKeyOptions(options: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions) {
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
