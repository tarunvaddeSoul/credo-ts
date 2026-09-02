import type { Kms } from '@credo-ts/core'

export const subtle = globalThis.crypto.subtle

export function randomBytes(length: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(length))
}

export function randomUuid(): string {
  return globalThis.crypto.randomUUID()
}

/**
 * WebCrypto rejects JWKs where `alg`/`use`/`key_ops` conflict with the requested
 * import parameters, while Credo JWKs are algorithm-agnostic. Strip all metadata
 * so only the key material is imported.
 */
export function jwkForSubtle(jwk: Kms.KmsJwkPrivate | Kms.KmsJwkPublic): Record<string, unknown> {
  const {
    kid,
    use,
    key_ops,
    alg,
    ext,
    x5c,
    x5t,
    x5u,
    'x5t#S256': x5tS256,
    ...keyMaterial
  } = jwk as Record<string, unknown>

  return keyMaterial
}

/**
 * Strip WebCrypto specific metadata (`alg`, `key_ops`, `ext`) from a JWK exported
 * with `subtle.exportKey` so the stored JWK stays algorithm-agnostic.
 */
export function stripJwkMetadata<Jwk>(jwk: unknown): Jwk {
  const { alg, key_ops, ext, use, ...keyMaterial } = jwk as Record<string, unknown>

  return keyMaterial as Jwk
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false

  let result = 0
  for (let i = 0; i < a.length; i++) result |= a[i] ^ b[i]

  return result === 0
}
