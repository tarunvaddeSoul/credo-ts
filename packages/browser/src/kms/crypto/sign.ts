import { Kms, TypedArrayEncoder } from '@credo-ts/core'
import { ed25519 } from '@noble/curves/ed25519.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { jwkForSubtle, subtle } from './webcrypto'

export const browserSupportedJwaAlgorithm = [
  'RS256',
  'PS256',
  'HS256',
  'ES256',
  'ES256K',
  'RS384',
  'PS384',
  'HS384',
  'ES384',
  'RS512',
  'PS512',
  'HS512',
  'ES512',
  'EdDSA',
  'Ed25519',
] as const satisfies Kms.KnownJwaSignatureAlgorithm[]

export function mapJwaSignatureAlgorithmToSubtleHash(algorithm: Kms.KnownJwaSignatureAlgorithm) {
  switch (algorithm) {
    case 'RS256':
    case 'PS256':
    case 'HS256':
    case 'ES256':
    case 'ES256K':
      return 'SHA-256'
    case 'RS384':
    case 'PS384':
    case 'HS384':
    case 'ES384':
      return 'SHA-384'
    case 'RS512':
    case 'PS512':
    case 'HS512':
    case 'ES512':
      return 'SHA-512'
    // For EdDSA the hash is derived based on the key
    case 'EdDSA':
    case 'Ed25519':
      return undefined
    default:
      throw new Kms.KeyManagementAlgorithmNotSupportedError(`JWA algorithm '${algorithm}'`, 'browser')
  }
}

export async function performSign(
  key: Kms.KmsJwkPrivate,
  algorithm: Kms.KnownJwaSignatureAlgorithm,
  data: Uint8Array
): Promise<Uint8Array> {
  const hash = mapJwaSignatureAlgorithmToSubtleHash(algorithm)

  switch (key.kty) {
    case 'RSA': {
      const isPss = algorithm.startsWith('PS')
      const cryptoKey = await subtle.importKey(
        'jwk',
        jwkForSubtle(key),
        { name: isPss ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5', hash: hash as string },
        false,
        ['sign']
      )

      const signature = await subtle.sign(
        isPss
          ? { name: 'RSA-PSS', saltLength: Number.parseInt(algorithm.slice(2), 10) / 8 }
          : { name: 'RSASSA-PKCS1-v1_5' },
        cryptoKey,
        data
      )

      return new Uint8Array(signature)
    }
    case 'EC': {
      // secp256k1 is not supported by WebCrypto
      if (key.crv === 'secp256k1') {
        return secp256k1.sign(sha256(data), TypedArrayEncoder.fromBase64Url(key.d), { prehash: false })
      }

      const cryptoKey = await subtle.importKey(
        'jwk',
        jwkForSubtle(key),
        { name: 'ECDSA', namedCurve: key.crv },
        false,
        ['sign']
      )

      // WebCrypto returns EC signatures in the raw format Credo expects
      const signature = await subtle.sign({ name: 'ECDSA', hash: hash as string }, cryptoKey, data)

      return new Uint8Array(signature)
    }
    case 'OKP': {
      // Ed25519 WebCrypto support is not available in all browsers yet
      if (key.crv !== 'Ed25519') {
        throw new Kms.KeyManagementAlgorithmNotSupportedError(`crv '${key.crv}' for signing`, 'browser')
      }

      return ed25519.sign(data, TypedArrayEncoder.fromBase64Url(key.d))
    }
    case 'oct': {
      const cryptoKey = await subtle.importKey(
        'raw',
        TypedArrayEncoder.fromBase64Url(key.k),
        { name: 'HMAC', hash: hash as string },
        false,
        ['sign']
      )

      return new Uint8Array(await subtle.sign('HMAC', cryptoKey, data))
    }
    default:
      // @ts-expect-error
      throw new Kms.KeyManagementAlgorithmNotSupportedError(`kty '${key.kty}'`, 'browser')
  }
}
