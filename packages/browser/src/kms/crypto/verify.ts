import { Kms, TypedArrayEncoder } from '@credo-ts/core'
import { ed25519 } from '@noble/curves/ed25519.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { mapJwaSignatureAlgorithmToSubtleHash } from './sign'
import { subtle } from './webcrypto'

export async function performVerify(
  key: Kms.KmsJwkPrivate | Kms.KmsJwkPublicEc | Kms.KmsJwkPublicOkp | Kms.KmsJwkPublicRsa,
  algorithm: Kms.KnownJwaSignatureAlgorithm,
  data: Uint8Array,
  signature: Uint8Array
): Promise<boolean> {
  const hash = mapJwaSignatureAlgorithmToSubtleHash(algorithm)

  switch (key.kty) {
    case 'RSA': {
      const isPss = algorithm.startsWith('PS')
      const cryptoKey = await subtle.importKey(
        'jwk',
        // The key can be a private JWK, only import the public key material
        { kty: key.kty, n: key.n, e: key.e },
        { name: isPss ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5', hash: hash as string },
        false,
        ['verify']
      )

      return await subtle.verify(
        isPss
          ? { name: 'RSA-PSS', saltLength: Number.parseInt(algorithm.slice(2), 10) / 8 }
          : { name: 'RSASSA-PKCS1-v1_5' },
        cryptoKey,
        signature,
        data
      )
    }
    case 'EC': {
      // secp256k1 is not supported by WebCrypto
      if (key.crv === 'secp256k1') {
        const publicKey = TypedArrayEncoder.concat([
          new Uint8Array([0x04]),
          TypedArrayEncoder.fromBase64Url(key.x),
          TypedArrayEncoder.fromBase64Url(key.y),
        ])

        // lowS false to match node, which accepts both low-s and high-s signatures
        return secp256k1.verify(signature, sha256(data), publicKey, { prehash: false, lowS: false })
      }

      const cryptoKey = await subtle.importKey(
        'jwk',
        // The key can be a private JWK, only import the public key material
        { kty: key.kty, crv: key.crv, x: key.x, y: key.y },
        { name: 'ECDSA', namedCurve: key.crv },
        false,
        ['verify']
      )

      // WebCrypto expects EC signatures in the raw format Credo uses
      return await subtle.verify({ name: 'ECDSA', hash: hash as string }, cryptoKey, signature, data)
    }
    case 'OKP': {
      // Ed25519 WebCrypto support is not available in all browsers yet
      if (key.crv !== 'Ed25519') {
        throw new Kms.KeyManagementAlgorithmNotSupportedError(`crv '${key.crv}' for verification`, 'browser')
      }

      return ed25519.verify(signature, data, TypedArrayEncoder.fromBase64Url(key.x))
    }
    case 'oct': {
      const cryptoKey = await subtle.importKey(
        'raw',
        TypedArrayEncoder.fromBase64Url(key.k),
        { name: 'HMAC', hash: hash as string },
        false,
        ['verify']
      )

      // subtle.verify performs a constant-time comparison
      return await subtle.verify('HMAC', cryptoKey, signature, data)
    }
    default:
      // @ts-expect-error
      throw new Kms.KeyManagementAlgorithmNotSupportedError(`kty '${key.kty}'`, 'browser')
  }
}
