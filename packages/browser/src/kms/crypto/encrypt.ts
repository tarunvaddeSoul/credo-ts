import { Kms, TypedArrayEncoder } from '@credo-ts/core'
import { chacha20poly1305 } from '@noble/ciphers/chacha.js'
import { aesCbcEncrypt, aesGcmEncrypt } from './aes'
import { performSign } from './sign'
import { randomBytes } from './webcrypto'

export const browserSupportedEncryptionAlgorithms = [
  'A128CBC',
  'A256CBC',
  'A128CBC-HS256',
  'A192CBC-HS384',
  'A256CBC-HS512',
  'A128GCM',
  'A192GCM',
  'A256GCM',
  'C20P',
  // Only in combination with ECDH-HSALSA20 (DIDComm v1)
  'XSALSA20-POLY1305',
] as const satisfies Kms.KnownJwaContentEncryptionAlgorithm[]

export const cbcHmacAlgorithmSettings = {
  'A128CBC-HS256': { hmacAlg: 'HS256', keySize: 16 },
  'A192CBC-HS384': { hmacAlg: 'HS384', keySize: 24 },
  'A256CBC-HS512': { hmacAlg: 'HS512', keySize: 32 },
} as const

/**
 * Calculate the authentication tag for AES-CBC with HMAC (RFC 7518).
 * AL is the 64-bit big-endian bit length of the AAD.
 */
export async function computeCbcHmacTag(options: {
  macKey: Uint8Array
  hmacAlg: 'HS256' | 'HS384' | 'HS512'
  keySize: number
  iv: Uint8Array
  encrypted: Uint8Array
  aad?: Uint8Array
}): Promise<Uint8Array> {
  const al = new Uint8Array(8)
  new DataView(al.buffer).setBigUint64(0, BigInt(options.aad ? options.aad.length * 8 : 0))

  const macData = TypedArrayEncoder.concat([options.aad ?? new Uint8Array(0), options.iv, options.encrypted, al])

  const hmac = await performSign(
    { kty: 'oct', k: TypedArrayEncoder.toBase64Url(options.macKey) },
    options.hmacAlg,
    macData
  )

  return hmac.subarray(0, options.keySize)
}

export async function performEncrypt(
  key: Kms.KmsJwkPrivateOct,
  dataEncryption: Kms.KmsEncryptDataEncryption,
  data: Uint8Array
): Promise<{ encrypted: Uint8Array; tag?: Uint8Array; iv: Uint8Array }> {
  const secretKeyBytes = TypedArrayEncoder.fromBase64Url(key.k)

  if (dataEncryption.algorithm === 'A128CBC' || dataEncryption.algorithm === 'A256CBC') {
    // IV should be exactly 16 bytes (128 bits) for CBC mode
    const iv = dataEncryption.iv ?? randomBytes(16)

    const encrypted = await aesCbcEncrypt(secretKeyBytes, iv, data)

    return { encrypted, iv }
  }

  if (
    dataEncryption.algorithm === 'A128CBC-HS256' ||
    dataEncryption.algorithm === 'A192CBC-HS384' ||
    dataEncryption.algorithm === 'A256CBC-HS512'
  ) {
    const algSettings = cbcHmacAlgorithmSettings[dataEncryption.algorithm]

    // IV should be exactly 16 bytes (128 bits) for CBC mode
    const iv = dataEncryption.iv ?? randomBytes(16)

    // The MAC key is the first half of the input key, the ENC key the second half
    const macKey = secretKeyBytes.subarray(0, algSettings.keySize)
    const encKey = secretKeyBytes.subarray(algSettings.keySize)

    const encrypted = await aesCbcEncrypt(encKey, iv, data)

    const tag = await computeCbcHmacTag({
      macKey,
      hmacAlg: algSettings.hmacAlg,
      keySize: algSettings.keySize,
      iv,
      encrypted,
      aad: dataEncryption.aad,
    })

    return { encrypted, tag, iv }
  }

  if (
    dataEncryption.algorithm === 'A128GCM' ||
    dataEncryption.algorithm === 'A192GCM' ||
    dataEncryption.algorithm === 'A256GCM'
  ) {
    // IV should be exactly 12 bytes (96 bits) for GCM
    const iv = dataEncryption.iv ?? randomBytes(12)

    const { encrypted, tag } = await aesGcmEncrypt(secretKeyBytes, iv, data, dataEncryption.aad)

    return { encrypted, tag, iv }
  }

  if (dataEncryption.algorithm === 'C20P') {
    // IV should be exactly 12 bytes (96 bits) for C20P
    const iv = dataEncryption.iv ?? randomBytes(12)

    // ChaCha20-Poly1305 is not supported by WebCrypto
    const combined = chacha20poly1305(secretKeyBytes, iv, dataEncryption.aad).encrypt(data)

    return {
      encrypted: combined.subarray(0, combined.length - 16),
      tag: combined.subarray(combined.length - 16),
      iv,
    }
  }

  throw new Kms.KeyManagementAlgorithmNotSupportedError(
    `JWA content encryption algorithm '${dataEncryption.algorithm}'`,
    'browser'
  )
}
