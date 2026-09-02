import type { Kms } from '@credo-ts/core'
import { TypedArrayEncoder } from '@credo-ts/core'
import { hsalsa, xsalsa20poly1305 } from '@noble/ciphers/salsa.js'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { blake2b } from '@noble/hashes/blake2.js'
import { randomBytes } from './webcrypto'

// NaCl crypto_box / crypto_box_seal used by DIDComm v1 envelopes
// (ECDH-HSALSA20 key agreement with XSALSA20-POLY1305 encryption)

// 'expand 32-byte k'
const SIGMA = new Uint8Array([101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107])

const asU32 = (bytes: Uint8Array) => new Uint32Array(bytes.buffer, bytes.byteOffset, bytes.byteLength / 4)

/**
 * crypto_box shared key: hsalsa20(x25519(privateKey, publicKey), zeros)
 */
function cryptoBoxSharedKey(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  const sharedSecret = x25519.getSharedSecret(privateKey, publicKey)

  const output = new Uint32Array(8)
  hsalsa(asU32(SIGMA), asU32(sharedSecret), new Uint32Array(4), output)

  return new Uint8Array(output.buffer)
}

export function cryptoBoxRandomNonce(): Uint8Array {
  return randomBytes(24)
}

export function cryptoBox(options: {
  recipientPublicKey: Uint8Array
  senderPrivateKey: Uint8Array
  message: Uint8Array
  nonce: Uint8Array
}): Uint8Array {
  const key = cryptoBoxSharedKey(options.senderPrivateKey, options.recipientPublicKey)
  return xsalsa20poly1305(key, options.nonce).encrypt(options.message)
}

export function cryptoBoxOpen(options: {
  recipientPrivateKey: Uint8Array
  senderPublicKey: Uint8Array
  message: Uint8Array
  nonce: Uint8Array
}): Uint8Array {
  const key = cryptoBoxSharedKey(options.recipientPrivateKey, options.senderPublicKey)
  return xsalsa20poly1305(key, options.nonce).decrypt(options.message)
}

/**
 * NaCl sealed box: ephemeralPublicKey || crypto_box(message) with
 * nonce = blake2b-24(ephemeralPublicKey || recipientPublicKey)
 */
export function cryptoBoxSeal(options: { recipientPublicKey: Uint8Array; message: Uint8Array }): Uint8Array {
  const ephemeralPrivateKey = x25519.utils.randomSecretKey()
  const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey)

  const nonce = blake2b(TypedArrayEncoder.concat([ephemeralPublicKey, options.recipientPublicKey]), { dkLen: 24 })
  const box = cryptoBox({
    recipientPublicKey: options.recipientPublicKey,
    senderPrivateKey: ephemeralPrivateKey,
    message: options.message,
    nonce,
  })

  return TypedArrayEncoder.concat([ephemeralPublicKey, box])
}

export function cryptoBoxSealOpen(options: { recipientPrivateKey: Uint8Array; ciphertext: Uint8Array }): Uint8Array {
  const ephemeralPublicKey = options.ciphertext.subarray(0, 32)
  const recipientPublicKey = x25519.getPublicKey(options.recipientPrivateKey)

  const nonce = blake2b(TypedArrayEncoder.concat([ephemeralPublicKey, recipientPublicKey]), { dkLen: 24 })

  return cryptoBoxOpen({
    recipientPrivateKey: options.recipientPrivateKey,
    senderPublicKey: ephemeralPublicKey,
    message: options.ciphertext.subarray(32),
    nonce,
  })
}

/**
 * DIDComm v1 uses Ed25519 keys for crypto_box operations, convert to X25519 when needed
 */
export function x25519PrivateKeyFromJwk(jwk: Kms.KmsJwkPrivateOkp): Uint8Array {
  const privateKey = TypedArrayEncoder.fromBase64Url(jwk.d)
  return jwk.crv === 'Ed25519' ? ed25519.utils.toMontgomerySecret(privateKey) : privateKey
}

export function x25519PublicKeyFromJwk(jwk: Kms.KmsJwkPublicOkp): Uint8Array {
  const publicKey = TypedArrayEncoder.fromBase64Url(jwk.x)
  return jwk.crv === 'Ed25519' ? ed25519.utils.toMontgomery(publicKey) : publicKey
}
