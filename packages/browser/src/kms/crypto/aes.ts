import { TypedArrayEncoder } from '@credo-ts/core'
import { cbc, gcm } from '@noble/ciphers/aes.js'
import { subtle } from './webcrypto'

// Chromium refuses 192 bit AES keys in WebCrypto, so 192 bit
// operations are performed with a pure JS implementation

export async function aesCbcEncrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  if (key.length === 24) return cbc(key, iv).encrypt(data)

  const cryptoKey = await subtle.importKey('raw', key, 'AES-CBC', false, ['encrypt'])
  return new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv }, cryptoKey, data))
}

export async function aesCbcDecrypt(key: Uint8Array, iv: Uint8Array, encrypted: Uint8Array): Promise<Uint8Array> {
  if (key.length === 24) return cbc(key, iv).decrypt(encrypted)

  const cryptoKey = await subtle.importKey('raw', key, 'AES-CBC', false, ['decrypt'])
  return new Uint8Array(await subtle.decrypt({ name: 'AES-CBC', iv }, cryptoKey, encrypted))
}

export async function aesGcmEncrypt(
  key: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array,
  aad?: Uint8Array
): Promise<{ encrypted: Uint8Array; tag: Uint8Array }> {
  let combined: Uint8Array
  if (key.length === 24) {
    combined = gcm(key, iv, aad).encrypt(data)
  } else {
    const cryptoKey = await subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt'])
    combined = new Uint8Array(
      await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, cryptoKey, data)
    )
  }

  // The 16 byte auth tag is appended to the ciphertext
  return {
    encrypted: combined.subarray(0, combined.length - 16),
    tag: combined.subarray(combined.length - 16),
  }
}

export async function aesGcmDecrypt(
  key: Uint8Array,
  iv: Uint8Array,
  encrypted: Uint8Array,
  tag: Uint8Array,
  aad?: Uint8Array
): Promise<Uint8Array> {
  const combined = TypedArrayEncoder.concat([encrypted, tag])

  if (key.length === 24) return gcm(key, iv, aad).decrypt(combined)

  const cryptoKey = await subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt'])
  return new Uint8Array(
    await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, cryptoKey, combined)
  )
}
