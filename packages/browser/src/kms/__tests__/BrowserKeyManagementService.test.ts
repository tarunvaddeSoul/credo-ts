import { readFileSync } from 'node:fs'
import path from 'node:path'
import { JsonEncoder, Kms, TypedArrayEncoder } from '@credo-ts/core'
import { getAgentContext } from '../../../../core/tests'
import { BrowserInMemoryKeyManagementStorage } from '../BrowserInMemoryKeyManagementStorage'
import { BrowserKeyManagementService } from '../BrowserKeyManagementService'

const agentContext = getAgentContext({ contextCorrelationId: 'default' })
const agentContextTenant = getAgentContext({ contextCorrelationId: 'd5d0141d-9456-49ec-9c52-338d2f4a7c60' })

describe('BrowserKeyManagementService', () => {
  let service: BrowserKeyManagementService
  let storage: BrowserInMemoryKeyManagementStorage

  beforeEach(() => {
    storage = new BrowserInMemoryKeyManagementStorage()
    service = new BrowserKeyManagementService(storage)
  })

  it('correctly identifies backend as browser', () => {
    expect(service.backend).toBe('browser')
  })

  describe('tenants', () => {
    it('automatically handles new context correlation ids', async () => {
      const { publicJwk } = await service.createKey(agentContextTenant, {
        type: { kty: 'EC', crv: 'P-256' },
        keyId: 'key-1',
      })

      expect(await storage.get(agentContext, 'key-1')).toBeNull()
      expect(await storage.get(agentContextTenant, 'key-1')).toEqual({
        ...publicJwk,
        d: expect.any(String),
      })
    })
  })

  describe('createKey', () => {
    it('throws error if key id already exists', async () => {
      const keyId = 'test-key'
      await service.createKey(agentContext, { type: { kty: 'EC', crv: 'P-256' }, keyId })

      await expect(service.createKey(agentContext, { type: { kty: 'EC', crv: 'P-256' }, keyId })).rejects.toThrow(
        new Kms.KeyManagementKeyExistsError('test-key', service.backend)
      )
    })

    it.each(['P-256', 'P-384', 'P-521', 'secp256k1'] as const)('creates EC %s key successfully', async (crv) => {
      const result = await service.createKey(agentContext, { type: { kty: 'EC', crv } })

      expect(result).toEqual({
        keyId: expect.any(String),
        publicJwk: {
          kid: result.keyId,
          kty: 'EC',
          crv,
          x: expect.any(String),
          y: expect.any(String),
        },
      })

      expect(await service.getPublicKey(agentContext, result.keyId)).toEqual(result.publicJwk)
    })

    it.each(['Ed25519', 'X25519'] as const)('creates OKP %s key successfully', async (crv) => {
      const result = await service.createKey(agentContext, { type: { kty: 'OKP', crv } })

      expect(result).toEqual({
        keyId: expect.any(String),
        publicJwk: {
          kid: result.keyId,
          kty: 'OKP',
          crv,
          x: expect.any(String),
        },
      })

      expect(await service.getPublicKey(agentContext, result.keyId)).toEqual(result.publicJwk)
    })

    it('creates RSA 2048 key successfully', async () => {
      const result = await service.createKey(agentContext, { type: { kty: 'RSA', modulusLength: 2048 } })

      expect(result).toEqual({
        keyId: expect.any(String),
        publicJwk: {
          kid: result.keyId,
          kty: 'RSA',
          n: expect.any(String),
          e: expect.any(String),
        },
      })
    })

    it('creates oct aes and hmac keys without exposing key material', async () => {
      const aes = await service.createKey(agentContext, { type: { kty: 'oct', algorithm: 'aes', length: 256 } })
      expect(aes.publicJwk).toEqual({ kid: aes.keyId, kty: 'oct' })

      const hmac = await service.createKey(agentContext, { type: { kty: 'oct', algorithm: 'hmac', length: 512 } })
      expect(hmac.publicJwk).toEqual({ kid: hmac.keyId, kty: 'oct' })
    })

    it('throws for oct C20P key creation', async () => {
      await expect(service.createKey(agentContext, { type: { kty: 'oct', algorithm: 'C20P' } })).rejects.toThrow(
        Kms.KeyManagementAlgorithmNotSupportedError
      )
    })
  })

  describe('sign and verify', () => {
    it.each([
      ['RS256', { kty: 'RSA', modulusLength: 2048 }],
      ['RS384', { kty: 'RSA', modulusLength: 3072 }],
      ['RS512', { kty: 'RSA', modulusLength: 4096 }],
      ['PS256', { kty: 'RSA', modulusLength: 2048 }],
      ['PS384', { kty: 'RSA', modulusLength: 3072 }],
      ['PS512', { kty: 'RSA', modulusLength: 4096 }],
      ['ES256', { kty: 'EC', crv: 'P-256' }],
      ['ES384', { kty: 'EC', crv: 'P-384' }],
      ['ES512', { kty: 'EC', crv: 'P-521' }],
      ['ES256K', { kty: 'EC', crv: 'secp256k1' }],
      ['EdDSA', { kty: 'OKP', crv: 'Ed25519' }],
      ['Ed25519', { kty: 'OKP', crv: 'Ed25519' }],
      ['HS256', { kty: 'oct', algorithm: 'hmac', length: 256 }],
      ['HS384', { kty: 'oct', algorithm: 'hmac', length: 384 }],
      ['HS512', { kty: 'oct', algorithm: 'hmac', length: 512 }],
    ] as const)('signs and verifies with %s', async (algorithm, type) => {
      const { keyId, publicJwk } = await service.createKey(agentContext, { type: type as Kms.KmsCreateKeyType })
      const data = TypedArrayEncoder.fromUtf8String('some random data')

      const { signature } = await service.sign(agentContext, { keyId, algorithm, data })

      // Verify with key id
      const byKeyId = await service.verify(agentContext, { key: { keyId }, algorithm, data, signature })
      expect(byKeyId).toEqual({ verified: true, publicJwk: expect.objectContaining({ kty: publicJwk.kty }) })

      // Verify with public jwk for asymmetric keys
      if (publicJwk.kty !== 'oct') {
        const byPublicJwk = await service.verify(agentContext, {
          key: { publicJwk: publicJwk as Kms.KmsJwkPublicAsymmetric },
          algorithm,
          data,
          signature,
        })
        expect(byPublicJwk.verified).toBe(true)
      }

      // A corrupted signature does not verify
      const corrupted = new Uint8Array(signature)
      corrupted[8] ^= 0xff
      const corruptedResult = await service.verify(agentContext, {
        key: { keyId },
        algorithm,
        data,
        signature: corrupted,
      })
      expect(corruptedResult).toEqual({ verified: false })

      // Modified data does not verify
      const modifiedResult = await service.verify(agentContext, {
        key: { keyId },
        algorithm,
        data: TypedArrayEncoder.fromUtf8String('other data'),
        signature,
      })
      expect(modifiedResult).toEqual({ verified: false })
    })

    it('throws error for missing keys', async () => {
      await expect(
        service.sign(agentContext, { keyId: 'nope', algorithm: 'ES256', data: new Uint8Array([1]) })
      ).rejects.toThrow(Kms.KeyManagementKeyNotFoundError)
    })

    it('throws error when key and algorithm do not match', async () => {
      const ecKey = await service.createKey(agentContext, { type: { kty: 'EC', crv: 'P-256' } })
      await expect(
        service.sign(agentContext, { keyId: ecKey.keyId, algorithm: 'RS256', data: new Uint8Array([1]) })
      ).rejects.toThrow(Kms.KeyManagementError)

      const x25519Key = await service.createKey(agentContext, { type: { kty: 'OKP', crv: 'X25519' } })
      await expect(
        service.sign(agentContext, { keyId: x25519Key.keyId, algorithm: 'EdDSA', data: new Uint8Array([1]) })
      ).rejects.toThrow(Kms.KeyManagementError)

      const hmacKey = await service.createKey(agentContext, { type: { kty: 'oct', algorithm: 'hmac', length: 384 } })
      await expect(
        service.sign(agentContext, { keyId: hmacKey.keyId, algorithm: 'HS512', data: new Uint8Array([1]) })
      ).rejects.toThrow(Kms.KeyManagementError)
    })
  })

  describe('importKey', () => {
    it.each(['P-256', 'P-384', 'P-521', 'secp256k1'] as const)('imports an EC %s key', async (crv) => {
      const { keyId } = await service.createKey(agentContext, { type: { kty: 'EC', crv } })
      const privateJwk = (await storage.get(agentContext, keyId)) as Kms.KmsJwkPrivateEc

      const imported = await service.importKey(agentContext, {
        privateJwk: { ...privateJwk, kid: `imported-${crv}` },
      })

      expect(imported.keyId).toBe(`imported-${crv}`)
      expect(imported.publicJwk).toEqual({
        kid: `imported-${crv}`,
        kty: 'EC',
        crv,
        x: privateJwk.x,
        y: privateJwk.y,
      })

      // Imported key can sign
      const algorithm = crv === 'P-256' ? 'ES256' : crv === 'P-384' ? 'ES384' : crv === 'P-521' ? 'ES512' : 'ES256K'
      const data = TypedArrayEncoder.fromUtf8String('imported key data')
      const { signature } = await service.sign(agentContext, { keyId: imported.keyId, algorithm, data })
      const result = await service.verify(agentContext, { key: { keyId: imported.keyId }, algorithm, data, signature })
      expect(result.verified).toBe(true)
    })

    it.each(['Ed25519', 'X25519'] as const)('imports an OKP %s key', async (crv) => {
      const { keyId } = await service.createKey(agentContext, { type: { kty: 'OKP', crv } })
      const privateJwk = (await storage.get(agentContext, keyId)) as Kms.KmsJwkPrivateOkp

      const imported = await service.importKey(agentContext, {
        privateJwk: { ...privateJwk, kid: `imported-${crv}` },
      })

      expect(imported.publicJwk).toEqual({
        kid: `imported-${crv}`,
        kty: 'OKP',
        crv,
        x: privateJwk.x,
      })
    })

    it('imports an RSA key', async () => {
      const { keyId } = await service.createKey(agentContext, { type: { kty: 'RSA', modulusLength: 2048 } })
      const privateJwk = (await storage.get(agentContext, keyId)) as Kms.KmsJwkPrivateRsa

      const imported = await service.importKey(agentContext, {
        privateJwk: { ...privateJwk, kid: 'imported-rsa' },
      })

      expect(imported.publicJwk).toEqual({
        kid: 'imported-rsa',
        kty: 'RSA',
        n: privateJwk.n,
        e: privateJwk.e,
      })
    })

    it('imports an oct key and generates a kid when not provided', async () => {
      const imported = await service.importKey(agentContext, {
        privateJwk: {
          kty: 'oct',
          k: TypedArrayEncoder.toBase64Url(new Uint8Array(32).fill(7)),
        },
      })

      expect(imported.keyId).toEqual(expect.any(String))
      expect(imported.publicJwk).toEqual({ kid: imported.keyId, kty: 'oct' })
    })

    it('throws for duplicate kid', async () => {
      await service.createKey(agentContext, { type: { kty: 'EC', crv: 'P-256' }, keyId: 'dup' })
      const { keyId } = await service.createKey(agentContext, { type: { kty: 'EC', crv: 'P-256' } })
      const privateJwk = (await storage.get(agentContext, keyId)) as Kms.KmsJwkPrivateEc

      await expect(service.importKey(agentContext, { privateJwk: { ...privateJwk, kid: 'dup' } })).rejects.toThrow(
        Kms.KeyManagementKeyExistsError
      )
    })
  })

  describe('deleteKey', () => {
    it('deletes an existing key and returns false for missing keys', async () => {
      const { keyId } = await service.createKey(agentContext, { type: { kty: 'EC', crv: 'P-256' } })

      expect(await service.deleteKey(agentContext, { keyId })).toBe(true)
      expect(await storage.has(agentContext, keyId)).toBe(false)
      expect(await service.deleteKey(agentContext, { keyId })).toBe(false)
    })
  })

  describe('getPublicKey', () => {
    it('returns null for missing keys', async () => {
      expect(await service.getPublicKey(agentContext, 'nope')).toBeNull()
    })

    it('does not return private key material', async () => {
      const { keyId } = await service.createKey(agentContext, { type: { kty: 'OKP', crv: 'Ed25519' } })
      const publicJwk = await service.getPublicKey(agentContext, keyId)

      expect(publicJwk).not.toHaveProperty('d')
    })
  })

  describe('encrypt and decrypt', () => {
    it.each([
      ['A128GCM', 32, 12],
      ['A192GCM', 48, 12],
      ['A256GCM', 64, 12],
      ['A128CBC-HS256', 64, 16],
      ['A192CBC-HS384', 96, 16],
      ['A256CBC-HS512', 128, 16],
    ] as const)('encrypts and decrypts with %s', async (algorithm, keyLengthBytes, ivLength) => {
      const privateJwk: Kms.KmsJwkPrivateOct = {
        kty: 'oct',
        k: TypedArrayEncoder.toBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(keyLengthBytes / 2))),
      }
      const data = TypedArrayEncoder.fromUtf8String('secret data')
      const aad = TypedArrayEncoder.fromUtf8String('additional data')

      const encrypted = await service.encrypt(agentContext, {
        key: { privateJwk },
        encryption: { algorithm, aad },
        data,
      })

      expect(encrypted.iv).toHaveLength(ivLength)
      expect(encrypted.tag).toBeDefined()

      const decrypted = await service.decrypt(agentContext, {
        key: { privateJwk },
        decryption: {
          algorithm,
          aad,
          // biome-ignore lint/style/noNonNullAssertion: always defined for these algorithms
          iv: encrypted.iv!,
          // biome-ignore lint/style/noNonNullAssertion: always defined for these algorithms
          tag: encrypted.tag!,
        },
        encrypted: encrypted.encrypted,
      })

      expect(decrypted.data).toEqual(data)
    })

    it.each([
      ['A128CBC', 16],
      ['A256CBC', 32],
    ] as const)('encrypts and decrypts with %s', async (algorithm, keyLengthBytes) => {
      const privateJwk: Kms.KmsJwkPrivateOct = {
        kty: 'oct',
        k: TypedArrayEncoder.toBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(keyLengthBytes))),
      }
      const data = TypedArrayEncoder.fromUtf8String('secret data')

      const encrypted = await service.encrypt(agentContext, {
        key: { privateJwk },
        encryption: { algorithm },
        data,
      })

      const decrypted = await service.decrypt(agentContext, {
        key: { privateJwk },
        // biome-ignore lint/style/noNonNullAssertion: always defined for CBC
        decryption: { algorithm, iv: encrypted.iv! },
        encrypted: encrypted.encrypted,
      })

      expect(decrypted.data).toEqual(data)
    })

    it('encrypts and decrypts with C20P', async () => {
      const privateJwk: Kms.KmsJwkPrivateOct = {
        kty: 'oct',
        k: TypedArrayEncoder.toBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(32))),
      }
      const data = TypedArrayEncoder.fromUtf8String('secret data')

      const encrypted = await service.encrypt(agentContext, {
        key: { privateJwk },
        encryption: { algorithm: 'C20P' },
        data,
      })

      const decrypted = await service.decrypt(agentContext, {
        key: { privateJwk },
        decryption: {
          algorithm: 'C20P',
          // biome-ignore lint/style/noNonNullAssertion: always defined for C20P
          iv: encrypted.iv!,
          // biome-ignore lint/style/noNonNullAssertion: always defined for C20P
          tag: encrypted.tag!,
        },
        encrypted: encrypted.encrypted,
      })

      expect(decrypted.data).toEqual(data)
    })

    it('throws on tampered authentication tag', async () => {
      const privateJwk: Kms.KmsJwkPrivateOct = {
        kty: 'oct',
        k: TypedArrayEncoder.toBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(32))),
      }
      const data = TypedArrayEncoder.fromUtf8String('secret data')

      const encrypted = await service.encrypt(agentContext, {
        key: { privateJwk },
        encryption: { algorithm: 'A128CBC-HS256' },
        data,
      })

      // biome-ignore lint/style/noNonNullAssertion: always defined for A128CBC-HS256
      const tamperedTag = new Uint8Array(encrypted.tag!)
      tamperedTag[0] ^= 0xff

      await expect(
        service.decrypt(agentContext, {
          key: { privateJwk },
          decryption: {
            algorithm: 'A128CBC-HS256',
            // biome-ignore lint/style/noNonNullAssertion: always defined for A128CBC-HS256
            iv: encrypted.iv!,
            tag: tamperedTag,
          },
          encrypted: encrypted.encrypted,
        })
      ).rejects.toThrow(Kms.KeyManagementError)
    })

    it.each([
      'X25519',
      'P-256',
      'secp256k1',
    ] as const)('encrypts and decrypts with ECDH-ES between two %s keys', async (crv) => {
      const type: Kms.KmsCreateKeyType =
        crv === 'X25519' ? { kty: 'OKP', crv } : { kty: 'EC', crv: crv as 'P-256' | 'secp256k1' }

      const sender = await service.createKey(agentContext, { type })
      const recipient = await service.createKey(agentContext, { type })

      const data = TypedArrayEncoder.fromUtf8String('ecdh secret data')

      const encrypted = await service.encrypt(agentContext, {
        key: {
          keyAgreement: {
            algorithm: 'ECDH-ES',
            keyId: sender.keyId,
            externalPublicJwk: recipient.publicJwk as Kms.KmsKeyAgreementEncryptOptions['externalPublicJwk'],
          },
        },
        encryption: { algorithm: 'A256GCM' },
        data,
      })

      const decrypted = await service.decrypt(agentContext, {
        key: {
          keyAgreement: {
            algorithm: 'ECDH-ES',
            keyId: recipient.keyId,
            externalPublicJwk: sender.publicJwk as Kms.KmsKeyAgreementEncryptOptions['externalPublicJwk'],
          },
        },
        decryption: {
          algorithm: 'A256GCM',
          // biome-ignore lint/style/noNonNullAssertion: always defined for A256GCM
          iv: encrypted.iv!,
          // biome-ignore lint/style/noNonNullAssertion: always defined for A256GCM
          tag: encrypted.tag!,
        },
        encrypted: encrypted.encrypted,
      })

      expect(decrypted.data).toEqual(data)
    })

    it.each([
      'ECDH-ES+A128KW',
      'ECDH-ES+A192KW',
      'ECDH-ES+A256KW',
    ] as const)('encrypts and decrypts with %s key wrapping', async (algorithm) => {
      const sender = await service.createKey(agentContext, { type: { kty: 'EC', crv: 'P-256' } })
      const recipient = await service.createKey(agentContext, { type: { kty: 'EC', crv: 'P-256' } })

      const data = TypedArrayEncoder.fromUtf8String('wrapped key data')

      const encrypted = await service.encrypt(agentContext, {
        key: {
          keyAgreement: {
            algorithm,
            keyId: sender.keyId,
            externalPublicJwk: recipient.publicJwk as Kms.KmsKeyAgreementEncryptOptions['externalPublicJwk'],
          },
        },
        encryption: { algorithm: 'A256GCM' },
        data,
      })

      expect(encrypted.encryptedKey).toBeDefined()

      const decrypted = await service.decrypt(agentContext, {
        key: {
          keyAgreement: {
            algorithm,
            keyId: recipient.keyId,
            externalPublicJwk: sender.publicJwk as Kms.KmsKeyAgreementEncryptOptions['externalPublicJwk'],
            // biome-ignore lint/style/noNonNullAssertion: always defined for key wrapping
            encryptedKey: encrypted.encryptedKey!,
          },
        },
        decryption: {
          algorithm: 'A256GCM',
          // biome-ignore lint/style/noNonNullAssertion: always defined for A256GCM
          iv: encrypted.iv!,
          // biome-ignore lint/style/noNonNullAssertion: always defined for A256GCM
          tag: encrypted.tag!,
        },
        encrypted: encrypted.encrypted,
      })

      expect(decrypted.data).toEqual(data)
    })

    it('decrypts a JARM JWE encrypted response with ECDH-ES and A256GCM', async () => {
      const { compactJwe, privateKeyJwk, decodedPayload } = JSON.parse(
        readFileSync(path.join(__dirname, '../__fixtures__/jarm-jwe-encrypted-response.json'), 'utf-8')
      ) as {
        compactJwe: string
        decodedPayload: Record<string, unknown>
        privateKeyJwk: Kms.KmsJwkPrivate
      }

      const [encodedHeader /* encryptionKey */, , encodedIv, encodedCiphertext, encodedTag] = compactJwe.split('.')
      const header = JsonEncoder.fromBase64Url(encodedHeader)

      const { keyId } = await service.importKey(agentContext, { privateJwk: privateKeyJwk })

      const decrypted = await service.decrypt(agentContext, {
        key: {
          keyAgreement: {
            algorithm: 'ECDH-ES',
            keyId,
            externalPublicJwk: header.epk,
            apu: TypedArrayEncoder.fromBase64Url(header.apu),
            apv: TypedArrayEncoder.fromBase64Url(header.apv),
          },
        },
        decryption: {
          algorithm: 'A256GCM',
          iv: TypedArrayEncoder.fromBase64Url(encodedIv),
          tag: TypedArrayEncoder.fromBase64Url(encodedTag),
          aad: TypedArrayEncoder.fromUtf8String(encodedHeader),
        },
        encrypted: TypedArrayEncoder.fromBase64Url(encodedCiphertext),
      })

      expect(JsonEncoder.fromUint8Array(decrypted.data)).toEqual(decodedPayload)
    })
  })

  describe('ECDH-HSALSA20 with XSALSA20-POLY1305 (DIDComm v1)', () => {
    it('encrypts and decrypts with a sender key (authcrypt)', async () => {
      const { ed25519 } = await import('@noble/curves/ed25519.js')

      // DIDComm v1 uses the Ed25519 verkey for crypto box operations
      const sender = await service.createKey(agentContext, { type: { kty: 'OKP', crv: 'Ed25519' } })
      const recipient = await service.createKey(agentContext, { type: { kty: 'OKP', crv: 'X25519' } })
      const data = TypedArrayEncoder.fromUtf8String('didcomm v1 message')

      const encrypted = await service.encrypt(agentContext, {
        key: {
          keyAgreement: {
            algorithm: 'ECDH-HSALSA20',
            keyId: sender.keyId,
            externalPublicJwk: recipient.publicJwk as Kms.KmsJwkPublicOkp & { crv: 'X25519' },
          },
        },
        encryption: { algorithm: 'XSALSA20-POLY1305' },
        data,
      })
      expect(encrypted.iv).toHaveLength(24)

      const senderX25519PublicJwk = {
        kty: 'OKP',
        crv: 'X25519',
        x: TypedArrayEncoder.toBase64Url(
          ed25519.utils.toMontgomery(TypedArrayEncoder.fromBase64Url((sender.publicJwk as Kms.KmsJwkPublicOkp).x))
        ),
      } as const

      const decrypted = await service.decrypt(agentContext, {
        key: {
          keyAgreement: {
            algorithm: 'ECDH-HSALSA20',
            keyId: recipient.keyId,
            externalPublicJwk: senderX25519PublicJwk,
          },
        },
        decryption: {
          algorithm: 'XSALSA20-POLY1305',
          // biome-ignore lint/style/noNonNullAssertion: always defined for authcrypt
          iv: encrypted.iv!,
        },
        encrypted: encrypted.encrypted,
      })

      expect(decrypted.data).toEqual(data)
    })

    it('encrypts and decrypts without a sender key (anoncrypt)', async () => {
      const recipient = await service.createKey(agentContext, { type: { kty: 'OKP', crv: 'X25519' } })
      const data = TypedArrayEncoder.fromUtf8String('anonymous didcomm v1 message')

      const encrypted = await service.encrypt(agentContext, {
        key: {
          keyAgreement: {
            algorithm: 'ECDH-HSALSA20',
            externalPublicJwk: recipient.publicJwk as Kms.KmsJwkPublicOkp & { crv: 'X25519' },
          },
        },
        encryption: { algorithm: 'XSALSA20-POLY1305' },
        data,
      })
      expect(encrypted.iv).toBeUndefined()

      const decrypted = await service.decrypt(agentContext, {
        key: { keyAgreement: { algorithm: 'ECDH-HSALSA20', keyId: recipient.keyId } },
        decryption: { algorithm: 'XSALSA20-POLY1305' },
        encrypted: encrypted.encrypted,
      })

      expect(decrypted.data).toEqual(data)
    })
  })

  describe('randomBytes', () => {
    it('returns the requested number of random bytes', () => {
      const bytes = service.randomBytes(agentContext, { length: 32 })
      expect(bytes).toBeInstanceOf(Uint8Array)
      expect(bytes).toHaveLength(32)
    })
  })
})
