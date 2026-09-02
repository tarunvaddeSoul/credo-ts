import type { AgentContext } from '@credo-ts/core'
import { Kms, TypedArrayEncoder } from '@credo-ts/core'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import type { BrowserKeyManagementStorage } from './BrowserKeyManagementStorage'
import {
  assertBrowserSupportedEcCrv,
  assertBrowserSupportedOctAlgorithm,
  assertBrowserSupportedOkpCrv,
  createEcKey,
  createOctKey,
  createOkpKey,
  createRsaKey,
} from './crypto/createKey'
import {
  cryptoBox,
  cryptoBoxOpen,
  cryptoBoxRandomNonce,
  cryptoBoxSeal,
  cryptoBoxSealOpen,
  x25519PrivateKeyFromJwk,
  x25519PublicKeyFromJwk,
} from './crypto/cryptoBox'
import { performDecrypt } from './crypto/decrypt'
import { browserSupportedKeyAgreementAlgorithms, deriveDecryptionKey, deriveEncryptionKey } from './crypto/deriveKey'
import { browserSupportedEncryptionAlgorithms, performEncrypt } from './crypto/encrypt'
import { browserSupportedJwaAlgorithm, performSign } from './crypto/sign'
import { performVerify } from './crypto/verify'
import { jwkForSubtle, randomBytes, randomUuid, subtle } from './crypto/webcrypto'

export class BrowserKeyManagementService implements Kms.KeyManagementService {
  public readonly backend = 'browser'

  #storage: BrowserKeyManagementStorage

  public constructor(storage: BrowserKeyManagementStorage) {
    this.#storage = storage
  }

  public isOperationSupported(_agentContext: AgentContext, operation: Kms.KmsOperation): boolean {
    if (operation.operation === 'deleteKey') return true
    if (operation.operation === 'randomBytes') return true

    if (operation.operation === 'createKey') {
      try {
        if (operation.type.kty === 'RSA') {
          return true
        }

        if (operation.type.kty === 'EC') {
          assertBrowserSupportedEcCrv(operation.type)
          return true
        }

        if (operation.type.kty === 'OKP') {
          assertBrowserSupportedOkpCrv(operation.type)
          return true
        }

        if (operation.type.kty === 'oct') {
          assertBrowserSupportedOctAlgorithm(operation.type)
          return true
        }
      } catch {
        return false
      }

      return false
    }

    if (operation.operation === 'importKey') {
      try {
        if (operation.privateJwk.kty === 'RSA' || operation.privateJwk.kty === 'oct') {
          return true
        }

        if (operation.privateJwk.kty === 'EC') {
          assertBrowserSupportedEcCrv({ kty: operation.privateJwk.kty, crv: operation.privateJwk.crv })
          return true
        }

        if (operation.privateJwk.kty === 'OKP') {
          assertBrowserSupportedOkpCrv({ kty: operation.privateJwk.kty, crv: operation.privateJwk.crv })
          return true
        }
      } catch {
        return false
      }
    }

    if (operation.operation === 'sign' || operation.operation === 'verify') {
      return browserSupportedJwaAlgorithm.includes(operation.algorithm)
    }

    if (operation.operation === 'encrypt') {
      const isSupportedEncryptionAlgorithm = browserSupportedEncryptionAlgorithms.includes(
        operation.encryption.algorithm as (typeof browserSupportedEncryptionAlgorithms)[number]
      )
      if (!isSupportedEncryptionAlgorithm) return false
      if (!operation.keyAgreement) return true

      return browserSupportedKeyAgreementAlgorithms.includes(
        operation.keyAgreement.algorithm as (typeof browserSupportedKeyAgreementAlgorithms)[number]
      )
    }

    if (operation.operation === 'decrypt') {
      const isSupportedEncryptionAlgorithm = browserSupportedEncryptionAlgorithms.includes(
        operation.decryption.algorithm as (typeof browserSupportedEncryptionAlgorithms)[number]
      )
      if (!isSupportedEncryptionAlgorithm) return false
      if (!operation.keyAgreement) return true

      return browserSupportedKeyAgreementAlgorithms.includes(
        operation.keyAgreement.algorithm as (typeof browserSupportedKeyAgreementAlgorithms)[number]
      )
    }

    return false
  }

  public randomBytes(_agentContext: AgentContext, options: Kms.KmsRandomBytesOptions): Kms.KmsRandomBytesReturn {
    return randomBytes(options.length)
  }

  public async getPublicKey(agentContext: AgentContext, keyId: string): Promise<Kms.KmsJwkPublic | null> {
    const privateJwk = await this.#storage.get(agentContext, keyId)
    if (!privateJwk) return null

    return Kms.publicJwkFromPrivateJwk(privateJwk)
  }

  public async importKey<Jwk extends Kms.KmsJwkPrivate>(
    agentContext: AgentContext,
    options: Kms.KmsImportKeyOptions<Jwk>
  ): Promise<Kms.KmsImportKeyReturn<Jwk>> {
    const { kid } = options.privateJwk

    if (kid) await this.assertKeyNotExists(agentContext, kid)

    const privateJwk = {
      ...options.privateJwk,
      kid: kid ?? randomUuid(),
    }

    try {
      if (privateJwk.kty === 'oct') {
        if (TypedArrayEncoder.fromBase64Url(privateJwk.k).length === 0) {
          throw new Kms.KeyManagementError('Invalid oct key. Key material must not be empty.')
        }
      } else if (privateJwk.kty === 'EC') {
        assertBrowserSupportedEcCrv({ kty: privateJwk.kty, crv: privateJwk.crv })

        if (privateJwk.crv === 'secp256k1') {
          // WebCrypto does not support secp256k1, validate the key with noble
          secp256k1.getPublicKey(TypedArrayEncoder.fromBase64Url(privateJwk.d))
        } else {
          // This validates the JWK
          await subtle.importKey(
            'jwk',
            jwkForSubtle(privateJwk),
            { name: 'ECDSA', namedCurve: privateJwk.crv },
            false,
            ['sign']
          )
        }
      } else if (privateJwk.kty === 'OKP') {
        assertBrowserSupportedOkpCrv({ kty: privateJwk.kty, crv: privateJwk.crv })

        // WebCrypto Ed25519/X25519 support is not available in all browsers, validate with noble
        const curve = privateJwk.crv === 'Ed25519' ? ed25519 : x25519
        curve.getPublicKey(TypedArrayEncoder.fromBase64Url(privateJwk.d))
      } else if (privateJwk.kty === 'RSA') {
        // This validates the JWK
        await subtle.importKey('jwk', jwkForSubtle(privateJwk), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, [
          'sign',
        ])
      } else {
        // All kty values supported for now, but can change in the future
        // @ts-expect-error
        throw new Kms.KeyManagementAlgorithmNotSupportedError(`kty '${privateJwk.kty}'`, this.backend)
      }

      await this.#storage.set(agentContext, privateJwk.kid, privateJwk)
      const publicJwk = Kms.publicJwkFromPrivateJwk(privateJwk)

      return {
        keyId: privateJwk.kid,
        publicJwk: {
          ...publicJwk,
          kid: privateJwk.kid,
        },
      } as Kms.KmsImportKeyReturn<Jwk>
    } catch (error) {
      if (error instanceof Kms.KeyManagementError) throw error

      throw new Kms.KeyManagementError('Error importing key', { cause: error })
    }
  }

  public async deleteKey(agentContext: AgentContext, options: Kms.KmsDeleteKeyOptions): Promise<boolean> {
    return await this.#storage.delete(agentContext, options.keyId)
  }

  public async createKey<Type extends Kms.KmsCreateKeyType>(
    agentContext: AgentContext,
    options: Kms.KmsCreateKeyOptions<Type>
  ): Promise<Kms.KmsCreateKeyReturn<Type>> {
    const { type, keyId } = options

    if (keyId) await this.assertKeyNotExists(agentContext, keyId)

    try {
      let jwks: { publicJwk: Kms.KmsJwkPublic; privateJwk: Kms.KmsJwkPrivate }
      if (type.kty === 'EC') {
        assertBrowserSupportedEcCrv(type)
        jwks = await createEcKey(type)
      } else if (type.kty === 'OKP') {
        assertBrowserSupportedOkpCrv(type)
        jwks = await createOkpKey(type)
      } else if (type.kty === 'RSA') {
        jwks = await createRsaKey(type)
      } else if (type.kty === 'oct') {
        assertBrowserSupportedOctAlgorithm(type)
        jwks = await createOctKey(type)
      } else {
        // @ts-expect-error
        throw new Kms.KeyManagementAlgorithmNotSupportedError(`kty '${type.kty}'`, this.backend)
      }

      jwks.privateJwk.kid = keyId ?? randomUuid()
      jwks.publicJwk.kid = jwks.privateJwk.kid

      await this.#storage.set(agentContext, jwks.privateJwk.kid, jwks.privateJwk)

      return {
        publicJwk: jwks.publicJwk as Kms.KmsCreateKeyReturn<Type>['publicJwk'],
        keyId: jwks.publicJwk.kid,
      }
    } catch (error) {
      if (error instanceof Kms.KeyManagementError) throw error

      throw new Kms.KeyManagementError('Error creating key', { cause: error })
    }
  }

  public async sign(agentContext: AgentContext, options: Kms.KmsSignOptions): Promise<Kms.KmsSignReturn> {
    const { keyId, algorithm, data } = options

    // 1. Retrieve the key
    const key = await this.getKeyAsserted(agentContext, keyId)

    try {
      // 2. Validate alg and use for key
      Kms.assertAllowedSigningAlgForKey(key, algorithm)
      Kms.assertKeyAllowsSign(key)

      // 3. Perform the signing operation
      const signature = await performSign(key, algorithm, data)

      return {
        signature,
      }
    } catch (error) {
      if (error instanceof Kms.KeyManagementError) throw error

      throw new Kms.KeyManagementError('Error signing with key', { cause: error })
    }
  }

  public async verify(agentContext: AgentContext, options: Kms.KmsVerifyOptions): Promise<Kms.KmsVerifyReturn> {
    const { algorithm, data, signature } = options

    try {
      let key: Exclude<Kms.KmsJwkPublic, Kms.KmsJwkPublicOct> | Kms.KmsJwkPrivate
      if (options.key.keyId) {
        key = await this.getKeyAsserted(agentContext, options.key.keyId)
      } else if (options.key.publicJwk?.kty === 'EC') {
        assertBrowserSupportedEcCrv(options.key.publicJwk)
        key = options.key.publicJwk
      } else if (options.key.publicJwk?.kty === 'OKP') {
        assertBrowserSupportedOkpCrv(options.key.publicJwk)
        key = options.key.publicJwk
      } else if (options.key.publicJwk?.kty === 'RSA') {
        key = options.key.publicJwk
      } else {
        // @ts-expect-error
        throw new Kms.KeyManagementAlgorithmNotSupportedError(`kty ${options.key.kty}`, this.backend)
      }

      // 2. Validate alg and use for key
      Kms.assertAllowedSigningAlgForKey(key, algorithm)
      Kms.assertKeyAllowsVerify(key)

      // 3. Perform the verify operation
      const verified = await performVerify(key, algorithm, data, signature)
      if (verified) {
        return {
          verified: true,
          publicJwk: Kms.publicJwkFromPrivateJwk(key),
        }
      }

      return {
        verified: false,
      }
    } catch (error) {
      if (error instanceof Kms.KeyManagementError) throw error

      throw new Kms.KeyManagementError('Error verifying with key', { cause: error })
    }
  }

  public async encrypt(agentContext: AgentContext, options: Kms.KmsEncryptOptions): Promise<Kms.KmsEncryptReturn> {
    const { data, encryption, key } = options

    Kms.assertSupportedEncryptionAlgorithm(encryption, browserSupportedEncryptionAlgorithms, this.backend)

    let encryptionKey: Kms.KmsJwkPrivate
    let encryptedKey: Kms.KmsEncryptedKey | undefined

    if (key.keyId) {
      encryptionKey = await this.getKeyAsserted(agentContext, key.keyId)
    } else if (key.privateJwk) {
      encryptionKey = key.privateJwk
    } else if (key.keyAgreement) {
      Kms.assertAllowedKeyDerivationAlgForKey(key.keyAgreement.externalPublicJwk, key.keyAgreement.algorithm)
      Kms.assertKeyAllowsDerive(key.keyAgreement.externalPublicJwk)
      Kms.assertSupportedKeyAgreementAlgorithm(key.keyAgreement, browserSupportedKeyAgreementAlgorithms, this.backend)

      // keyId can be absent for ECDH-HSALSA20 (anonymous encryption)
      const privateJwk = key.keyAgreement.keyId
        ? await this.getKeyAsserted(agentContext, key.keyAgreement.keyId)
        : undefined
      if (privateJwk && key.keyAgreement.keyId) {
        Kms.assertJwkAsymmetric(privateJwk, key.keyAgreement.keyId)
        Kms.assertAllowedKeyDerivationAlgForKey(privateJwk, key.keyAgreement.algorithm)
        Kms.assertKeyAllowsDerive(privateJwk)

        // For DIDComm v1 our own key is often an Ed25519 key while the external key is X25519
        if (key.keyAgreement.algorithm !== 'ECDH-HSALSA20') {
          Kms.assertAsymmetricJwkKeyTypeMatches(privateJwk, key.keyAgreement.externalPublicJwk)
        }
      }

      if (key.keyAgreement.algorithm === 'ECDH-HSALSA20' || encryption.algorithm === 'XSALSA20-POLY1305') {
        if (encryption.algorithm !== 'XSALSA20-POLY1305' || key.keyAgreement.algorithm !== 'ECDH-HSALSA20') {
          throw new Kms.KeyManagementAlgorithmNotSupportedError(
            `key agreement algorithm '${key.keyAgreement.algorithm}' with encryption algorithm '${encryption.algorithm}'`,
            this.backend
          )
        }

        try {
          const recipientPublicKey = x25519PublicKeyFromJwk(key.keyAgreement.externalPublicJwk as Kms.KmsJwkPublicOkp)

          // anonymous encryption
          if (!privateJwk) {
            return { encrypted: cryptoBoxSeal({ recipientPublicKey, message: data }) }
          }

          const nonce = cryptoBoxRandomNonce()
          const encrypted = cryptoBox({
            recipientPublicKey,
            senderPrivateKey: x25519PrivateKeyFromJwk(privateJwk as Kms.KmsJwkPrivateOkp),
            message: data,
            nonce,
          })

          return { encrypted, iv: nonce }
        } catch (error) {
          if (error instanceof Kms.KeyManagementError) throw error

          throw new Kms.KeyManagementError('Error encrypting', { cause: error })
        }
      }

      if (!privateJwk) {
        throw new Kms.KeyManagementError('sender key is required for ECDH-ES key derivation.')
      }
      Kms.assertJwkAsymmetric(privateJwk, key.keyAgreement.keyId)

      const { contentEncryptionKey, encryptedContentEncryptionKey } = await deriveEncryptionKey({
        keyAgreement: key.keyAgreement,
        encryption,
        privateJwk,
      })

      encryptionKey = contentEncryptionKey
      encryptedKey = encryptedContentEncryptionKey
    } else {
      throw new Kms.KeyManagementError('Unexpected key parameter for encrypt')
    }

    if (encryption.algorithm === 'XSALSA20-POLY1305') {
      throw new Kms.KeyManagementAlgorithmNotSupportedError(
        `encryption algorithm '${encryption.algorithm}' can only be used with key agreement algorithm ECDH-HSALSA20`,
        this.backend
      )
    }

    if (encryptionKey.kty !== 'oct') {
      throw new Kms.KeyManagementAlgorithmNotSupportedError(
        `kty '${encryptionKey.kty} for content encryption'`,
        this.backend
      )
    }

    try {
      // 2. Validate alg and use for key
      Kms.assertAllowedEncryptionAlgForKey(encryptionKey, encryption.algorithm)
      Kms.assertKeyAllowsEncrypt(encryptionKey)

      // 3. Perform the encryption operation
      const encrypted = await performEncrypt(encryptionKey, options.encryption, data)
      return {
        ...encrypted,
        encryptedKey,
      }
    } catch (error) {
      if (error instanceof Kms.KeyManagementError) throw error

      throw new Kms.KeyManagementError('Error encrypting', { cause: error })
    }
  }

  public async decrypt(agentContext: AgentContext, options: Kms.KmsDecryptOptions): Promise<Kms.KmsDecryptReturn> {
    const { decryption, encrypted, key } = options

    Kms.assertSupportedEncryptionAlgorithm(decryption, browserSupportedEncryptionAlgorithms, this.backend)

    let decryptionKey: Kms.KmsJwkPrivate
    if (key.keyId) {
      decryptionKey = await this.getKeyAsserted(agentContext, key.keyId)
    } else if (key.privateJwk) {
      decryptionKey = key.privateJwk
    } else if (key.keyAgreement) {
      Kms.assertSupportedKeyAgreementAlgorithm(key.keyAgreement, browserSupportedKeyAgreementAlgorithms, this.backend)

      // externalPublicJwk can be absent for ECDH-HSALSA20 (anonymous encryption)
      if (key.keyAgreement.externalPublicJwk) {
        Kms.assertAllowedKeyDerivationAlgForKey(key.keyAgreement.externalPublicJwk, key.keyAgreement.algorithm)
        Kms.assertKeyAllowsDerive(key.keyAgreement.externalPublicJwk)
      }

      const privateJwk = await this.getKeyAsserted(agentContext, key.keyAgreement.keyId)
      Kms.assertJwkAsymmetric(privateJwk, key.keyAgreement.keyId)
      Kms.assertAllowedKeyDerivationAlgForKey(privateJwk, key.keyAgreement.algorithm)
      Kms.assertKeyAllowsDerive(privateJwk)

      // For DIDComm v1 our own key is often an Ed25519 key while the external key is X25519
      if (key.keyAgreement.externalPublicJwk && key.keyAgreement.algorithm !== 'ECDH-HSALSA20') {
        Kms.assertAsymmetricJwkKeyTypeMatches(privateJwk, key.keyAgreement.externalPublicJwk)
      }

      if (key.keyAgreement.algorithm === 'ECDH-HSALSA20' || decryption.algorithm === 'XSALSA20-POLY1305') {
        if (decryption.algorithm !== 'XSALSA20-POLY1305' || key.keyAgreement.algorithm !== 'ECDH-HSALSA20') {
          throw new Kms.KeyManagementAlgorithmNotSupportedError(
            `key agreement algorithm '${key.keyAgreement.algorithm}' with encryption algorithm '${decryption.algorithm}'`,
            this.backend
          )
        }

        try {
          const recipientPrivateKey = x25519PrivateKeyFromJwk(privateJwk as Kms.KmsJwkPrivateOkp)

          // anonymous encryption
          if (!key.keyAgreement.externalPublicJwk) {
            return { data: cryptoBoxSealOpen({ recipientPrivateKey, ciphertext: encrypted }) }
          }

          if (!decryption.iv) {
            throw new Kms.KeyManagementError(
              `Missing required 'iv' for key agreement algorithm ${key.keyAgreement.algorithm} and encryption algorithm ${decryption.algorithm} with sender key defined.`
            )
          }

          const data = cryptoBoxOpen({
            recipientPrivateKey,
            senderPublicKey: x25519PublicKeyFromJwk(key.keyAgreement.externalPublicJwk as Kms.KmsJwkPublicOkp),
            message: encrypted,
            nonce: decryption.iv,
          })

          return { data }
        } catch (error) {
          if (error instanceof Kms.KeyManagementError) throw error

          throw new Kms.KeyManagementError('Error decrypting', { cause: error })
        }
      }

      if (!key.keyAgreement.externalPublicJwk) {
        throw new Kms.KeyManagementError('sender key is required for ECDH-ES key derivation.')
      }

      const { contentEncryptionKey } = await deriveDecryptionKey({
        keyAgreement: key.keyAgreement,
        decryption,
        privateJwk,
      })

      decryptionKey = contentEncryptionKey
    } else {
      throw new Kms.KeyManagementError('Unexpected key parameter for decrypt')
    }

    if (decryption.algorithm === 'XSALSA20-POLY1305') {
      throw new Kms.KeyManagementAlgorithmNotSupportedError(
        `decryption algorithm '${decryption.algorithm}' can only be used with key agreement algorithm ECDH-HSALSA20`,
        this.backend
      )
    }

    if (decryptionKey.kty !== 'oct') {
      throw new Kms.KeyManagementAlgorithmNotSupportedError(
        `kty '${decryptionKey.kty}' for content encryption`,
        this.backend
      )
    }

    try {
      // 2. Validate alg and use for key
      Kms.assertAllowedEncryptionAlgForKey(decryptionKey, decryption.algorithm)
      Kms.assertKeyAllowsEncrypt(decryptionKey)

      // 3. Perform the decryption operation
      return await performDecrypt(decryptionKey, decryption, encrypted)
    } catch (error) {
      if (error instanceof Kms.KeyManagementError) throw error

      throw new Kms.KeyManagementError('Error decrypting', { cause: error })
    }
  }

  private async getKeyAsserted(agentContext: AgentContext, keyId: string) {
    const storageKey = await this.#storage.get(agentContext, keyId)
    if (!storageKey) {
      throw new Kms.KeyManagementKeyNotFoundError(keyId, [this.backend])
    }

    return storageKey
  }

  private async assertKeyNotExists(agentContext: AgentContext, keyId: string) {
    const storageKey = await this.#storage.get(agentContext, keyId)

    if (storageKey) {
      throw new Kms.KeyManagementKeyExistsError(keyId, this.backend)
    }
  }
}
