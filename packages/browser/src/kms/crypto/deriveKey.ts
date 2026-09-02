import { Kms, TypedArrayEncoder } from '@credo-ts/core'
import { aeskw } from '@noble/ciphers/aes.js'
import { x25519 } from '@noble/curves/ed25519.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js'
import { jwkForSubtle, randomBytes, subtle } from './webcrypto'

const browserSupportedEcdhKeyDerivationEcCrv = ['P-256', 'P-384', 'P-521', 'secp256k1'] as const

const browserSupportedEcdhEsKeyAgreementAlgorithms = [
  'ECDH-ES',
  'ECDH-ES+A128KW',
  'ECDH-ES+A192KW',
  'ECDH-ES+A256KW',
] as const satisfies Kms.KnownJwaKeyAgreementAlgorithm[]

export const browserSupportedKeyAgreementAlgorithms = [
  ...browserSupportedEcdhEsKeyAgreementAlgorithms,
  // Only in combination with XSALSA20-POLY1305 (DIDComm v1)
  'ECDH-HSALSA20',
] satisfies Kms.KnownJwaKeyAgreementAlgorithm[]

function assertBrowserSupportedEcdhKeyDerivationCrv<
  Jwk extends Kms.KmsJwkPrivateAsymmetric | Kms.KmsJwkPublicAsymmetric,
>(
  jwk: Jwk
): asserts jwk is Jwk & {
  kty: 'OKP' | 'EC'
  crv: (typeof browserSupportedEcdhKeyDerivationEcCrv)[number] | 'X25519'
} {
  if (
    (jwk.kty === 'OKP' && jwk.crv !== 'X25519') ||
    (jwk.kty === 'EC' && !(browserSupportedEcdhKeyDerivationEcCrv as readonly string[]).includes(jwk.crv))
  ) {
    throw new Kms.KeyManagementAlgorithmNotSupportedError(
      `key derivation with crv '${jwk.crv}' for kty '${jwk.kty}'`,
      'browser'
    )
  }
}

type BrowserSupportedKeyAgreementDecryptOptions = Kms.KmsKeyAgreementDecryptOptions & {
  algorithm: (typeof browserSupportedEcdhEsKeyAgreementAlgorithms)[number]
}
type BrowserSupportedKeyAgreementEncryptOptions = Kms.KmsKeyAgreementEncryptOptions & {
  algorithm: (typeof browserSupportedEcdhEsKeyAgreementAlgorithms)[number]
}

export async function deriveEncryptionKey(options: {
  keyAgreement: BrowserSupportedKeyAgreementEncryptOptions
  privateJwk: Kms.KmsJwkPrivateAsymmetric
  encryption: Kms.KmsEncryptDataEncryption
}) {
  const { keyAgreement, encryption, privateJwk } = options

  assertBrowserSupportedEcdhKeyDerivationCrv(keyAgreement.externalPublicJwk)
  assertBrowserSupportedEcdhKeyDerivationCrv(privateJwk)

  const keyLength =
    keyAgreement.algorithm === 'ECDH-ES'
      ? mapContentEncryptionAlgorithmToKeyLength(encryption.algorithm)
      : keyAgreement.algorithm === 'ECDH-ES+A128KW'
        ? 128
        : keyAgreement.algorithm === 'ECDH-ES+A192KW'
          ? 192
          : 256

  const derivedKeyBytes = await deriveKeyEcdhEs({
    keyLength,
    usageAlgorithm: keyAgreement.algorithm === 'ECDH-ES' ? encryption.algorithm : keyAgreement.algorithm,
    privateJwk,
    publicJwk: keyAgreement.externalPublicJwk,
    apu: keyAgreement.apu,
    apv: keyAgreement.apv,
  })

  if (keyAgreement.algorithm === 'ECDH-ES') {
    return {
      contentEncryptionKey: {
        kty: 'oct',
        k: TypedArrayEncoder.toBase64Url(derivedKeyBytes),
      } as const,
    }
  }

  // Key wrapping. WebCrypto AES-KW rejects 192 bit keys in Chromium, so a pure JS
  // implementation is used for all key sizes
  const contentEncryptionKeyBytes = randomBytes(mapContentEncryptionAlgorithmToKeyLength(encryption.algorithm) >> 3)
  const encryptedContentEncryptionKey = aeskw(derivedKeyBytes).encrypt(contentEncryptionKeyBytes)

  return {
    encryptedContentEncryptionKey: {
      encrypted: encryptedContentEncryptionKey,
    } satisfies Kms.KmsEncryptedKey,
    contentEncryptionKey: {
      kty: 'oct',
      k: TypedArrayEncoder.toBase64Url(contentEncryptionKeyBytes),
    } as const,
  }
}

export async function deriveDecryptionKey(options: {
  keyAgreement: BrowserSupportedKeyAgreementDecryptOptions
  privateJwk: Kms.KmsJwkPrivateAsymmetric
  decryption: Kms.KmsDecryptDataDecryption
}) {
  const { keyAgreement, decryption, privateJwk } = options

  assertBrowserSupportedEcdhKeyDerivationCrv(keyAgreement.externalPublicJwk)
  assertBrowserSupportedEcdhKeyDerivationCrv(privateJwk)

  const keyLength =
    keyAgreement.algorithm === 'ECDH-ES'
      ? mapContentEncryptionAlgorithmToKeyLength(decryption.algorithm)
      : keyAgreement.algorithm === 'ECDH-ES+A128KW'
        ? 128
        : keyAgreement.algorithm === 'ECDH-ES+A192KW'
          ? 192
          : 256

  const derivedKeyBytes = await deriveKeyEcdhEs({
    keyLength,
    usageAlgorithm: keyAgreement.algorithm === 'ECDH-ES' ? decryption.algorithm : keyAgreement.algorithm,
    privateJwk,
    publicJwk: keyAgreement.externalPublicJwk,
    apu: keyAgreement.apu,
    apv: keyAgreement.apv,
  })

  if (keyAgreement.algorithm === 'ECDH-ES') {
    return {
      contentEncryptionKey: {
        kty: 'oct',
        k: TypedArrayEncoder.toBase64Url(derivedKeyBytes),
      } as const,
    }
  }

  // Key unwrapping
  const contentEncryptionKeyBytes = aeskw(derivedKeyBytes).decrypt(keyAgreement.encryptedKey.encrypted)

  return {
    contentEncryptionKey: {
      kty: 'oct',
      k: TypedArrayEncoder.toBase64Url(contentEncryptionKeyBytes),
    } as const,
  }
}

/**
 * Derive a key using ECDH and Concat KDF
 */
async function deriveKeyEcdhEs(options: {
  keyLength: number
  /**
   * This is only used for the AlgorithmID in KDF
   */
  usageAlgorithm: string
  apv?: Uint8Array
  apu?: Uint8Array
  privateJwk: Kms.KmsJwkPrivateEc | Kms.KmsJwkPrivateOkp
  publicJwk: Kms.KmsJwkPublicEc | Kms.KmsJwkPublicOkp
}): Promise<Uint8Array> {
  const concatKdfHashLength = mapCrvToHashLength(options.publicJwk.crv)

  const sharedSecret = await ecdhSharedSecret(options.privateJwk, options.publicJwk)

  // Prepare AlgorithmID for KDF (Datalen || Data)
  const algorithmData = TypedArrayEncoder.fromUtf8String(options.usageAlgorithm) // ASCII representation of alg
  const algorithmId = TypedArrayEncoder.concat([numberTo4ByteUint8Array(algorithmData.length), algorithmData])

  // Prepare PartyUInfo and PartyVInfo with proper length prefix
  const apu = options.apu ?? new Uint8Array(0)
  const partyUInfo = TypedArrayEncoder.concat([numberTo4ByteUint8Array(apu.length), apu])

  const apv = options.apv ?? new Uint8Array(0)
  const partyVInfo = TypedArrayEncoder.concat([numberTo4ByteUint8Array(apv.length), apv])

  // Prepare otherInfo for KDF
  const otherInfo = TypedArrayEncoder.concat([
    algorithmId,
    partyUInfo,
    partyVInfo,
    // SuppPubInfo: 32-bit big-endian representation of keydatalen
    numberTo4ByteUint8Array(options.keyLength),
    // SuppPrivInfo (empty octet sequence)
    new Uint8Array(0),
  ])

  // Derive final key using Concat KDF
  return concatKdf(sharedSecret, options.keyLength, concatKdfHashLength, otherInfo)
}

async function ecdhSharedSecret(
  privateJwk: Kms.KmsJwkPrivateEc | Kms.KmsJwkPrivateOkp,
  publicJwk: Kms.KmsJwkPublicEc | Kms.KmsJwkPublicOkp
): Promise<Uint8Array> {
  const publicKey = Kms.PublicJwk.fromPublicJwk(publicJwk).publicKey
  if (publicKey.kty === 'RSA') {
    throw new Kms.KeyManagementError('Key type RSA is not supported for ECDH-ES')
  }

  const privateKeyBytes = TypedArrayEncoder.fromBase64Url(privateJwk.d)

  // X25519 and secp256k1 are not supported by WebCrypto
  if (privateJwk.crv === 'X25519') {
    return x25519.getSharedSecret(privateKeyBytes, publicKey.publicKey)
  }

  if (privateJwk.crv === 'secp256k1') {
    // The first byte is the compressed point prefix, the shared secret is the x coordinate
    return secp256k1.getSharedSecret(privateKeyBytes, publicKey.publicKey, true).subarray(1)
  }

  const namedCurve = privateJwk.crv
  const cryptoPrivateKey = await subtle.importKey(
    'jwk',
    jwkForSubtle(privateJwk),
    { name: 'ECDH', namedCurve },
    false,
    ['deriveBits']
  )
  const cryptoPublicKey = await subtle.importKey(
    'jwk',
    jwkForSubtle(publicJwk),
    { name: 'ECDH', namedCurve },
    false,
    []
  )

  // The shared secret is the full x coordinate: 32/48/66 bytes for P-256/P-384/P-521
  const secretLengthBits = namedCurve === 'P-256' ? 256 : namedCurve === 'P-384' ? 384 : 528

  return new Uint8Array(
    await subtle.deriveBits({ name: 'ECDH', public: cryptoPublicKey }, cryptoPrivateKey, secretLengthBits)
  )
}

function numberTo4ByteUint8Array(number: number) {
  const buffer = new ArrayBuffer(4)
  const view = new DataView(buffer)
  view.setUint32(0, number)
  return new Uint8Array(buffer)
}

/**
 * Implements Concat KDF as per NIST SP 800-56A
 */
function concatKdf(secret: Uint8Array, length: number, hashLength: ConcatKdfHashLength, otherInfo: Uint8Array) {
  const hash = hashLength === 256 ? sha256 : hashLength === 384 ? sha384 : sha512

  const reps = Math.ceil((length >> 3) / (hashLength >> 3))
  const output = new Uint8Array(reps * (hashLength >> 3))

  for (let i = 0; i < reps; i++) {
    const input = TypedArrayEncoder.concat([numberTo4ByteUint8Array(i + 1), secret, otherInfo])
    output.set(hash(input), (i * hashLength) >> 3)
  }

  return output.subarray(0, length >> 3)
}

type ConcatKdfHashLength = ReturnType<typeof mapCrvToHashLength>
function mapCrvToHashLength(crv: Kms.KmsJwkPublicEc['crv'] | Kms.KmsJwkPublicOkp['crv']) {
  switch (crv) {
    case 'secp256k1':
    case 'X25519':
    case 'P-256':
      return 256
    case 'P-384':
      return 384
    case 'P-521':
      return 512
    default:
      throw new Kms.KeyManagementAlgorithmNotSupportedError(`crv '${crv}' for ECDH-ES`, 'browser')
  }
}

function mapContentEncryptionAlgorithmToKeyLength(
  encryptionAlgorithm: Kms.KnownJwaContentEncryptionAlgorithm | Kms.KnownJwaKeyEncryptionAlgorithm
): number {
  switch (encryptionAlgorithm) {
    case 'A128CBC':
    case 'A128GCM':
    case 'A128KW':
      return 128
    case 'A192KW':
      return 192
    case 'A128CBC-HS256':
    case 'A256CBC':
    case 'A256GCM':
    case 'C20P':
    case 'XC20P':
    case 'A256KW':
      return 256

    case 'A192CBC-HS384':
    case 'A192GCM':
      return 384
    case 'A256CBC-HS512':
      return 512
    case 'XSALSA20-POLY1305':
      return 256
  }
}
