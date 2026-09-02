import { Kms, TypedArrayEncoder } from '@credo-ts/core'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { randomBytes, stripJwkMetadata, subtle } from './webcrypto'

const browserSupportedEcCrvs = ['P-256', 'P-384', 'P-521', 'secp256k1'] satisfies Kms.KmsJwkPublicEc['crv'][]
export type BrowserKmsSupportedEcCrvs = (typeof browserSupportedEcCrvs)[number]
export function assertBrowserSupportedEcCrv(
  options: Kms.KmsCreateKeyTypeEc
): asserts options is Kms.KmsCreateKeyTypeEc & { crv: BrowserKmsSupportedEcCrvs } {
  if (!browserSupportedEcCrvs.includes(options.crv as BrowserKmsSupportedEcCrvs)) {
    throw new Kms.KeyManagementAlgorithmNotSupportedError(`crv '${options.crv}' for kty '${options.kty}'`, 'browser')
  }
}

export async function createEcKey({ crv }: Kms.KmsCreateKeyTypeEc & { crv: BrowserKmsSupportedEcCrvs }) {
  // secp256k1 is not supported by WebCrypto
  if (crv === 'secp256k1') {
    const secretKey = secp256k1.utils.randomSecretKey()
    const publicKey = secp256k1.getPublicKey(secretKey, false)

    const privateJwk: Kms.KmsJwkPrivateEc = {
      kty: 'EC',
      crv,
      x: TypedArrayEncoder.toBase64Url(publicKey.subarray(1, 33)),
      y: TypedArrayEncoder.toBase64Url(publicKey.subarray(33)),
      d: TypedArrayEncoder.toBase64Url(secretKey),
    }

    return {
      privateJwk,
      publicJwk: Kms.publicJwkFromPrivateJwk(privateJwk) as Kms.KmsJwkPublicEc,
    }
  }

  const keyPair = await subtle.generateKey({ name: 'ECDSA', namedCurve: crv }, true, ['sign', 'verify'])

  return {
    privateJwk: stripJwkMetadata<Kms.KmsJwkPrivateEc>(await subtle.exportKey('jwk', keyPair.privateKey)),
    publicJwk: stripJwkMetadata<Kms.KmsJwkPublicEc>(await subtle.exportKey('jwk', keyPair.publicKey)),
  }
}

export async function createRsaKey({ modulusLength }: Kms.KmsCreateKeyTypeRsa) {
  const keyPair = await subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength,
      publicExponent: new Uint8Array([1, 0, 1]),
      // The hash is not bound to the key material, Credo JWKs are algorithm-agnostic
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify']
  )

  return {
    privateJwk: stripJwkMetadata<Kms.KmsJwkPrivateRsa>(await subtle.exportKey('jwk', keyPair.privateKey)),
    publicJwk: stripJwkMetadata<Kms.KmsJwkPublicRsa>(await subtle.exportKey('jwk', keyPair.publicKey)),
  }
}

const browserSupportedOkpCrvs = ['Ed25519', 'X25519'] satisfies Kms.KmsJwkPublicOkp['crv'][]
type BrowserKmsSupportedOkpCrvs = (typeof browserSupportedOkpCrvs)[number]
export function assertBrowserSupportedOkpCrv(
  options: Kms.KmsCreateKeyTypeOkp
): asserts options is Kms.KmsCreateKeyTypeOkp & { crv: BrowserKmsSupportedOkpCrvs } {
  if (!browserSupportedOkpCrvs.includes(options.crv as BrowserKmsSupportedOkpCrvs)) {
    throw new Kms.KeyManagementAlgorithmNotSupportedError(`crv '${options.crv}' for kty '${options.kty}'`, 'browser')
  }
}

export async function createOkpKey({ crv }: Kms.KmsCreateKeyTypeOkp & { crv: BrowserKmsSupportedOkpCrvs }) {
  // Ed25519/X25519 WebCrypto support is not available in all browsers yet
  const curve = crv === 'Ed25519' ? ed25519 : x25519
  const secretKey = curve.utils.randomSecretKey()
  const publicKey = curve.getPublicKey(secretKey)

  const privateJwk: Kms.KmsJwkPrivateOkp = {
    kty: 'OKP',
    crv,
    x: TypedArrayEncoder.toBase64Url(publicKey),
    d: TypedArrayEncoder.toBase64Url(secretKey),
  }

  return {
    privateJwk,
    publicJwk: Kms.publicJwkFromPrivateJwk(privateJwk) as Kms.KmsJwkPublicOkp,
  }
}

const browserSupportedOctAlgorithms = ['aes', 'hmac'] satisfies Kms.KmsCreateKeyTypeOct['algorithm'][]
type BrowserSupportedOctAlgorithms = (typeof browserSupportedOctAlgorithms)[number]
export function assertBrowserSupportedOctAlgorithm(
  options: Kms.KmsCreateKeyTypeOct
): asserts options is Kms.KmsCreateKeyTypeOct & { algorithm: BrowserSupportedOctAlgorithms } {
  if (!browserSupportedOctAlgorithms.includes(options.algorithm as BrowserSupportedOctAlgorithms)) {
    throw new Kms.KeyManagementAlgorithmNotSupportedError(
      `algorithm '${options.algorithm}' for kty '${options.kty}'`,
      'browser'
    )
  }
}

export async function createOctKey(options: Kms.KmsCreateKeyTypeOct & { algorithm: BrowserSupportedOctAlgorithms }) {
  const secretBytes = randomBytes(options.length >> 3)

  const privateJwk = {
    kty: 'oct',
    k: TypedArrayEncoder.toBase64Url(secretBytes),
  }

  const { k, ...publicJwk } = privateJwk

  return {
    privateJwk: privateJwk as Kms.KmsJwkPrivateOct,
    publicJwk: publicJwk as Kms.KmsJwkPublicOct,
  }
}
