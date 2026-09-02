import { Kms, TypedArrayEncoder } from '@credo-ts/core'
import { chacha20poly1305 } from '@noble/ciphers/chacha.js'
import { aesCbcDecrypt, aesGcmDecrypt } from './aes'
import { cbcHmacAlgorithmSettings, computeCbcHmacTag } from './encrypt'
import { constantTimeEqual } from './webcrypto'

export async function performDecrypt(
  key: Kms.KmsJwkPrivateOct,
  dataDecryption: Kms.KmsDecryptDataDecryption,
  encrypted: Uint8Array
): Promise<{ data: Uint8Array }> {
  const secretKeyBytes = TypedArrayEncoder.fromBase64Url(key.k)

  if (dataDecryption.algorithm === 'A128CBC' || dataDecryption.algorithm === 'A256CBC') {
    const data = await aesCbcDecrypt(secretKeyBytes, dataDecryption.iv, encrypted)

    return { data }
  }

  if (
    dataDecryption.algorithm === 'A128GCM' ||
    dataDecryption.algorithm === 'A192GCM' ||
    dataDecryption.algorithm === 'A256GCM'
  ) {
    const data = await aesGcmDecrypt(
      secretKeyBytes,
      dataDecryption.iv,
      encrypted,
      dataDecryption.tag,
      dataDecryption.aad
    )

    return { data }
  }

  if (
    dataDecryption.algorithm === 'A128CBC-HS256' ||
    dataDecryption.algorithm === 'A192CBC-HS384' ||
    dataDecryption.algorithm === 'A256CBC-HS512'
  ) {
    const algSettings = cbcHmacAlgorithmSettings[dataDecryption.algorithm]

    // The MAC key is the first half of the input key, the ENC key the second half
    const macKey = secretKeyBytes.subarray(0, algSettings.keySize)
    const encKey = secretKeyBytes.subarray(algSettings.keySize)

    // Verify the authentication tag before decrypting
    const calculatedTag = await computeCbcHmacTag({
      macKey,
      hmacAlg: algSettings.hmacAlg,
      keySize: algSettings.keySize,
      iv: dataDecryption.iv,
      encrypted,
      aad: dataDecryption.aad,
    })

    if (!constantTimeEqual(calculatedTag, dataDecryption.tag)) {
      throw new Kms.KeyManagementError(
        `Error during verification of authentication tag with decryption algorithm '${dataDecryption.algorithm}'`
      )
    }

    const data = await aesCbcDecrypt(encKey, dataDecryption.iv, encrypted)

    return { data }
  }

  if (dataDecryption.algorithm === 'C20P') {
    // ChaCha20-Poly1305 is not supported by WebCrypto
    const combined = TypedArrayEncoder.concat([encrypted, dataDecryption.tag])
    const data = chacha20poly1305(secretKeyBytes, dataDecryption.iv, dataDecryption.aad).decrypt(combined)

    return { data }
  }

  throw new Kms.KeyManagementAlgorithmNotSupportedError(
    `JWA content decryption algorithm '${dataDecryption.algorithm}'`,
    'browser'
  )
}
