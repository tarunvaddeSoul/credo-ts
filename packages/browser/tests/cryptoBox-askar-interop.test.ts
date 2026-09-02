// Verifies the pure JS NaCl box implementation used for DIDComm v1 envelopes
// against askar's native CryptoBox implementation.
import { CryptoBox, Key, KeyAlgorithm } from '@openwallet-foundation/askar-nodejs'
import {
  cryptoBox,
  cryptoBoxOpen,
  cryptoBoxRandomNonce,
  cryptoBoxSeal,
  cryptoBoxSealOpen,
} from '../src/kms/crypto/cryptoBox'

const message = new TextEncoder().encode('didcomm v1 envelope payload')

describe('cryptoBox askar interop', () => {
  test('browser seal is opened by askar sealOpen', () => {
    const recipient = Key.generate(KeyAlgorithm.X25519)

    const ciphertext = cryptoBoxSeal({ recipientPublicKey: recipient.publicBytes, message })
    const decrypted = CryptoBox.sealOpen({ recipientKey: recipient, ciphertext })

    expect(new Uint8Array(decrypted)).toEqual(message)
  })

  test('askar seal is opened by browser sealOpen', () => {
    const recipient = Key.generate(KeyAlgorithm.X25519)

    const ciphertext = new Uint8Array(CryptoBox.seal({ recipientKey: recipient, message }))
    const decrypted = cryptoBoxSealOpen({ recipientPrivateKey: recipient.secretBytes, ciphertext })

    expect(decrypted).toEqual(message)
  })

  test('browser cryptoBox is opened by askar open', () => {
    const sender = Key.generate(KeyAlgorithm.X25519)
    const recipient = Key.generate(KeyAlgorithm.X25519)
    const nonce = cryptoBoxRandomNonce()

    const encrypted = cryptoBox({
      recipientPublicKey: recipient.publicBytes,
      senderPrivateKey: sender.secretBytes,
      message,
      nonce,
    })

    const decrypted = CryptoBox.open({
      recipientKey: recipient,
      senderKey: Key.fromPublicBytes({ algorithm: KeyAlgorithm.X25519, publicKey: sender.publicBytes }),
      message: encrypted,
      nonce,
    })

    expect(new Uint8Array(decrypted)).toEqual(message)
  })

  test('askar cryptoBox is opened by browser open', () => {
    const sender = Key.generate(KeyAlgorithm.X25519)
    const recipient = Key.generate(KeyAlgorithm.X25519)
    const nonce = new Uint8Array(CryptoBox.randomNonce())

    const encrypted = new Uint8Array(
      CryptoBox.cryptoBox({
        recipientKey: Key.fromPublicBytes({ algorithm: KeyAlgorithm.X25519, publicKey: recipient.publicBytes }),
        senderKey: sender,
        message,
        nonce,
      })
    )

    const decrypted = cryptoBoxOpen({
      recipientPrivateKey: recipient.secretBytes,
      senderPublicKey: sender.publicBytes,
      message: encrypted,
      nonce,
    })

    expect(decrypted).toEqual(message)
  })

  test('ed25519 to x25519 conversion matches askar', async () => {
    const { ed25519 } = await import('@noble/curves/ed25519.js')

    const edKey = Key.generate(KeyAlgorithm.Ed25519)
    const askarConverted = edKey.convertkey({ algorithm: KeyAlgorithm.X25519 })

    expect(ed25519.utils.toMontgomery(edKey.publicBytes)).toEqual(askarConverted.publicBytes)
    expect(ed25519.utils.toMontgomerySecret(edKey.secretBytes.slice(0, 32))).toEqual(askarConverted.secretBytes)
  })
})
