import type { AgentContext } from '@credo-ts/core'
import { Hasher, TypedArrayEncoder, injectable } from '@credo-ts/core'

import type { GroupMemberEntry } from '../repository/GroupRecord'

/**
 * Handles all group-layer cryptographic operations:
 * - GCK (Group Content Key) generation
 * - AES-256-GCM encrypt/decrypt for group messages
 * - Epoch hash chain computation
 */
@injectable()
export class GroupCryptoService {
  /**
   * Generate a fresh 256-bit AES key for use as a Group Content Key.
   * Uses the agent's KMS randomBytes for cryptographically secure generation.
   */
  public generateGck(_agentContext: AgentContext): string {
    const keyBytes = agentRandomBytes(32)
    return TypedArrayEncoder.toBase64URL(keyBytes)
  }

  /**
   * Encrypt a group message plaintext using AES-256-GCM with the GCK.
   *
   * AAD is bound to groupId, epoch, and sender to prevent cross-group
   * and cross-sender ciphertext transplant attacks.
   */
  public encrypt(
    plaintext: string,
    gck: string,
    groupId: string,
    epoch: number,
    senderDid: string
  ): GroupCiphertext {
    const key = TypedArrayEncoder.fromBase64(gck)
    const iv = agentRandomBytes(12)
    const aad = TypedArrayEncoder.fromString(`${groupId}.${epoch}.${senderDid}`)
    const data = TypedArrayEncoder.fromString(plaintext)

    // Use WebCrypto-compatible AES-256-GCM via Node.js crypto
    const crypto = require('node:crypto') as typeof import('node:crypto')
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 })
    cipher.setAAD(Buffer.from(aad))

    const encrypted = Buffer.concat([cipher.update(Buffer.from(data)), cipher.final()])
    const tag = cipher.getAuthTag()

    return {
      ciphertext: TypedArrayEncoder.toBase64URL(encrypted),
      iv: TypedArrayEncoder.toBase64URL(iv),
      tag: TypedArrayEncoder.toBase64URL(tag),
    }
  }

  /**
   * Decrypt a group message ciphertext using AES-256-GCM with the GCK.
   *
   * @throws if authentication tag verification fails (tampered or wrong key)
   */
  public decrypt(
    ciphertext: string,
    iv: string,
    tag: string,
    gck: string,
    groupId: string,
    epoch: number,
    senderDid: string
  ): string {
    const crypto = require('node:crypto') as typeof import('node:crypto')

    const key = TypedArrayEncoder.fromBase64(gck)
    const ivBytes = TypedArrayEncoder.fromBase64(iv)
    const tagBytes = TypedArrayEncoder.fromBase64(tag)
    const aad = TypedArrayEncoder.fromString(`${groupId}.${epoch}.${senderDid}`)
    const ciphertextBytes = TypedArrayEncoder.fromBase64(ciphertext)

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, ivBytes, { authTagLength: 16 })
    decipher.setAAD(Buffer.from(aad))
    decipher.setAuthTag(Buffer.from(tagBytes))

    const decrypted = Buffer.concat([decipher.update(Buffer.from(ciphertextBytes)), decipher.final()])
    return decrypted.toString('utf-8')
  }

  /**
   * Compute the epoch hash for tamper evidence.
   *
   * epoch_hash = SHA-256(previous_hash || epoch || sorted_member_dids || gck_fingerprint)
   *
   * The gck_fingerprint is SHA-256 of the raw GCK bytes.
   */
  public computeEpochHash(
    previousHash: string | undefined,
    epoch: number,
    members: GroupMemberEntry[],
    gck: string
  ): string {
    const sortedDids = members
      .map((m) => m.did)
      .sort()
      .join('|')

    const gckBytes = TypedArrayEncoder.fromBase64(gck)
    const gckFingerprint = TypedArrayEncoder.toBase64URL(Hasher.hash(gckBytes, 'sha-256'))

    const input = `${previousHash ?? ''}${epoch}${sortedDids}${gckFingerprint}`
    const hash = Hasher.hash(input, 'sha-256')

    return `sha256:${Buffer.from(hash).toString('hex')}`
  }

  /**
   * Verify an epoch hash against expected values.
   */
  public verifyEpochHash(
    epochHash: string,
    previousHash: string | undefined,
    epoch: number,
    members: GroupMemberEntry[],
    gck: string
  ): boolean {
    const computed = this.computeEpochHash(previousHash, epoch, members, gck)
    return computed === epochHash
  }
}

export interface GroupCiphertext {
  ciphertext: string
  iv: string
  tag: string
}

/**
 * Generate random bytes using Node.js crypto.
 * Fallback utility for IV generation where we don't need the full KMS.
 */
function agentRandomBytes(length: number): Uint8Array {
  const crypto = require('node:crypto') as typeof import('node:crypto')
  return new Uint8Array(crypto.randomBytes(length))
}
