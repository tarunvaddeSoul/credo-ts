import type { DownloadToFileOptions, FileSystem } from '@credo-ts/core'
import { CredoError, TypedArrayEncoder } from '@credo-ts/core'
import { sha256 } from '@noble/hashes/sha2.js'

function dirname(path: string) {
  const lastSlashIndex = path.lastIndexOf('/')
  if (lastSlashIndex <= 0) return '/'
  return path.slice(0, lastSlashIndex)
}

/**
 * In-memory {@link FileSystem} implementation for browser environments.
 *
 * Browsers do not expose a general purpose file system. Credo only uses the
 * file system for caching (e.g. anoncreds tails files), so an in-memory
 * implementation is sufficient for most browser wallets. A custom persistent
 * implementation (e.g. based on OPFS) can be provided through `agentDependencies`.
 */
export class BrowserFileSystem implements FileSystem {
  public readonly dataPath: string
  public readonly cachePath: string
  public readonly tempPath: string

  #files = new Map<string, Uint8Array>()
  #directories = new Set<string>()

  public constructor(options?: { baseDataPath?: string; baseCachePath?: string; baseTempPath?: string }) {
    this.dataPath = `${options?.baseDataPath ?? '/credo'}/data`
    this.cachePath = `${options?.baseCachePath ?? '/credo'}/cache`
    this.tempPath = `${options?.baseTempPath ?? '/credo'}/temp`
  }

  public async exists(path: string): Promise<boolean> {
    if (this.#files.has(path) || this.#directories.has(path)) return true

    // A path also exists if it is a parent directory of an existing file
    const prefix = `${path}/`
    for (const filePath of this.#files.keys()) {
      if (filePath.startsWith(prefix)) return true
    }

    return false
  }

  public async createDirectory(path: string): Promise<void> {
    this.#directories.add(dirname(path))
  }

  public async copyFile(sourcePath: string, destinationPath: string): Promise<void> {
    const file = this.#files.get(sourcePath)
    if (!file) {
      throw new CredoError(`File '${sourcePath}' does not exist`)
    }

    this.#files.set(destinationPath, file)
  }

  public async write(path: string, data: string): Promise<void> {
    this.#directories.add(dirname(path))
    this.#files.set(path, new TextEncoder().encode(data))
  }

  public async read(path: string): Promise<string> {
    const file = this.#files.get(path)
    if (!file) {
      throw new CredoError(`File '${path}' does not exist`)
    }

    return new TextDecoder().decode(file)
  }

  public async delete(path: string): Promise<void> {
    this.#files.delete(path)
    this.#directories.delete(path)

    const prefix = `${path}/`
    for (const filePath of this.#files.keys()) {
      if (filePath.startsWith(prefix)) this.#files.delete(filePath)
    }
    for (const directoryPath of this.#directories.values()) {
      if (directoryPath.startsWith(prefix)) this.#directories.delete(directoryPath)
    }
  }

  public async downloadToFile(url: string, path: string, options?: DownloadToFileOptions): Promise<void> {
    const response = await fetch(url)
    if (!response.ok) {
      throw new CredoError(`Unable to download file from url: ${url}. Response status was ${response.status}`)
    }

    const data = new Uint8Array(await response.arrayBuffer())

    if (options?.verifyHash) {
      const digest = sha256(data)
      const expectedHash = options.verifyHash.hash

      const matches =
        digest.length === expectedHash.length && digest.every((byte, index) => byte === expectedHash[index])

      if (!matches) {
        throw new CredoError(
          `Hash of downloaded file does not match expected hash. Expected: ${TypedArrayEncoder.toBase64Url(
            expectedHash
          )}, Actual: ${TypedArrayEncoder.toBase64Url(digest)}`
        )
      }
    }

    this.#directories.add(dirname(path))
    this.#files.set(path, data)
  }
}
