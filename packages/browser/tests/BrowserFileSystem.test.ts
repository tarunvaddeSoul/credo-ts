import { CredoError } from '@credo-ts/core'
import { sha256 } from '@noble/hashes/sha2.js'
import { BrowserFileSystem } from '../src'

describe('BrowserFileSystem', () => {
  let fileSystem: BrowserFileSystem

  beforeEach(() => {
    fileSystem = new BrowserFileSystem()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('exposes data, cache and temp paths', () => {
    expect(fileSystem.dataPath).toBe('/credo/data')
    expect(fileSystem.cachePath).toBe('/credo/cache')
    expect(fileSystem.tempPath).toBe('/credo/temp')
  })

  it('writes and reads a file', async () => {
    await fileSystem.write('/credo/data/file.txt', 'hello')

    expect(await fileSystem.read('/credo/data/file.txt')).toBe('hello')
    expect(await fileSystem.exists('/credo/data/file.txt')).toBe(true)
    expect(await fileSystem.exists('/credo/data')).toBe(true)
    expect(await fileSystem.exists('/credo/data/missing.txt')).toBe(false)
  })

  it('copies a file', async () => {
    await fileSystem.write('/source.txt', 'content')
    await fileSystem.copyFile('/source.txt', '/destination.txt')

    expect(await fileSystem.read('/destination.txt')).toBe('content')
  })

  it('throws when reading or copying a missing file', async () => {
    await expect(fileSystem.read('/missing.txt')).rejects.toThrow(CredoError)
    await expect(fileSystem.copyFile('/missing.txt', '/destination.txt')).rejects.toThrow(CredoError)
  })

  it('deletes files and directories recursively', async () => {
    await fileSystem.write('/dir/a.txt', 'a')
    await fileSystem.write('/dir/nested/b.txt', 'b')

    await fileSystem.delete('/dir')

    expect(await fileSystem.exists('/dir')).toBe(false)
    expect(await fileSystem.exists('/dir/a.txt')).toBe(false)
    expect(await fileSystem.exists('/dir/nested/b.txt')).toBe(false)

    // Deleting a missing path does not throw
    await expect(fileSystem.delete('/missing')).resolves.toBeUndefined()
  })

  describe('downloadToFile', () => {
    const fileContent = new TextEncoder().encode('downloaded content')

    beforeEach(() => {
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(fileContent, { status: 200 })))
    })

    it('downloads a file', async () => {
      await fileSystem.downloadToFile('https://example.com/file.txt', '/downloads/file.txt')

      expect(await fileSystem.read('/downloads/file.txt')).toBe('downloaded content')
    })

    it('verifies the hash of the downloaded file', async () => {
      await fileSystem.downloadToFile('https://example.com/file.txt', '/downloads/file.txt', {
        verifyHash: { algorithm: 'sha256', hash: sha256(fileContent) },
      })

      expect(await fileSystem.exists('/downloads/file.txt')).toBe(true)
    })

    it('throws when the hash does not match', async () => {
      await expect(
        fileSystem.downloadToFile('https://example.com/file.txt', '/downloads/file.txt', {
          verifyHash: { algorithm: 'sha256', hash: new Uint8Array(32) },
        })
      ).rejects.toThrow(CredoError)

      expect(await fileSystem.exists('/downloads/file.txt')).toBe(false)
    })

    it('throws on non-success responses', async () => {
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 404 })))

      await expect(fileSystem.downloadToFile('https://example.com/file.txt', '/downloads/file.txt')).rejects.toThrow(
        CredoError
      )
    })
  })
})
