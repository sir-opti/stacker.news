/* eslint-env jest */

import { Notary, RemoteCalendar, catSHA256, makeMerkleTree } from '../notary.js'
import { DetachedTimestampFile, Timestamp } from '../timestamp.js'
import { PendingAttestation } from '../attestation.js'
import { OpSHA256, OpAppend, OpPrepend } from '../ops.js'
import { SerializeContext } from '../encoding.js'

// ---------------------------------------------------------------------------
// Shared test helper
// ---------------------------------------------------------------------------
function makeDetached () {
  return DetachedTimestampFile.fromHash(new OpSHA256(), Buffer.alloc(32))
}

/**
 * Build a mock calendar response: a minimal serialized Timestamp that
 * carries one PendingAttestation. The response is what RemoteCalendar.submit
 * would receive from a real calendar server.
 */
function buildCalendarResponse (digest, calendarUrl) {
  const stamp = new Timestamp(digest)
  stamp.attestations.push(new PendingAttestation(calendarUrl))
  const sctx = new SerializeContext()
  stamp.serialize(sctx)
  return sctx.getOutput()
}

/** construct a fetch reader mock for a jest resolver */
function makeReaderWithResolver (resolver) {
  let called = false
  return function () {
    return {
      read () {
        if (!called) {
          called = true
          return resolver()
        }
        return Promise.resolve({ done: true, value: undefined })
      }
    }
  }
}

/** construct a fetch reader mock to replay an ArrayBuffer in chunks */
function makeReader (ab, chunkSize = 100) {
  let pos = 0
  const buf = Buffer.from(ab)
  return function () {
    return {
      read () {
        let chunk
        if (buf.byteLength === pos) {
          return Promise.resolve({ done: true, value: undefined })
        } else if (buf.byteLength > pos + chunkSize) {
          chunk = buf.slice(pos, pos + chunkSize)
          pos += chunkSize
        } else {
          chunk = buf.slice(pos)
          pos = buf.byteLength
        }
        return Promise.resolve({ done: false, value: chunk })
      }
    }
  }
}

// ---------------------------------------------------------------------------
// RemoteCalendar.submit — response body consumed on error
// ---------------------------------------------------------------------------
describe('RemoteCalendar.submit consumes response body on error', () => {
  afterEach(() => {
    jest.restoreAllMocks()
    delete globalThis.fetch
  })

  test('consumes response body on non-200 response', async () => {
    const prom = jest.fn().mockResolvedValue({ done: false, value: new ArrayBuffer(1) })
    globalThis.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 500,
      body: { getReader: makeReaderWithResolver(prom) }
    })

    const cal = new RemoteCalendar('https://a.example.com')
    await expect(cal.submit(Buffer.alloc(32))).rejects.toThrow()
    expect(prom).toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// RemoteCalendar.submit — timeout nullish coalescing
// ---------------------------------------------------------------------------
describe('RemoteCalendar.submit passes explicit timeout', () => {
  afterEach(() => {
    jest.restoreAllMocks()
    delete globalThis.fetch
  })

  test('explicit timeout:0 is passed to AbortSignal, not replaced by default', async () => {
    const timeoutSpy = jest.spyOn(globalThis.AbortSignal, 'timeout').mockReturnValue(undefined)
    globalThis.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 500,
      body: { getReader: makeReader(new ArrayBuffer(0)) }
    })

    const cal = new RemoteCalendar('https://a.example.com')
    await cal.submit(Buffer.alloc(32), 0).catch(() => {})

    expect(timeoutSpy).toHaveBeenCalledWith(0)
  })
})

// ---------------------------------------------------------------------------
// RemoteCalendar.submit — response body exceeding MAX_RESPONSE_SIZE
// ---------------------------------------------------------------------------
describe('RemoteCalendar.submit rejects oversized response', () => {
  afterEach(() => {
    jest.restoreAllMocks()
    delete globalThis.fetch
  })

  test('throws when response body exceeds MAX_RESPONSE_SIZE', async () => {
    globalThis.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: { getReader: makeReader(new ArrayBuffer(RemoteCalendar.MAX_RESPONSE_SIZE + 1), 1000) }
    })

    const cal = new RemoteCalendar('https://a.example.com')
    await expect(cal.submit(Buffer.alloc(32))).rejects.toThrow(/exceeded/)
  })
})

// ---------------------------------------------------------------------------
// RemoteCalendar.submit — trailing data in response
// ---------------------------------------------------------------------------
describe('RemoteCalendar.submit rejects trailing data', () => {
  afterEach(() => {
    jest.restoreAllMocks()
    delete globalThis.fetch
  })

  test('throws when response body contains bytes past serialization end', async () => {
    globalThis.fetch = jest.fn().mockImplementation(async (url, opts) => {
      const digest = Buffer.from(opts.body)
      const responseBytes = buildCalendarResponse(digest, url)
      return {
        ok: true,
        status: 200,
        body: { getReader: makeReader(Buffer.concat([responseBytes, Buffer.from([0x01])])) }
      }
    })

    const cal = new RemoteCalendar('https://a.example.com')
    await expect(cal.submit(Buffer.alloc(32))).rejects.toThrow(/trailing data/)
  })
})

// ---------------------------------------------------------------------------
// AbortSignal.timeout: slow-stream defence
// ---------------------------------------------------------------------------
describe('RemoteCalendar.submit timeout mitigates slow-stream attacks', () => {
  afterEach(() => {
    jest.restoreAllMocks()
    delete globalThis.fetch
  })

  test('aborts a drip-feeding response within the timeout window', async () => {
    const shortTimeout = 300

    globalThis.fetch = jest.fn().mockImplementation(async (url, opts) => {
      const signal = opts.signal

      return {
        ok: true,
        status: 200,
        body: {
          getReader () {
            return {
              async read () {
                if (signal.aborted) {
                  return { done: true, value: undefined }
                }
                // Drip-feed: 1 byte every 200ms
                await new Promise(resolve => setTimeout(resolve, 200))
                if (signal.aborted) {
                  return { done: true, value: undefined }
                }
                return { done: false, value: new Uint8Array([0x00]) }
              }
            }
          }
        }
      }
    })

    const cal = new RemoteCalendar('https://evil.example.com')
    await expect(cal.submit(Buffer.alloc(32), shortTimeout)).rejects.toThrow()
  }, 2000)
})

// ---------------------------------------------------------------------------
// Notary.stamp — calendar URL validation
// ---------------------------------------------------------------------------
describe('Notary.stamp validates calendar URLs', () => {
  afterEach(() => {
    jest.restoreAllMocks()
    delete globalThis.fetch
  })

  test('rejects non-HTTPS calendar URL without making a fetch request', async () => {
    globalThis.fetch = jest.fn()
    const dtf = makeDetached()
    await expect(
      Notary.stamp(dtf, { calendars: ['http://evil.com'], m: 1 })
    ).rejects.toThrow()
    expect(globalThis.fetch).not.toHaveBeenCalled()
  })

  test('rejects an invalid (non-URL) calendar entry without making a fetch request', async () => {
    globalThis.fetch = jest.fn()
    const dtf = makeDetached()
    await expect(
      Notary.stamp(dtf, { calendars: ['not-a-url'], m: 1 })
    ).rejects.toThrow()
    expect(globalThis.fetch).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// Notary.stamp — m > calendars.length throws before any fetch
// ---------------------------------------------------------------------------
describe('Notary.stamp validates m parameter', () => {
  afterEach(() => {
    jest.restoreAllMocks()
    delete globalThis.fetch
  })

  test('throws when m > number of calendars', async () => {
    globalThis.fetch = jest.fn()
    const dtf = makeDetached()
    await expect(
      Notary.stamp(dtf, { calendars: ['https://a.example.com'], m: 5 })
    ).rejects.toThrow(/invalid m/)
    expect(globalThis.fetch).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// Notary.stamp — happy path with mocked fetch
// ---------------------------------------------------------------------------
describe('Notary.stamp happy path', () => {
  afterEach(() => {
    jest.restoreAllMocks()
    delete globalThis.fetch
  })

  test('mutates DetachedTimestampFile with attestations after stamp', async () => {
    const dtf = makeDetached()

    // We intercept fetch to return a valid calendar response.
    // The digest sent to the calendar is the Merkle tip, which we don't
    // know in advance. We capture it from the fetch call and build the
    // response dynamically.
    globalThis.fetch = jest.fn().mockImplementation(async (url, opts) => {
      const digest = Buffer.from(opts.body)
      const responseBytes = buildCalendarResponse(digest, url)
      return {
        ok: true,
        status: 200,
        body: {
          getReader: makeReader(responseBytes.buffer.slice(
            responseBytes.byteOffset,
            responseBytes.byteOffset + responseBytes.byteLength
          ))
        }
      }
    })

    const calendars = ['https://a.example.com', 'https://b.example.com']
    await Notary.stamp(dtf, { calendars, m: 2 })

    // The DTF should now have ops (nonce append + SHA256 at minimum)
    expect(dtf.timestamp.ops.size).toBeGreaterThan(0)

    // Walk the tree to find attestations
    function collectAttestations (ts) {
      const result = [...ts.attestations]
      ts.ops.forEach(child => {
        result.push(...collectAttestations(child))
      })
      return result
    }

    const attestations = collectAttestations(dtf.timestamp)
    expect(attestations.length).toBeGreaterThanOrEqual(2)
  })

  test('stamps multiple DetachedTimestampFiles', async () => {
    const dtf1 = makeDetached()
    const dtf2 = makeDetached()

    globalThis.fetch = jest.fn().mockImplementation(async (url, opts) => {
      const digest = Buffer.from(opts.body)
      const responseBytes = buildCalendarResponse(digest, url)
      return {
        ok: true,
        status: 200,
        body: {
          getReader: makeReader(responseBytes.buffer.slice(
            responseBytes.byteOffset,
            responseBytes.byteOffset + responseBytes.byteLength
          ))
        }
      }
    })

    const calendars = ['https://a.example.com', 'https://b.example.com']
    await Notary.stamp([dtf1, dtf2], { calendars, m: 2 })

    // Both should have ops added
    expect(dtf1.timestamp.ops.size).toBeGreaterThan(0)
    expect(dtf2.timestamp.ops.size).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// catSHA256 / makeMerkleTree — known hash vectors
// ---------------------------------------------------------------------------
describe('catSHA256 produces correct Merkle hash', () => {
  test('SHA256("foo" || "bar") matches known vector', () => {
    const left = new Timestamp(Buffer.from('foo'))
    const right = new Timestamp(Buffer.from('bar'))
    const result = catSHA256(left, right)
    expect(result.msg.toString('hex')).toBe('c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2')

    const leftChild = left.getStamp(new OpAppend(right.msg))
    expect(leftChild).toBeInstanceOf(Timestamp)
    expect(leftChild.getStamp(new OpSHA256())).toBeInstanceOf(Timestamp)

    const rightChild = right.getStamp(new OpPrepend(left.msg))
    expect(rightChild).toBeInstanceOf(Timestamp)
    expect(rightChild.getStamp(new OpSHA256())).toBeInstanceOf(Timestamp)
  })

  test('catSHA256 chained twice matches known vector', () => {
    const left = new Timestamp(Buffer.from('foo'))
    const right = new Timestamp(Buffer.from('bar'))
    const stamplr = catSHA256(left, right)

    const leftChild = left.getStamp(new OpAppend(right.msg))
    expect(leftChild).toBeInstanceOf(Timestamp)
    expect(leftChild.getStamp(new OpSHA256())).toBeInstanceOf(Timestamp)

    const rightChild = right.getStamp(new OpPrepend(left.msg))
    expect(rightChild).toBeInstanceOf(Timestamp)
    expect(rightChild.getStamp(new OpSHA256())).toBeInstanceOf(Timestamp)

    const righter = new Timestamp(Buffer.from('baz'))
    const result = catSHA256(stamplr, righter)
    expect(result.msg.toString('hex')).toBe('23388b16c66f1fa37ef14af8eb081712d570813e2afb8c8ae86efa726f3b7276')

    const stamplrChild = stamplr.getStamp(new OpAppend(righter.msg))
    expect(stamplrChild).toBeInstanceOf(Timestamp)
    expect(stamplrChild.getStamp(new OpSHA256())).toBeInstanceOf(Timestamp)

    const righterChild = righter.getStamp(new OpPrepend(stamplr.msg))
    expect(righterChild).toBeInstanceOf(Timestamp)
    expect(righterChild.getStamp(new OpSHA256())).toBeInstanceOf(Timestamp)
  })
})

// Known Merkle root hashes
const MERKLE_ROOTS = [
  [2, 'b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2'],
  [3, 'e6aa639123d8aac95d13d365ec3779dade4b49c083a8fed97d7bfc0d89bb6a5e'],
  [4, '7699a4fdd6b8b6908a344f73b8f05c8e1400f7253f544602c442ff5c65504b24'],
  [5, 'aaa9609d0c949fee22c1c941a4432f32dc1c2de939e4af25207f0dc62df0dbd8'],
  [6, 'ebdb4245f648b7e77b60f4f8a99a6d0529d1d372f98f35478b3284f16da93c06'],
  [7, 'ba4603a311279dea32e8958bfb660c86237157bf79e6bfee857803e811d91b8f']
]

describe('makeMerkleTree() produces known Merkle roots', () => {
  /**
   * Simulate the same pairing logic as makeMerkleTree to produce expected
   * intermediate nodes at each level, so we can verify the full tree structure.
   */
  function expectedLevels (leaves) {
    const levels = [leaves.map(l => l.msg)]
    let current = leaves.slice()
    while (current.length > 1) {
      const next = []
      for (let i = 0; i + 1 < current.length; i += 2) {
        // catSHA256 computes SHA256(left.msg || right.msg)
        const concat = Buffer.concat([current[i].msg, current[i + 1].msg])
        const hash = require('crypto').createHash('sha256').update(concat).digest()
        next.push({ msg: hash })
      }
      if (current.length % 2 === 1) next.push(current[current.length - 1])
      levels.push(next.map(n => n.msg))
      current = next
    }
    return levels
  }

  /**
   * Walk a leaf through its op chain and collect the messages at each step.
   * Returns an array of hex strings representing the path from leaf to root.
   */
  function walkUp (node) {
    const path = [node.msg.toString('hex')]
    let current = node
    while (current.ops.size > 0) {
      // Each node in the Merkle path has exactly one op edge (Append/Prepend),
      // whose child has exactly one op edge (SHA256), leading to the next level.
      // Exception: the root may have zero ops.
      const entries = [...current.ops.entries()]
      if (entries.length !== 1) break
      const [, child] = entries[0]
      // child is the concatenation node; it should have one OpSHA256 edge
      const childEntries = [...child.ops.entries()]
      if (childEntries.length !== 1) break
      const [childOp, grandchild] = childEntries[0]
      if (!(childOp instanceof OpSHA256)) break
      path.push(grandchild.msg.toString('hex'))
      current = grandchild
    }
    return path
  }

  for (const [n, expectedRoot] of MERKLE_ROOTS) {
    test(`${n} leaves → root ${expectedRoot.slice(0, 8)}… with correct tree structure`, () => {
      const leaves = Array.from({ length: n }, (_, i) => new Timestamp(Buffer.from([i])))
      const merkleTip = makeMerkleTree(leaves)
      expect(merkleTip.msg.toString('hex')).toBe(expectedRoot)

      // Verify the tree structure level by level
      const levels = expectedLevels(leaves)

      // The root should match the last level
      expect(levels[levels.length - 1]).toHaveLength(1)
      expect(levels[levels.length - 1][0].toString('hex')).toBe(expectedRoot)

      // Verify each paired leaf has the correct ops
      let currentLevel = leaves.slice()
      for (let level = 0; currentLevel.length > 1; level++) {
        for (let i = 0; i + 1 < currentLevel.length; i += 2) {
          const left = currentLevel[i]
          const right = currentLevel[i + 1]

          // Left should have OpAppend(right.msg) → concat node
          const leftAppendChild = left.getStamp(new OpAppend(right.msg))
          expect(leftAppendChild).toBeInstanceOf(Timestamp)
          expect(leftAppendChild.msg).toEqual(Buffer.concat([left.msg, right.msg]))

          // Right should have OpPrepend(left.msg) → same concat node
          const rightPrependChild = right.getStamp(new OpPrepend(left.msg))
          expect(rightPrependChild).toBeInstanceOf(Timestamp)
          expect(rightPrependChild.msg).toEqual(leftAppendChild.msg)

          // Both should reference the same concat node (shared child)
          expect(rightPrependChild).toBe(leftAppendChild)

          // Concat node should have OpSHA256 → parent
          const parent = leftAppendChild.getStamp(new OpSHA256())
          expect(parent).toBeInstanceOf(Timestamp)
          expect(parent.msg.toString('hex')).toBe(levels[level + 1][Math.floor(i / 2)].toString('hex'))
        }

        // Rebuild currentLevel for the next iteration (same logic as makeMerkleTree)
        const nextLevel = []
        for (let i = 0; i + 1 < currentLevel.length; i += 2) {
          const left = currentLevel[i]
          const concatChild = left.getStamp(new OpAppend(currentLevel[i + 1].msg))
          nextLevel.push(concatChild.getStamp(new OpSHA256()))
        }
        if (currentLevel.length % 2 === 1) nextLevel.push(currentLevel[currentLevel.length - 1])
        currentLevel = nextLevel
      }

      // Every leaf should be able to walk up to the root
      for (const leaf of leaves) {
        const path = walkUp(leaf)
        expect(path[path.length - 1]).toBe(expectedRoot)
      }
    })
  }
})

// ---------------------------------------------------------------------------
// makeMerkleTree edge cases
// ---------------------------------------------------------------------------
describe('makeMerkleTree edge cases', () => {
  test('single leaf returns itself', () => {
    const leaf = new Timestamp(Buffer.from([0x42]))
    const result = makeMerkleTree([leaf])
    expect(result).toBe(leaf)
  })

  test('empty array throws', () => {
    expect(() => makeMerkleTree([])).toThrow(/empty/)
  })
})

// ---------------------------------------------------------------------------
// Merkle construction: second-preimage resistance
// ---------------------------------------------------------------------------
describe('catSHA256 second-preimage resistance', () => {
  test('swapping left/right produces a different root', () => {
    const a = new Timestamp(Buffer.from('left-leaf'))
    const b = new Timestamp(Buffer.from('right-leaf'))
    const rootLR = catSHA256(a, b)

    const c = new Timestamp(Buffer.from('left-leaf'))
    const d = new Timestamp(Buffer.from('right-leaf'))
    const rootRL = catSHA256(d, c) // swapped

    expect(rootLR.msg.equals(rootRL.msg)).toBe(false)
  })

  test('OpAppend is assigned to left and OpPrepend is assigned to right', () => {
    const left = new Timestamp(Buffer.from('L'))
    const right = new Timestamp(Buffer.from('R'))
    catSHA256(left, right)

    // left gets OpAppend(right.msg), right gets OpPrepend(left.msg)
    const leftChild = left.getStamp(new OpAppend(Buffer.from('R')))
    expect(leftChild).toBeInstanceOf(Timestamp)

    const rightChild = right.getStamp(new OpPrepend(Buffer.from('L')))
    expect(rightChild).toBeInstanceOf(Timestamp)

    // No cross-assignment
    expect(left.getStamp(new OpPrepend(Buffer.from('R')))).toBeUndefined()
    expect(right.getStamp(new OpAppend(Buffer.from('L')))).toBeUndefined()
  })

  test('identical left and right still produces append/prepend asymmetry', () => {
    const a = new Timestamp(Buffer.from('same'))
    const b = new Timestamp(Buffer.from('same'))
    const root = catSHA256(a, b)

    expect(a.getStamp(new OpAppend(Buffer.from('same')))).toBeInstanceOf(Timestamp)
    expect(b.getStamp(new OpPrepend(Buffer.from('same')))).toBeInstanceOf(Timestamp)
    expect(root).toBeInstanceOf(Timestamp)
  })
})

// ---------------------------------------------------------------------------
// Integration: fromHash → stamp (mocked) → serializeToBytes → deserialize
// ---------------------------------------------------------------------------
describe('end-to-end integration: stamp → serialize → deserialize', () => {
  afterEach(() => {
    jest.restoreAllMocks()
    delete globalThis.fetch
  })

  test('full round-trip preserves attestations through serialization', async () => {
    const hash = Buffer.alloc(32, 0xab)
    const dtf = DetachedTimestampFile.fromHash(new OpSHA256(), hash)

    globalThis.fetch = jest.fn().mockImplementation(async (url, opts) => {
      const digest = Buffer.from(opts.body)
      const responseBytes = buildCalendarResponse(digest, url)
      return {
        ok: true,
        status: 200,
        body: {
          getReader: makeReader(responseBytes.buffer.slice(
            responseBytes.byteOffset,
            responseBytes.byteOffset + responseBytes.byteLength
          ))
        }
      }
    })

    await Notary.stamp(dtf, {
      calendars: ['https://a.example.com', 'https://b.example.com'],
      m: 2
    })

    // Serialize to bytes, then deserialize
    const bytes = dtf.serializeToBytes()
    const restored = DetachedTimestampFile.deserialize(bytes)

    // The restored DTF should have the same hash
    expect(restored.timestamp.msg).toEqual(hash)
    expect(restored.fileHashOp).toBeInstanceOf(OpSHA256)

    // Walk tree to collect attestations — should find at least the 2 calendar URIs
    function collectAttestations (ts) {
      const result = [...ts.attestations]
      ts.ops.forEach(child => {
        result.push(...collectAttestations(child))
      })
      return result
    }

    const attestations = collectAttestations(restored.timestamp)
    expect(attestations.length).toBeGreaterThanOrEqual(2)
    const uris = attestations.map(a => a.uri)
    expect(uris).toContain('https://a.example.com/digest')
    expect(uris).toContain('https://b.example.com/digest')
  })
})

// ---------------------------------------------------------------------------
// Notary.stamp with m=0
// ---------------------------------------------------------------------------
describe('Notary.stamp with m=0', () => {
  afterEach(() => {
    jest.restoreAllMocks()
    delete globalThis.fetch
  })

  test('rejects m=0 before any network call', async () => {
    globalThis.fetch = jest.fn()
    const dtf = DetachedTimestampFile.fromHash(new OpSHA256(), Buffer.alloc(32))
    await expect(
      Notary.stamp(dtf, { calendars: ['https://a.example.com'], m: 0 })
    ).rejects.toThrow(/invalid m/)
    expect(globalThis.fetch).not.toHaveBeenCalled()
  })
})
