/* eslint-env jest */

import { promises as fs } from 'node:fs'
import path from 'node:path'

import { Timestamp, DetachedTimestampFile } from '../timestamp.js'
import { PendingAttestation } from '../attestation.js'
import { OpAppend, OpSHA256 } from '../ops.js'
import { SerializeContext, DeserializeContext } from '../encoding.js'
import { HEADER_MAGIC } from '../constants.js'

// ---------------------------------------------------------------------------
// Timestamp.add()
// Ported from: test/timestamp.js addOp, setResultTimestamp
// ---------------------------------------------------------------------------
describe('Timestamp.add()', () => {
  test('is idempotent: calling add twice with the same op returns the same child', () => {
    // Ported from: test/timestamp.js addOp
    const t = new Timestamp(Buffer.from('abcd'))
    const opAppend = new OpAppend(Buffer.from('efgh'))
    const child1 = t.add(opAppend)
    const child2 = t.add(opAppend)
    expect(child1).toBe(child2)
    expect(child1.msg).toEqual(Buffer.from('abcdefgh'))
  })

  test('chaining two ops produces the correct composed message', () => {
    // Ported from: test/timestamp.js setResultTimestamp
    const t1 = new Timestamp(Buffer.from('foo'))
    const opAppend1 = new OpAppend(Buffer.from('bar'))
    const opAppend2 = new OpAppend(Buffer.from('baz'))
    const t2 = t1.add(opAppend1) // t2.msg === 'foobar'
    const t3 = t2.add(opAppend2) // t3.msg === 'foobarbaz'
    expect(t3.msg).toEqual(Buffer.from('foobarbaz'))
  })
})

// ---------------------------------------------------------------------------
// Timestamp.serialize() / Timestamp.deserialize()
// Ported from: test/timestamp.js serialization
// ---------------------------------------------------------------------------
describe('Timestamp serialize / deserialize round-trip', () => {
  test('1 attestation', () => {
    const stamp = new Timestamp(Buffer.from('foo'))
    stamp.attestations.push(new PendingAttestation('foobar'))

    const ctx = new SerializeContext()
    stamp.serialize(ctx)
    const stamp2 = Timestamp.deserialize(new DeserializeContext(ctx.getOutput()), Buffer.from('foo'))

    expect(stamp2.attestations).toHaveLength(1)
    expect(stamp2.attestations[0].uri).toBe('foobar')
    expect(stamp2.ops.size).toBe(0)
  })

  test('2 attestations — both URIs survive the round-trip', () => {
    const stamp = new Timestamp(Buffer.from('foo'))
    stamp.attestations.push(new PendingAttestation('foobar'))
    stamp.attestations.push(new PendingAttestation('barfoo'))

    const ctx = new SerializeContext()
    stamp.serialize(ctx)
    const stamp2 = Timestamp.deserialize(new DeserializeContext(ctx.getOutput()), Buffer.from('foo'))

    expect(stamp2.attestations).toHaveLength(2)
    expect(stamp2.attestations.map(a => a.uri).sort()).toEqual(['barfoo', 'foobar'])
  })

  test('3 attestations — all URIs survive the round-trip', () => {
    const stamp = new Timestamp(Buffer.from('foo'))
    stamp.attestations.push(new PendingAttestation('foobar'))
    stamp.attestations.push(new PendingAttestation('barfoo'))
    stamp.attestations.push(new PendingAttestation('foobaz'))

    const ctx = new SerializeContext()
    stamp.serialize(ctx)
    const stamp2 = Timestamp.deserialize(new DeserializeContext(ctx.getOutput()), Buffer.from('foo'))

    expect(stamp2.attestations).toHaveLength(3)
    expect(stamp2.attestations.map(a => a.uri).sort()).toEqual(['barfoo', 'foobar', 'foobaz'])
  })

  test('attestations + 1 SHA256 op with child attestation', () => {
    // Ported from: test/timestamp.js serialization (last sub-case)
    const stamp = new Timestamp(Buffer.from('foo'))
    stamp.attestations.push(new PendingAttestation('foobar'))
    stamp.attestations.push(new PendingAttestation('barfoo'))
    stamp.attestations.push(new PendingAttestation('foobaz'))
    const sha256Stamp = stamp.add(new OpSHA256())
    sha256Stamp.attestations.push(new PendingAttestation('deeper'))

    const ctx = new SerializeContext()
    stamp.serialize(ctx)
    const stamp2 = Timestamp.deserialize(new DeserializeContext(ctx.getOutput()), Buffer.from('foo'))

    expect(stamp2.attestations).toHaveLength(3)
    expect(stamp2.ops.size).toBe(1)
    let childUri = null
    stamp2.ops.forEach(child => {
      if (child.attestations.length > 0) childUri = child.attestations[0].uri
    })
    expect(childUri).toBe('deeper')
  })
})

// ---------------------------------------------------------------------------
// Timestamp.addChild
// ---------------------------------------------------------------------------

describe('Timestamp.addChild()', () => {
  test('throws when a unique child Op exists', () => {
    const stamp = new Timestamp(Buffer.from('a'))
    expect(() => stamp.addChild(new OpSHA256(), new Timestamp(Buffer.from('b')))).not.toThrow()
    expect(() => stamp.addChild(new OpSHA256(), new Timestamp(Buffer.from('b')))).toThrow(/the same op twice/)
    expect(() => stamp.addChild(new OpAppend(Buffer.from('c')), new Timestamp(Buffer.from('c')))).not.toThrow()
    expect(() => stamp.addChild(new OpAppend(Buffer.from('c')), new Timestamp(Buffer.from('d')))).toThrow(/the same op twice/)
  })

  test('does not throw when a non-unique child Op of the same class exists', () => {
    const stamp = new Timestamp(Buffer.from('a'))
    expect(() => stamp.addChild(new OpAppend(Buffer.from('e')), new Timestamp(Buffer.from('e')))).not.toThrow()
    expect(() => stamp.addChild(new OpAppend(Buffer.from('f')), new Timestamp(Buffer.from('d')))).not.toThrow()
  })
})

// ---------------------------------------------------------------------------
// Timestamp.merge()
// Ported from: test/timestamp.js merge
// ---------------------------------------------------------------------------
describe('Timestamp.merge()', () => {
  test('propagates attestations from other into this', () => {
    const stamp1 = new Timestamp(Buffer.from('a'))
    const stamp2 = new Timestamp(Buffer.from('a'))
    stamp2.attestations.push(new PendingAttestation('foobar'))
    stamp1.merge(stamp2)
    expect(stamp1.attestations).toHaveLength(1)
    expect(stamp1.attestations[0].uri).toBe('foobar')
  })

  test('does not duplicate attestations already present', () => {
    const stamp1 = new Timestamp(Buffer.from('a'))
    stamp1.attestations.push(new PendingAttestation('foobar'))
    const stamp2 = new Timestamp(Buffer.from('a'))
    stamp2.attestations.push(new PendingAttestation('foobar'))
    stamp1.merge(stamp2)
    expect(stamp1.attestations).toHaveLength(1)
  })

  test('validates msg equality', () => {
    // Original opentimestamps throws when merging timestamps whose .msg fields differ.
    // ots-mini does not enforce this constraint; the test documents current behavior.
    const stampA = new Timestamp(Buffer.from('a'))
    const stampB = new Timestamp(Buffer.from('b'))
    stampB.attestations.push(new PendingAttestation('foobar'))
    expect(() => stampA.merge(stampB)).toThrow()
  })

  test('merging two timestamps that share some ops keeps shared subtree intact', () => {
    const msg = Buffer.from('shared')
    const stamp1 = new Timestamp(msg)
    const stamp2 = new Timestamp(msg)

    // Both have OpSHA256 (shared) — stamp1 also has OpAppend('x')
    const sha1 = stamp1.add(new OpSHA256())
    sha1.attestations.push(new PendingAttestation('cal-a'))
    const append1 = stamp1.add(new OpAppend(Buffer.from('x')))
    append1.attestations.push(new PendingAttestation('cal-b'))

    // stamp2 has the same OpSHA256 but with a different attestation
    const sha2 = stamp2.add(new OpSHA256())
    sha2.attestations.push(new PendingAttestation('cal-c'))

    stamp1.merge(stamp2)

    // The shared SHA256 child should now have both attestations merged
    const mergedSha = stamp1.getStamp(new OpSHA256())
    expect(mergedSha.attestations).toHaveLength(2)
    expect(mergedSha.attestations.map(a => a.uri).sort()).toEqual(['cal-a', 'cal-c'])

    // The non-shared OpAppend child should remain untouched
    const mergedAppend = stamp1.getStamp(new OpAppend(Buffer.from('x')))
    expect(mergedAppend.attestations).toHaveLength(1)
    expect(mergedAppend.attestations[0].uri).toBe('cal-b')
  })

  test('merging two timestamps with disjoint ops combines all branches', () => {
    const msg = Buffer.from('disjoint')
    const stamp1 = new Timestamp(msg)
    const stamp2 = new Timestamp(msg)

    // stamp1 has only OpAppend('a')
    const child1 = stamp1.add(new OpAppend(Buffer.from('a')))
    child1.attestations.push(new PendingAttestation('cal-1'))

    // stamp2 has only OpAppend('b')
    const child2 = stamp2.add(new OpAppend(Buffer.from('b')))
    child2.attestations.push(new PendingAttestation('cal-2'))

    stamp1.merge(stamp2)

    // stamp1 should now have both ops
    expect(stamp1.ops.size).toBe(2)
    const mergedA = stamp1.getStamp(new OpAppend(Buffer.from('a')))
    expect(mergedA.attestations[0].uri).toBe('cal-1')
    const mergedB = stamp1.getStamp(new OpAppend(Buffer.from('b')))
    expect(mergedB.attestations[0].uri).toBe('cal-2')
  })

  test('deep recursive merge of multi-level trees', () => {
    const msg = Buffer.from('deep')
    const stamp1 = new Timestamp(msg)
    const stamp2 = new Timestamp(msg)

    // stamp1: msg -> SHA256 -> Append('x') -> attestation('leaf-1')
    const sha1 = stamp1.add(new OpSHA256())
    const append1 = sha1.add(new OpAppend(Buffer.from('x')))
    append1.attestations.push(new PendingAttestation('leaf-1'))

    // stamp2: msg -> SHA256 -> Append('x') -> attestation('leaf-2')
    //                       -> Append('y') -> attestation('leaf-3')
    const sha2 = stamp2.add(new OpSHA256())
    const append2x = sha2.add(new OpAppend(Buffer.from('x')))
    append2x.attestations.push(new PendingAttestation('leaf-2'))
    const append2y = sha2.add(new OpAppend(Buffer.from('y')))
    append2y.attestations.push(new PendingAttestation('leaf-3'))

    stamp1.merge(stamp2)

    // After merge: SHA256 child should have both Append('x') and Append('y')
    const mergedSha = stamp1.getStamp(new OpSHA256())
    expect(mergedSha.ops.size).toBe(2)

    // Append('x') child should have both leaf-1 and leaf-2
    const mergedAppendX = mergedSha.getStamp(new OpAppend(Buffer.from('x')))
    expect(mergedAppendX.attestations).toHaveLength(2)
    expect(mergedAppendX.attestations.map(a => a.uri).sort()).toEqual(['leaf-1', 'leaf-2'])

    // Append('y') child should have leaf-3
    const mergedAppendY = mergedSha.getStamp(new OpAppend(Buffer.from('y')))
    expect(mergedAppendY.attestations).toHaveLength(1)
    expect(mergedAppendY.attestations[0].uri).toBe('leaf-3')
  })
})

// ---------------------------------------------------------------------------
// DetachedTimestampFile round-trip
// Ported from: test/open-timestamps.js OpenTimestamps.serialize() and
//              OpenTimestamps.DetachedTimestampFile()
// ---------------------------------------------------------------------------
describe('DetachedTimestampFile round-trip', () => {
  test('serializeToBytes() then deserialize() preserves hash and attestations', () => {
    const hash = Buffer.alloc(32, 0xab)
    const dtf = DetachedTimestampFile.fromHash(new OpSHA256(), hash)
    dtf.timestamp.attestations.push(new PendingAttestation('https://example.com'))

    const bytes = dtf.serializeToBytes()
    const dtf2 = DetachedTimestampFile.deserialize(bytes)

    expect(dtf2.timestamp.msg).toEqual(hash)
    expect(dtf2.timestamp.attestations).toHaveLength(1)
    expect(dtf2.timestamp.attestations[0].uri).toBe('https://example.com')
  })

  test('deserialize() throws on wrong magic header', () => {
    expect(() => DetachedTimestampFile.deserialize(Buffer.alloc(64, 0x00))).toThrow()
  })

  test('deserialize() throws on unsupported version number', () => {
    const ctx = new SerializeContext()
    ctx.writeBytes(HEADER_MAGIC)
    ctx.writeVaruint(99) // wrong version
    ctx.writeByte(OpSHA256.TAG)
    ctx.writeBytes(Buffer.alloc(32))
    expect(() => DetachedTimestampFile.deserialize(ctx.getOutput())).toThrow()
  })
})

// ---------------------------------------------------------------------------
// DetachedTimestampFile on a known good .ots file
// Timestamped `14759b3eef13f3b401bfade03f7d0d4cc6653e1fd6c82145ca0de6dfaf118ef7`
// with the python opentimestamps-client, stored as `fixtures/known_good.ots`
//
// This test prevents live calendar calls in unit tests, as those are third
// party services that would both negatively impact their performance, and
// potentially SN CI outcomes when remotes are down or unreachable.
// ---------------------------------------------------------------------------
describe('DetachedTimestampFile deserialization of python ots file', () => {
  test('deserialize a known good .ots file generated with python tooling', async () => {
    const sunny = await fs.readFile(path.join(__dirname, '/fixtures/known_good.ots'))
    const dtf = DetachedTimestampFile.deserialize(sunny)

    expect(dtf.fileHashOp._TAG()).toEqual(OpSHA256.TAG)
    expect(dtf.timestamp.msg.toString('hex')).toEqual('14759b3eef13f3b401bfade03f7d0d4cc6653e1fd6c82145ca0de6dfaf118ef7')

    function collectAttestations (ts) {
      const result = [...ts.attestations]
      ts.ops.forEach(child => {
        result.push(...collectAttestations(child))
      })
      return result
    }

    const attestations = collectAttestations(dtf.timestamp)
    expect(attestations.length).toEqual(4)
    expect(attestations[0].uri).toBe('https://bob.btc.calendar.opentimestamps.org')
    expect(attestations[1].uri).toBe('https://finney.calendar.eternitywall.com')
    expect(attestations[2].uri).toBe('https://btc.calendar.catallaxy.com')
    expect(attestations[3].uri).toBe('https://alice.btc.calendar.opentimestamps.org')
  })

  test('fails when extra data is padded to a known good file', async () => {
    const sunny = await fs.readFile(path.join(__dirname, '/fixtures/known_good.ots'))
    expect(() => DetachedTimestampFile.deserialize(Buffer.concat([sunny, Buffer.from([0x00])]))).toThrow(/trailing data/)
  })

  test('deserialize then re-serialize produces byte-identical output', async () => {
    const original = await fs.readFile(path.join(__dirname, '/fixtures/known_good.ots'))
    const dtf = DetachedTimestampFile.deserialize(original)
    const reserialized = dtf.serializeToBytes()
    expect(reserialized.equals(original)).toBe(true)
  })
})
