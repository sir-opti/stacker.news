import { randomBytes } from 'node:crypto'
import { DEFAULT_CALENDARS, DEFAULT_REMOTE_TIMEOUT, MIN_CALENDAR_RESPONSES, MAX_RESPONSE_SIZE } from './constants.js'
import { DeserializeContext } from './encoding.js'
import { makeMerkleTree } from './merkle.js'
import { OpAppend, OpSHA256 } from './ops.js'
import { DetachedTimestampFile, Timestamp } from './timestamp.js'

/**
 * Client for submitting digests to an OpenTimestamps calendar server.
 */
export class RemoteCalendar {
  /**
   * @param {string} url - Base URL of the calendar server.
   */
  constructor (url) {
    this.url = url // string, e.g. 'https://a.pool.opentimestamps.org'
    this.defaultTimeout = DEFAULT_REMOTE_TIMEOUT
  }

  /**
   * POSTs url/digest with the raw digest bytes as the request body.
   * @param {Buffer} digest - The raw digest bytes to submit.
   * @param {number} [timeout] - Optional timeout in milliseconds (defaults to 30s).
   * @returns {Promise<Timestamp>} The deserialized pending-attestation Timestamp.
   * @throws {Error} If fetch or AbortSignal.timeout is unavailable, on non-200 response,
   *                 if response exceeds MAX_RESPONSE_SIZE or if the server added extra
   *                 bytes to the response.
   */
  async submit (digest, timeout) {
    if (typeof globalThis.fetch !== 'function') {
      throw new Error('RemoteCalendar.submit: globalThis.fetch is not available (requires Node.js 18+ or a fetch polyfill)')
    }
    if (typeof globalThis.AbortSignal?.timeout !== 'function') {
      throw new Error('RemoteCalendar.submit: AbortSignal.timeout is not available (requires Node.js 17.3+ or a polyfill)')
    }

    // Combine 2 AbortControllers: 1 for timeout which we cannot control, one in our control
    // for when the remote is exceeding MAX_RESPONSE_SIZE
    const abortController = new globalThis.AbortController()
    const timeoutSignal = globalThis.AbortSignal.timeout(timeout ?? this.defaultTimeout)
    const combinedSignal = AbortSignal.any([timeoutSignal, abortController.signal])

    const response = await globalThis.fetch(`${this.url}/digest`, {
      method: 'POST',
      // note: although this content type doesn't make sense, it matches the implementation
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: digest,
      signal: combinedSignal
    })

    const reader = await response.body?.getReader()

    const chunks = []
    let resLen = 0
    while (true) {
      const { done, value } = await reader.read()
      if (done || combinedSignal.aborted) {
        break
      }

      if (value !== undefined) {
        resLen += value.byteLength
        if (resLen > MAX_RESPONSE_SIZE) {
          abortController.abort(new Error(`Response from remote exceeded ${MAX_RESPONSE_SIZE} bytes`))
          break
        }
        chunks.push(value)
      }
    }

    if (!response.ok) throw new Error(`calendar ${this.url} returned ${response.status}`)
    if (combinedSignal.aborted) {
      throw new Error(`RemoteCalendar.submit: request was aborted with ${combinedSignal.reason}`)
    }

    const buf = Buffer.concat(chunks.map(c => Buffer.from(c)))
    const ctx = new DeserializeContext(buf)
    const timestamp = Timestamp.deserialize(ctx, digest)
    if (!ctx.atEOF()) {
      throw new Error('RemoteCalendar.submit: trailing data received from remote')
    }

    return timestamp
  }
}

/**
 * Coordinates stamping files across multiple calendar servers.
 */
export class Notary {
  /**
   * Stamp one or more DetachedTimestampFile objects.
   *
   * Steps:
   *   1. Normalise detached to an array.
   *   2. For each file: append a 16-byte random nonce, hash with SHA-256 → Merkle leaf.
   *   3. Build a Merkle tree over all leaves → merkleTip.
   *   4. Submit merkleTip.msg concurrently to all calendars.
   *   5. Require at least options.m (default 2) successes; throw otherwise.
   *   6. Merge each successful calendar Timestamp into merkleTip.
   *
   * Each DetachedTimestampFile is mutated in-place.
   * @param {DetachedTimestampFile|DetachedTimestampFile[]} detached - One or more detached timestamp files to stamp.
   * @param {Object} [options] - Optional configuration.
   * @param {string[]} [options.calendars] - Calendar server URLs (defaults to DEFAULT_CALENDARS).
   * @param {number} [options.m] - Minimum successful calendar responses required (defaults to MIN_CALENDAR_RESPONSES).
   * @returns {Promise<void>}
   * @throws {Error} If any calendar URL is invalid or non-HTTPS, if m is out of range, or if too few calendars respond.
   */
  static async stamp (detached, options = {}) {
    const detachedList = detached instanceof DetachedTimestampFile ? [detached] : detached

    const calendars = options.calendars ?? DEFAULT_CALENDARS
    for (const url of calendars) {
      let parsed
      try {
        parsed = new URL(url)
      } catch {
        throw new Error(`Notary.stamp: invalid calendar URL: ${url}`)
      }
      if (parsed.protocol !== 'https:') {
        throw new Error(`Notary.stamp: calendar URL must use HTTPS: ${url}`)
      }
    }
    const m = options.m ?? MIN_CALENDAR_RESPONSES
    if (m <= 0 || m > calendars.length) {
      throw new Error(`Notary.stamp: invalid m value: ${m}`)
    }

    // Step 2 — nonce + SHA-256 per file
    const merkleLeaves = detachedList.map(dtf => {
      const nonce = randomBytes(16)
      const nonceStamp = dtf.timestamp.add(new OpAppend(nonce))
      return nonceStamp.add(new OpSHA256())
    })

    // Step 3 — Merkle tree
    const merkleTip = makeMerkleTree(merkleLeaves)

    // Step 4 — concurrent calendar submissions
    const results = await Promise.allSettled(
      calendars.map(url => new RemoteCalendar(url).submit(merkleTip.msg))
    )

    // Step 5 — require m successes
    const successes = results
      .filter(r => r.status === 'fulfilled')
      .map(r => r.value)
    if (successes.length < m) {
      // Note: this deviates from the original opentimestamps. Since if the threshold fails, then
      // this equals not having a stamp. Items without stamp can be re-stamped in batch, and we can
      // configure this as a retry, or as a batch. Having to go parse every timestamp to find those
      // that need to be redone is compute expensive and having a timestamp file that doesn't
      // result in the item being actually stamped would be deceiving.
      throw new Error(
        `Notary.stamp: only ${successes.length} of ${calendars.length} calendars responded (need ${m})`
      )
    }

    // Step 6 — merge into Merkle tip (propagates to all DetachedTimestampFiles)
    for (const calTs of successes) merkleTip.merge(calTs)
  }
}
