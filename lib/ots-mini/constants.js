/** @type {Buffer} 31-byte magic header identifying OpenTimestamps proof files. */
export const HEADER_MAGIC = Buffer.from([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73,
  0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94
])

/** @type {number} Major version of the OTS proof format. */
export const MAJOR_VERSION = 1

/** @type {number} Maximum number of attestations allowed per timestamp node. */
export const MAX_ATTESTATIONS_PER_TIMESTAMP = 16

/** @type {number} Maximum nodes in a Timestamp tree */
// Value taken from python opentimestamps/core/timestamp.py
export const TIMESTAMP_RECURSION_LIMIT = 256

/** @type {number} Maximum serialized item length in bytes. */
// Note:
// - this corresponds to a 2-byte encoded varint ([0xff, 0x7f])
// - this must be larger than any other limit
export const MAX_ITEM_LENGTH = 16383

/** @type {string[]} Default public calendar server URLs. */
export const DEFAULT_CALENDARS = [
  'https://a.pool.opentimestamps.org',
  'https://b.pool.opentimestamps.org',
  'https://a.pool.eternitywall.com',
  'https://ots.btc.catallaxy.com'
]

/** @type {number} Minimum number of successful calendar responses required. */
export const MIN_CALENDAR_RESPONSES = 1
